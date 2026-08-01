import os
import uuid
from datetime import datetime
from pathlib import Path

from flask import Flask, g, jsonify, request

from auth import authenticate, create_token, ensure_demo_user, require_auth
from detectors import DETECTORS
from parser import parse_file

app = Flask(__name__)

UPLOAD_DIR = Path("uploads")
UPLOAD_DIR.mkdir(exist_ok=True)

# Analyses are held in memory, keyed by upload id, each tagged with its owner
# so one user cannot read another's results. Lost on restart; the raw uploaded
# file on disk is the durable copy.
ANALYSES: dict[str, dict] = {}

ensure_demo_user()


@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    return response


@app.route('/api/health')
def health():
    return jsonify({'status': 'ok', 'time': datetime.now().isoformat()})


@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json(silent=True) or {}
    username = data.get('username', '')
    password = data.get('password', '')
    # Same message for an unknown user and a wrong password, so the response
    # cannot be used to discover which usernames exist.
    if not authenticate(username, password):
        return jsonify({'error': 'invalid credentials'}), 401
    return jsonify({'token': create_token(username), 'username': username})


def summarize(records: list[dict], skipped: int) -> dict:
    return {
        "total_records": len(records),
        "skipped_lines": skipped,
        "unique_users": len({r["user"] for r in records}),
        "unique_domains": len({r["domain"] for r in records}),
        "unique_ips": len({r["src_ip"] for r in records}),
        "blocked_count": sum(1 for r in records if r["action"] == "BLOCKED"),
        "time_range": {
            "start": min(r["ts"] for r in records).isoformat(),
            "end": max(r["ts"] for r in records).isoformat(),
        },
    }


def severity_from_confidence(confidence: float) -> str:
    if confidence >= 0.8:
        return "high"
    if confidence >= 0.5:
        return "medium"
    return "low"


def build_timeline(records: list[dict], findings: list[dict]) -> list[dict]:
    timeline = [
        {
            "time": f["first_seen"],
            "severity": severity_from_confidence(f["confidence"]),
            "detector": f["detector"],
            "entity": f["entity"],
            "description": f["reason"],
        }
        for f in findings
    ]
    timeline.sort(key=lambda e: e["time"])
    return timeline


@app.route('/api/upload', methods=['POST'])
@require_auth
def upload():
    if 'file' not in request.files:
        return jsonify({'error': 'no file provided'}), 400

    uploaded = request.files['file']
    if uploaded.filename == '':
        return jsonify({'error': 'empty filename'}), 400

    upload_id = str(uuid.uuid4())
    saved_path = UPLOAD_DIR / f"{upload_id}.log"
    uploaded.save(saved_path)

    records, skipped = parse_file(str(saved_path))
    if not records:
        return jsonify({'error': 'no valid log records found in file'}), 400

    findings = []
    for detect in DETECTORS:
        findings.extend(detect(records))
    findings.sort(key=lambda f: f['confidence'], reverse=True)

    result = {
        'upload_id': upload_id,
        'filename': uploaded.filename,
        'analyzed_at': datetime.now().isoformat(),
        'stats': summarize(records, skipped),
        'findings': findings,
        'timeline': build_timeline(records, findings),
    }
    ANALYSES[upload_id] = {'owner': g.username, 'result': result}
    return jsonify(result), 201


@app.route('/api/results/<upload_id>')
@require_auth
def get_results(upload_id):
    entry = ANALYSES.get(upload_id)
    # 404 rather than 403 when it belongs to someone else: a 403 would confirm
    # that the upload exists.
    if entry is None or entry['owner'] != g.username:
        return jsonify({'error': 'unknown upload id'}), 404
    return jsonify(entry['result'])


MAX_EVENTS = 200


def matches(record: dict, filters: dict) -> bool:
    """True when a parsed record satisfies every filter that was supplied.

    Filters are applied by this code against known field names; only the VALUES
    come from the request, so a caller cannot ask for arbitrary fields.
    """
    if (ip := filters.get("src_ip")) and record["src_ip"] != ip:
        return False
    if (domain := filters.get("domain")) and record["domain"] != domain:
        return False
    if (user := filters.get("user")) and record["user"] != user:
        return False
    if (action := filters.get("action")) and record["action"] != action:
        return False
    if (min_bytes := filters.get("min_bytes_sent")) and record["bytes_sent"] < int(min_bytes):
        return False
    if (start := filters.get("time_from")) and record["timestamp"] < start:
        return False
    if (end := filters.get("time_to")) and record["timestamp"] > end:
        return False
    return True


@app.route('/api/results/<upload_id>/events')
@require_auth
def get_events(upload_id):
    """Pivot: the log lines behind a finding.

    Re-reads the uploaded file rather than holding parsed records in memory,
    so memory does not grow with the number of uploads. At ~150ms for 7.5k
    lines this is fine at prototype scale; at volume the events would live in
    an indexed store instead.
    """
    entry = ANALYSES.get(upload_id)
    if entry is None or entry['owner'] != g.username:
        return jsonify({'error': 'unknown upload id'}), 404

    saved_path = UPLOAD_DIR / f"{upload_id}.log"
    if not saved_path.exists():
        return jsonify({'error': 'log file no longer available'}), 410

    filters = {k: v for k, v in request.args.items() if k != 'limit' and v}
    limit = min(int(request.args.get('limit', MAX_EVENTS)), MAX_EVENTS)

    records, _ = parse_file(str(saved_path))
    matched = [r for r in records if matches(r, filters)]
    events = [
        {k: r[k] for k in
         ('timestamp', 'user', 'src_ip', 'domain', 'action', 'category',
          'bytes_sent', 'bytes_received', 'status')}
        for r in matched[:limit]
    ]
    return jsonify({
        'events': events,
        'total_matched': len(matched),
        'returned': len(events),
        'filters': filters,
    })


if __name__ == '__main__':
    app.run(port=int(os.environ.get('PORT', 5000)), debug=True)
