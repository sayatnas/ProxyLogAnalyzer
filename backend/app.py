import os
import uuid
from collections import Counter
from datetime import datetime
from pathlib import Path

from flask import Flask, g, jsonify, request

from dotenv import load_dotenv
load_dotenv()
import llm
from anonymize import Pseudonymizer
from auth import authenticate, create_token, ensure_demo_user, require_auth
from detectors import DETECTORS
from parser import parse_file
from tools import build_registry, matches

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


def build_charts(records: list[dict]) -> dict:
    """Chart data the frontend draws: request volume over time and top hosts
    by bytes sent. Bucketing adapts to the log's span so any log gets ~120
    bars regardless of whether it covers ten minutes or a week."""
    times = [r["ts"] for r in records]
    start, end = min(times), max(times)
    span = max((end - start).total_seconds(), 1)
    bucket_seconds = max(int(span // 120), 60)
    counts = [0] * (int(span // bucket_seconds) + 1)
    for r in records:
        counts[int((r["ts"] - start).total_seconds() // bucket_seconds)] += 1

    bytes_by_host = Counter()
    for r in records:
        bytes_by_host[r["src_ip"]] += r["bytes_sent"]

    return {
        "activity": {
            "start": start.isoformat(),
            "end": end.isoformat(),
            "bucket_seconds": bucket_seconds,
            "counts": counts,
        },
        "bytes_by_host": [
            {"src_ip": ip, "bytes": b} for ip, b in bytes_by_host.most_common(10)
        ],
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
        'detectors': [d.__name__.removeprefix('detect_') for d in DETECTORS],
        'charts': build_charts(records),
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


@app.route('/api/results/<upload_id>/summarize', methods=['POST'])
@require_auth
def generate_summary(upload_id):
    """AI triage summary, on demand. Cached on the analysis after the first
    call so repeat clicks are free."""
    entry = ANALYSES.get(upload_id)
    if entry is None or entry['owner'] != g.username:
        return jsonify({'error': 'unknown upload id'}), 404

    result = entry['result']
    if 'summary' in result:
        return jsonify(result['summary'])

    saved_path = UPLOAD_DIR / f"{upload_id}.log"
    if not saved_path.exists():
        return jsonify({'error': 'log file no longer available'}), 410
    records, _ = parse_file(str(saved_path))

    summary = llm.triage_findings(result['stats'], result['findings'],
                                  build_registry(records), Pseudonymizer(records))
    result['summary'] = summary
    return jsonify(summary)


@app.route('/api/results/<upload_id>/investigate', methods=['POST'])
@require_auth
def investigate(upload_id):
    """Run the investigation agent against one finding.

    On demand rather than automatic: the loop costs money and seconds, so it
    runs when an analyst asks for it, not on every upload.
    """
    entry = ANALYSES.get(upload_id)
    if entry is None or entry['owner'] != g.username:
        return jsonify({'error': 'unknown upload id'}), 404

    body = request.get_json(silent=True) or {}
    key = body.get('finding_key')
    finding = next(
        (f for f in entry['result']['findings'] if f['detector'] + f['entity'] == key),
        None,
    )
    if finding is None:
        return jsonify({'error': 'unknown finding'}), 404

    saved_path = UPLOAD_DIR / f"{upload_id}.log"
    if not saved_path.exists():
        return jsonify({'error': 'log file no longer available'}), 410
    records, _ = parse_file(str(saved_path))

    return jsonify(llm.investigate_finding(finding, build_registry(records),
                                           Pseudonymizer(records)))


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
    # 0.0.0.0 so the app is reachable inside a container; debug only when
    # asked for, never on a public deployment (the debugger is a code
    # execution hole).
    app.run(host='0.0.0.0',
            port=int(os.environ.get('PORT', 5000)),
            debug=os.environ.get('FLASK_DEBUG', '1') == '1')
