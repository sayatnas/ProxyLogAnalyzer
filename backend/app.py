from flask import Flask, jsonify, request
from datetime import datetime
from pathlib import Path
import uuid

from parser import parse_file
from detectors import DETECTORS

app = Flask(__name__)

UPLOAD_DIR = Path("uploads")
UPLOAD_DIR.mkdir(exist_ok=True)

# In-memory result store, keyed by upload id. Replaced by Postgres later;
# results are lost on restart until then.
ANALYSES = {}


@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    return response


@app.route('/api/health')
def health():
    return jsonify({'status': 'ok', 'time': datetime.now().isoformat()})


def summarize(records: list[dict], skipped: int) -> dict:
    # TODO(you): build the headline numbers an analyst sees above the findings.
    #
    # Return a dict with at least:
    #   total_records, skipped_lines, unique_users, unique_domains,
    #   unique_ips, blocked_count, time_range {"start": iso, "end": iso}
    #
    # All of it is counting over `records`. Use set comprehensions for the
    # unique counts. Remember the values must be JSON-safe, so timestamps
    # become strings (records carry the raw string under "timestamp").
    #
    # Design decision that is YOURS: what else belongs here? Think about what
    # a SOC analyst wants to know in the first five seconds of opening a file.
    # Candidates: top talkers, most-hit domains, busiest hour, top categories.
    ...
    return {
        "total_records": len(records),
        "skipped_lines": skipped,
        "unique_users": len(set([record["user"] for record in records])),
        "unique_domains": len(set([record["domain"] for record in records])),
        "unique_ips": len(set([record["src_ip"] for record in records])),
        "blocked_count": len([record for record in records if record["action"] == "BLOCKED"]),
        "time_range": {"start": min([record["ts"] for record in records]).isoformat(), "end": max([record["ts"] for record in records]).isoformat()},
    }


def severity_from_confidence(confidence: float) -> str:
    return "high" if confidence > 0.9 else "medium" if confidence > 0.5 else "low"

def build_timeline(records: list[dict], findings: list[dict]) -> list[dict]:
    # TODO(you): turn findings into a chronological narrative of the day.
    #
    # A list sorted by confidence answers "what is worst?". A timeline answers
    # "what happened, and in what order?" Analysts need both: sequence reveals
    # co-occurrence, and things that happen together are often one incident.
    #
    # Return a list of events sorted by time, each:
    #   {"time": iso string, "severity": "high"|"medium"|"low",
    #    "detector": ..., "entity": ..., "description": "..."}
    #
    # Getting the time for each finding is the interesting part, because each
    # detector stores time differently in its evidence:
    #   - rate_spike: evidence["minute"] is already an iso string
    #   - beaconing: no timestamp in evidence at all. You need the FIRST
    #     occurrence: scan records for that ip+domain pair and take min(ts).
    #     (Or add a "first_seen" field to the beaconing finding: cleaner,
    #     and a reasonable change to make now.)
    #   - exfiltration: no timestamp either. Same approach: earliest large
    #     upload by that entity.
    #
    # This mismatch is worth noticing: the finding shape we designed has no
    # standard time field, and the timeline needs one. Adding "first_seen"
    # (and maybe "last_seen") to EVERY finding is the better fix, and it is
    # the kind of schema change you make once you see how data gets consumed.
    #
    # severity: map from confidence. Your thresholds, your call.
    timeline = []

    for f in findings:
        timeline.append({
            "time": f["first_seen"],
            "severity": severity_from_confidence(f["confidence"]),
            "detector": f["detector"],
            "entity": f["entity"],
            "description": f["reason"],
        })
    timeline.sort(key=lambda e: e["time"])
    return timeline

@app.route('/api/upload', methods=['POST'])
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
    ANALYSES[upload_id] = result
    return jsonify(result), 200


@app.route('/api/results/<upload_id>')
def get_results(upload_id):
    result = ANALYSES.get(upload_id)
    if result is None:
        return jsonify({'error': 'unknown upload id'}), 404
    return jsonify(result)


if __name__ == '__main__':
    app.run(port=5000, debug=True)
