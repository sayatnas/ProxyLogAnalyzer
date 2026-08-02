"""Anomaly detectors for parsed proxy log records.
Every detector takes record list and returns list of findings.
Finding is a dict with a fixed shape shared by all detectors:
    {
        "detector": "rate_spike",
        "entity": "10.0.1.11",        # who/what is anomalous
        "mitre": "T1595",             # MITRE ATT&CK technique tag
        "confidence": 0.93,           # 0..1, heuristic mapped from z-score
        "reason": "162 requests in one minute (typical: 1.1)",
        "evidence": {...},            # numbers backing the claim
    }
"""
from collections import defaultdict
from datetime import timedelta
from statistics import mean, median, stdev

Z_THRESHOLD = 5.0
MIN_REQUESTS_PER_MINUTE = 10  

BEACON_CV_MAX = 0.15
MIN_BEACON_EVENTS = 6

MIN_EXFIL_BYTES = 10_000_000
LARGE_UPLOAD_BYTES = 1_000_000 # 1 MB floor

BLOCKED_RATIO_MAX = 0.30
MIN_REQUESTS_FOR_RATIO = 20
RARE_DOMAIN_MAX_HITS = 2

MAD_SCALE = 0.6745


def robust_scores(values: list[float]) -> tuple[float, float, str]:
    if len(values) < 2: 
        return 0.0, 0.0, "none"

    center = median(values) 
    mad = median([abs(v - center) for v in values]) 
    if mad > 0: #use mad if it's a better measure of spread than stdev
        return center, mad / MAD_SCALE, "mad"

    spread = stdev(values) #use stdev if mad is not a good measure of spread
    if spread > 0:
        return mean(values), spread, "stdev"
    return center, 0.0, "none"


def confidence_from_z(z: float) -> float:
    return round(min(1.0, z / 10), 2)


def detect_rate_spike(records: list[dict]) -> list[dict]:
    findings = []
    minute_counts = defaultdict(int)  # requests per (src_ip, minute)
    for record in records:
        minute = record["ts"].replace(second=0, microsecond=0)
        minute_counts[(record["src_ip"], minute)] += 1

    counts = list(minute_counts.values())
    baseline, spread, method = robust_scores(counts)
    if spread == 0:
        return findings

    ip_worst_minute = {}
    for (ip, minute), count in minute_counts.items():
        if count < MIN_REQUESTS_PER_MINUTE:
            continue
        z = (count - baseline) / spread
        if z > Z_THRESHOLD:
            if ip not in ip_worst_minute or z > ip_worst_minute[ip]["z"]:
                ip_worst_minute[ip] = {"minute": minute, "count": count, "z": z}

    for ip, data in ip_worst_minute.items():
        findings.append({
            "detector": "rate_spike",
            "entity": ip,
            "mitre": "T1595",
            "confidence": confidence_from_z(data["z"]),
            "reason": (f"{data['count']} requests in one minute at "
                       f"{data['minute']:%H:%M} (typical: {baseline:.1f})"),
            "evidence": {
                "minute": data["minute"].isoformat(),
                "count": data["count"],
                "z": round(data["z"], 1),
                "baseline_method": method,
            },
            "first_seen": data["minute"].isoformat(),
            "last_seen": data["minute"].isoformat(),
            "filter": {
                "src_ip": ip,
                "time_from": data["minute"].isoformat(),
                "time_to": (data["minute"] + timedelta(minutes=1)).isoformat(),
            },
            "entity_filter": {"src_ip": ip},
        })
    return findings

def detect_beaconing(records: list[dict]) -> list[dict]:
    findings = []
    pairs = defaultdict(list)
    for record in records:
        pairs[(record["src_ip"], record["domain"])].append(record["ts"])
    for (ip, domain), timestamps in pairs.items():
        if len(timestamps) < MIN_BEACON_EVENTS:
            continue
        timestamps = sorted(timestamps)
        gaps = [(timestamps[i] - timestamps[i-1]).total_seconds() for i in range(1, len(timestamps))]
        mean_gap = mean(gaps)
        cv = (stdev(gaps) / mean_gap) if mean_gap > 0 else 0
        if cv < BEACON_CV_MAX:
            findings.append({
                "detector": "beaconing",
                "entity": f"{ip} -> {domain}",
                "mitre": "T1071",
                "confidence": round(1 - cv / BEACON_CV_MAX, 2),
                "reason": f"{len(timestamps)} requests to {domain} every ~{mean_gap:.1f}s (variation: {cv:.1%})",
                "evidence": {
                    "events": len(timestamps),
                    "mean_gap_seconds": round(mean_gap, 1),
                    "cv": round(cv, 3),
                },
                "first_seen": timestamps[0].isoformat(),
                "last_seen": timestamps[-1].isoformat(),
                "filter": {
                    "src_ip": ip,
                    "domain": domain
                },
                "entity_filter": {"src_ip": ip},
            })
    return findings

def detect_exfiltration(records: list[dict]) -> list[dict]:
    findings = []
    bytes_sent = defaultdict(int)
    first = {}
    last = {}
    large_count = defaultdict(int)
    for record in records:
        ip = record["src_ip"]
        bytes_sent[ip] += record["bytes_sent"]
        if record["bytes_sent"] >= LARGE_UPLOAD_BYTES:
            large_count[ip] += 1
            if ip not in first or record["ts"] < first[ip]:
                first[ip] = record["ts"]
            if ip not in last or record["ts"] > last[ip]:
                last[ip] = record["ts"]
    baseline, spread, method = robust_scores(list(bytes_sent.values()))
    if spread == 0:
        return findings
    for ip, total in bytes_sent.items():
        if total < MIN_EXFIL_BYTES:
            continue
        z = (total - baseline) / spread
        if z > Z_THRESHOLD:
            findings.append({
                "detector": "exfiltration",
                "entity": ip,
                "mitre": "T1048",
                "confidence": confidence_from_z(z),
                "reason": f"{total / 1_000_000:.1f} MB uploaded (typical: {baseline / 1_000_000:.1f} MB) in {large_count[ip]} transfers between {first[ip].strftime('%H:%M')} and {last[ip].strftime('%H:%M')}",
                "evidence": {
                    "bytes_sent": total,
                    "z": round(z, 1),
                    "baseline_method": method,
                },
                "first_seen": first[ip].isoformat(),
                "last_seen": last[ip].isoformat(),
                "filter": {
                    "src_ip": ip,
                    "min_bytes_sent": LARGE_UPLOAD_BYTES,
                },
                "entity_filter": {"src_ip": ip},
            })
    return findings


def detect_blocked_burst(records: list[dict]) -> list[dict]:
    findings = []
    totals = defaultdict(int)
    blocked = defaultdict(int)
    first = {}
    last = {}
    for record in records:
        user = record["user"]
        totals[user] += 1
        if record["action"] == "BLOCKED":
            blocked[user] += 1
            if user not in first or record["ts"] < first[user]:
                first[user] = record["ts"]
            if user not in last or record["ts"] > last[user]:
                last[user] = record["ts"]
    for user, total in totals.items():
        if total < MIN_REQUESTS_FOR_RATIO:
            continue
        ratio = blocked[user] / total
        if ratio <= BLOCKED_RATIO_MAX:
            continue
        findings.append({
            "detector": "blocked_burst",
            "entity": user,
            "mitre": "T1071",
            "confidence": round(min(0.95, 0.4 + ratio * 0.6), 2),
            "reason": f"{ratio:.0%} of {user}'s {total} requests were blocked (threshold: {BLOCKED_RATIO_MAX:.0%})",
            "evidence": {
                "requests": total,
                "blocked": blocked[user],
                "blocked_ratio": round(ratio, 3),
            },
            "first_seen": first[user].isoformat(),
            "last_seen": last[user].isoformat(),
            "filter": {"user": user, "action": "BLOCKED"},
            "entity_filter": {"user": user},
        })
    return findings


def detect_rare_destination(records: list[dict]) -> list[dict]:
    # Domains almost nobody visits AND the proxy cannot categorise.
    findings = []
    hits = defaultdict(list)
    for record in records:
        if record["category"] == "uncategorized":
            hits[record["domain"]].append(record)
    for domain, rows in hits.items():
        if len(rows) > RARE_DOMAIN_MAX_HITS:
            continue
        hosts = {r["src_ip"] for r in rows}
        times = sorted(r["ts"] for r in rows)
        findings.append({
            "detector": "rare_destination",
            "entity": domain,
            "mitre": "T1568",
            "confidence": 0.6,
            "reason": f"{domain}: {len(rows)} request(s) from {len(hosts)} host(s), uncategorized domain",
            "evidence": {
                "hits": len(rows),
                "distinct_hosts": len(hosts),
                "hosts": sorted(hosts),
            },
            "first_seen": times[0].isoformat(),
            "last_seen": times[-1].isoformat(),
            "filter": {"domain": domain},
            "entity_filter": {"domain": domain},
        })
    return findings


DETECTORS = [
    detect_rate_spike,
    detect_beaconing,
    detect_exfiltration,
    detect_blocked_burst,
    detect_rare_destination,
]


if __name__ == "__main__":
    import sys
    from parser import parse_file

    records, skipped = parse_file(sys.argv[1])
    print(f"{len(records)} records ({skipped} skipped)")
    findings = []
    for detect in DETECTORS:
        findings.extend(detect(records))
    findings.sort(key=lambda f: f["confidence"], reverse=True)
    for f in findings:
        print(f"[{f['detector']}] {f['entity']}  conf={f['confidence']:.2f}  {f['reason']}")
    if not findings:
        print("no findings")
