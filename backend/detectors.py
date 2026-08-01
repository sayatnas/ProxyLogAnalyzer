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
from statistics import mean, median, stdev

# Tuning lives here rather than inline, so thresholds are config, not code.
Z_THRESHOLD = 5.0
MIN_REQUESTS_PER_MINUTE = 10   # absolute floor: 6 requests/min is never interesting

# Scales MAD so a MAD-based score is comparable to an ordinary z-score.
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
    return min(1.0, z / 10)


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
        })
    return findings

DETECTORS = [detect_rate_spike]


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
