"""Generate realistic proxy logs with planted anomalies for testing.

Produces a CSV log (same format parser.py expects) plus a ground-truth JSON
sidecar recording exactly what was planted, so tests can assert the detectors
find all of it and nothing else.

Usage:
    python generate_logs.py --out ../examples/sample_day.log --seed 42
"""
import argparse
import json
import random
from datetime import datetime, timedelta

HEADER = "timestamp,user,src_ip,domain,action,category,bytes_sent,bytes_received,status"

# domain -> category; one flat map keeps every generated line consistent
DOMAINS = {
    "news-site.com": "news", "daily-wire.net": "news",
    "wiki-pedia.org": "reference", "mail-box.com": "email",
    "code-forge.dev": "dev-tools", "pkg-registry.org": "dev-tools",
    "social-hub.net": "social", "chat-app.io": "social",
    "video-stream.tv": "streaming", "file-drop.io": "cloud-storage",
    "backup-vault.com": "cloud-storage", "ad-tracker.biz": "ads",
    "crypto-miner.xyz": "malware", "malware-c2.xyz": "malware",
}

USERS = [
    ("alice", "10.0.1.4"), ("bob", "10.0.1.7"), ("carol", "10.0.1.9"),
    ("dave", "10.0.1.11"), ("frank", "10.0.1.12"), ("grace", "10.0.1.13"),
    ("heidi", "10.0.1.14"), ("mallory", "10.0.1.15"), ("eve", "10.0.1.16"),
]

DAY = datetime(2026, 7, 30)


def line(ts, user, ip, domain, action, bytes_sent, bytes_recv):
    status = 403 if action == "BLOCKED" else 200
    cat = DOMAINS.get(domain, "uncategorized")
    return (ts, f"{ts.isoformat()},{user},{ip},{domain},{action},{cat},{bytes_sent},{bytes_recv},{status}")


def generate(seed: int, normal_requests: int):
    rng = random.Random(seed)
    rows = []

    # --- normal traffic: workday browsing, 08:00-18:00 ---
    for _ in range(normal_requests):
        user, ip = rng.choice(USERS)
        ts = DAY + timedelta(hours=8, seconds=rng.randint(0, 10 * 3600))
        domain = rng.choice(list(DOMAINS))
        blocked = rng.random() < (0.65 if user == "mallory" else 0.03)
        sent = int(rng.lognormvariate(6.5, 1.0))
        recv = int(rng.lognormvariate(9.5, 1.2))
        rows.append(line(ts, user, ip, domain, "BLOCKED" if blocked else "ALLOWED", sent, recv))

    # --- planted: rate spike (dave's machine hammers one domain for 3 min) ---
    spike_ip = "10.0.1.11"
    for _ in range(150):
        ts = DAY + timedelta(hours=10, minutes=30, seconds=rng.randint(0, 179))
        rows.append(line(ts, "dave", spike_ip, "crypto-miner.xyz",
                         "BLOCKED" if rng.random() < 0.5 else "ALLOWED", 210, 0))

    # --- planted: beaconing (service account checks in every ~60s all day) ---
    t = DAY
    beacon_count = 0
    while t < DAY + timedelta(days=1):
        rows.append(line(t, "svc-backup", "10.0.1.99", "sync-cdn.net", "ALLOWED", 256, 512))
        beacon_count += 1
        t += timedelta(seconds=60 + rng.randint(-3, 3))

    # --- planted: exfiltration (three huge uploads to cloud storage) ---
    exfil_bytes = [52_428_800, 61_000_000, 78_643_200]
    for i, b in enumerate(exfil_bytes):
        ts = DAY + timedelta(hours=13, minutes=20 * i)
        rows.append(line(ts, "eve", "10.0.1.16", "file-drop.io", "ALLOWED", b, 900))

    # --- planted: rare destination (single odd-hour hit, unknown domain) ---
    rare_ts = DAY + timedelta(hours=3, minutes=12)
    rows.append(line(rare_ts, "carol", "10.0.1.9", "xj9-relay.top", "ALLOWED", 840, 12000))

    # --- planted: hunt-only (brand-imitating typosquat, three quiet hits;
    #     evades every statistical shape: too few requests for a rate spike,
    #     tiny bytes, no periodicity, never blocked, and one hit more than a
    #     rare-destination threshold of 2. Only the domain NAME is evidence,
    #     so nothing but semantic judgement can flag it) ---
    for td in (timedelta(hours=9, minutes=41), timedelta(hours=11, minutes=7),
               timedelta(hours=15, minutes=33)):
        rows.append(line(DAY + td, "grace", "10.0.1.13", "micr0soft-login.com",
                         "ALLOWED", 1900, 3400))

    rows.sort(key=lambda r: r[0])
    out_lines = [HEADER] + [r[1] for r in rows]

    # --- malformed lines, planted at fixed relative positions ---
    for pos, junk in [(0.2, "SENSOR GLITCH ###"),
                      (0.5, "2026-07-30T12:00:00,truncated,line"),
                      (0.8, ",,,,,,,,")]:
        out_lines.insert(int(len(out_lines) * pos), junk)

    truth = {
        "seed": seed,
        "total_good_lines": len(rows),
        "malformed_lines": 3,
        "planted": {
            "rate_spike": {"src_ip": spike_ip, "user": "dave", "domain": "crypto-miner.xyz",
                           "window": "10:30-10:33", "requests": 150},
            "beaconing": {"src_ip": "10.0.1.99", "user": "svc-backup", "domain": "sync-cdn.net",
                          "interval_seconds": 60, "jitter_seconds": 3, "events": beacon_count},
            "exfiltration": {"user": "eve", "domain": "file-drop.io",
                             "bytes_sent": exfil_bytes, "total_bytes": sum(exfil_bytes)},
            "blocked_burst": {"user": "mallory", "blocked_ratio_approx": 0.65},
            "rare_destination": {"domain": "xj9-relay.top", "user": "carol",
                                 "time": rare_ts.isoformat()},
            "hunt_only": {"domain": "micr0soft-login.com", "user": "grace",
                          "src_ip": "10.0.1.13", "hits": 3,
                          "why": "typosquat name; statistically invisible"},
        },
    }
    return out_lines, truth


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="../examples/sample_day.log")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--requests", type=int, default=6000)
    args = ap.parse_args()

    out_lines, truth = generate(args.seed, args.requests)
    with open(args.out, "w") as f:
        f.write("\n".join(out_lines) + "\n")
    truth_path = args.out.replace(".log", ".ground_truth.json")
    with open(truth_path, "w") as f:
        json.dump(truth, f, indent=2)
    print(f"wrote {len(out_lines)} lines to {args.out}")
    print(f"ground truth -> {truth_path}")


if __name__ == "__main__":
    main()
