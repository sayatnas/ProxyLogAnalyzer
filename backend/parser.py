"""Parser for Zscaler-style proxy logs.

Expected format: CSV with a header line:
timestamp,user,src_ip,domain,action,category,bytes_sent,bytes_received,status
"""
from datetime import datetime

FIELDS = [
    "timestamp", "user", "src_ip", "domain", "action",
    "category", "bytes_sent", "bytes_received", "status",
]


def parse_line(line: str) -> dict | None:
    fields = line.split(",")
    if len(fields) != len(FIELDS):
        return None
    record = dict(zip(FIELDS, fields))
    try:
        record["ts"] = datetime.fromisoformat(record["timestamp"])
        record["bytes_sent"] = int(record["bytes_sent"])
        record["bytes_received"] = int(record["bytes_received"])
        record["status"] = int(record["status"])
    except ValueError:
        return None

    return record


def parse_file(path: str) -> tuple[list[dict], int]:
    records = []
    skipped = 0
    with open(path, "r") as f: 
        for line in f:
            if line.startswith("timestamp,"):
                continue
            if line.strip() == "":
                continue
            record = parse_line(line.strip())
            if record is not None:
                records.append(record)
            else:
                skipped += 1
    return records, skipped


if __name__ == "__main__":
    import sys

    records, skipped = parse_file(sys.argv[1])
    print(f"{len(records)} records, {skipped} skipped")
    if records:
        print("first:", records[0])
