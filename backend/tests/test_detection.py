"""Detection evaluated against the generated ground truth.

The sample log is produced by generate_logs.py together with a sidecar JSON
recording exactly what was planted, so these tests assert both directions:
every planted anomaly the detectors cover is found, and nothing else is.
"""
import json

import pytest

from conftest import EXAMPLES
from detectors import DETECTORS
from parser import parse_file


@pytest.fixture(scope="module")
def day():
    records, skipped = parse_file(str(EXAMPLES / "sample_day.log"))
    findings = []
    for detect in DETECTORS:
        findings.extend(detect(records))
    truth = json.loads((EXAMPLES / "sample_day.ground_truth.json").read_text())
    return records, skipped, findings, truth


def test_parser_counts_match_ground_truth(day):
    records, skipped, _, truth = day
    assert skipped == truth["malformed_lines"]
    assert len(records) == truth["total_good_lines"]


def test_rate_spike_found(day):
    _, _, findings, truth = day
    planted = truth["planted"]["rate_spike"]
    hits = [f for f in findings if f["detector"] == "rate_spike"]
    assert len(hits) == 1
    assert hits[0]["entity"] == planted["src_ip"]


def test_beaconing_found(day):
    _, _, findings, truth = day
    planted = truth["planted"]["beaconing"]
    hits = [f for f in findings if f["detector"] == "beaconing"]
    assert len(hits) == 1
    assert planted["src_ip"] in hits[0]["entity"]
    assert planted["domain"] in hits[0]["entity"]


def test_exfiltration_found(day):
    records, _, findings, truth = day
    planted = truth["planted"]["exfiltration"]
    exfil_ip = next(r["src_ip"] for r in records if r["user"] == planted["user"])
    hits = [f for f in findings if f["detector"] == "exfiltration"]
    assert len(hits) == 1
    assert exfil_ip in hits[0]["entity"]


def test_no_false_positives(day):
    # Exactly one finding per implemented detector; ordinary traffic,
    # mallory's blocked browsing, and the hunt-only typosquat must not fire.
    _, _, findings, _ = day
    assert len(findings) == 3, [f["entity"] for f in findings]


def test_every_finding_has_the_contract_fields(day):
    _, _, findings, _ = day
    for f in findings:
        for field in ("detector", "entity", "confidence", "reason",
                      "first_seen", "filter", "entity_filter"):
            assert field in f, f"{f['detector']} missing {field}"
        assert 0.0 <= f["confidence"] <= 1.0


@pytest.mark.skip(reason="detector not implemented; planted anomaly documented in ground truth")
def test_blocked_burst_found():
    pass


@pytest.mark.skip(reason="detector not implemented; planted anomaly documented in ground truth")
def test_rare_destination_found():
    pass


def test_small_log_is_clean():
    records, skipped, = parse_file(str(EXAMPLES / "sample_small.log"))
    assert skipped == 2
    assert len(records) == 9
    findings = []
    for detect in DETECTORS:
        findings.extend(detect(records))
    assert findings == []
