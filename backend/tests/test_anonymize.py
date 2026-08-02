"""Pseudonymizer round trips, collisions, and case handling."""
from anonymize import Pseudonymizer

RECORDS = [
    {"user": "eve", "src_ip": "10.0.1.16"},
    {"user": "alice", "src_ip": "10.0.1.1"},
    {"user": "eve", "src_ip": "10.0.1.16"},  # duplicate on purpose
    {"user": "svc-backup", "src_ip": "10.0.1.99"},
]


def test_mapping_is_deduplicated_and_symmetric():
    p = Pseudonymizer(RECORDS)
    assert len(p.forward) == 6
    assert len(p.reverse) == 6
    for real, alias in p.forward.items():
        assert p.reverse[alias] == real


def test_scrub_replaces_and_leaves_domains():
    p = Pseudonymizer(RECORDS)
    s = p.scrub('{"user": "eve", "src_ip": "10.0.1.16", "domain": "backup-vault.com"}')
    assert "eve" not in s.replace("events", "")
    assert "10.0.1.16" not in s
    assert "backup-vault.com" in s


def test_username_does_not_corrupt_json_keys():
    # user "eve" must not match inside the key "events"
    p = Pseudonymizer(RECORDS)
    s = p.scrub('{"events": [], "total_events": 7, "user": "eve"}')
    assert '"events"' in s
    assert '"total_events"' in s


def test_ip_prefix_collision():
    # 10.0.1.1 must not match inside 10.0.1.16 or 110.0.1.1
    p = Pseudonymizer(RECORDS)
    s = p.scrub("10.0.1.1 and 10.0.1.16 and 110.0.1.1")
    assert s.endswith("110.0.1.1")
    assert "host-" in s.split(" and ")[0]
    assert "host-" in s.split(" and ")[1]


def test_round_trip_is_identity():
    p = Pseudonymizer(RECORDS)
    for sample in ['{"user": "eve"}', "svc-backup sent 192MB from 10.0.1.99",
                   "10.0.1.1 vs 10.0.1.16"]:
        assert p.unscrub(p.scrub(sample)) == sample


def test_unscrub_survives_model_recasing():
    # the model capitalises aliases at sentence starts
    p = Pseudonymizer(RECORDS)
    assert p.unscrub("Host-2 was busy. HOST-2 again. host-2's traffic.") == \
        "10.0.1.16 was busy. 10.0.1.16 again. 10.0.1.16's traffic."


def test_scrub_stays_case_sensitive():
    # "Eve" cased differently is a different identity; do not conflate
    p = Pseudonymizer(RECORDS)
    assert p.scrub("Eve is not eve") == "Eve is not user-2"


def test_empty_records_are_a_noop():
    p = Pseudonymizer([])
    assert p.scrub("hello eve 10.0.1.16") == "hello eve 10.0.1.16"
