"""assess() and collect(): the judge's pure steps between scanner output and verdicts."""

from dataclasses import replace

from helpers import PATH22, config, eni_endpoint, state

from classify import assess
from model import OwnedIPv4, ScanRecord, Tcp, Verdict
from scanner import collect

CFG = config()
EP = eni_endpoint()


def result(endpoint_id, ip, open_=None, closed=(), scanned=((1, 1024),), at=100):
    return {"at": at, "targets": [{"endpoint_id": endpoint_id, "ip": ip, "scanned": [list(r) for r in scanned], "open": open_ or {}, "closed": [[p, p] for p in closed]}], "http": [], "refused": []}


def test_collect_merges_an_endpoints_addresses_across_batches():
    two = replace(EP, probe=Tcp((OwnedIPv4("203.0.113.10", "eni-1 in 1/us-east-1"), OwnedIPv4("203.0.113.11", "eni-2 in 1/us-east-1"))))
    scans, https, refusals, not_scanned = collect([result(two.id, "203.0.113.10", {"22": "SSH-2.0"}), result(two.id, "203.0.113.11", closed=(80,), at=200), {"refused": ["batch expired"], "not_scanned": ["x: gone"], "targets": [], "http": []}])
    record = scans[two.id]
    assert record.at == 200 and record.open == {"203.0.113.10": {22: "SSH-2.0"}, "203.0.113.11": {}}
    assert record.closed["203.0.113.11"] == frozenset({80}) and refusals == ["batch expired"] and not_scanned == ["x: gone"]


def test_collect_merges_an_addresss_port_ranges_across_batches():
    scans, *_ = collect([result(EP.id, "203.0.113.10", {"22": "SSH-2.0"}, closed=(80,), scanned=((1, 1000),)), result(EP.id, "203.0.113.10", {"8443": None}, closed=(9000,), scanned=((1001, 65535),))])
    record = scans[EP.id]
    assert record.open == {"203.0.113.10": {22: "SSH-2.0", 8443: None}} and record.closed["203.0.113.10"] == frozenset({80, 9000})
    assert record.scanned == frozenset(range(1, 65536))


def test_an_all_filtered_address_still_yields_latent_filtered():
    scans, *_ = collect([result(EP.id, "203.0.113.10")])
    current, _ = assess(EP, None, scans[EP.id], None, CFG)
    assert current.findings["tcp/22"].verdict is Verdict.LATENT_FILTERED


def test_an_unscanned_endpoint_is_judged_from_its_last_scan_against_todays_expectations():
    scans, *_ = collect([result(EP.id, "203.0.113.10", {"22": "SSH-2.0"})])
    before, _ = assess(EP, None, scans[EP.id], None, CFG)
    assert before.findings["tcp/22"].verdict is Verdict.UNEXPECTED_OPEN
    declared = config(expected=[["prod/eni/*", {"ports": [22], "reason": "bastion"}]])
    after, expectation = assess(EP, before, None, None, declared)
    assert after.findings["tcp/22"].verdict is Verdict.EXPECTED_OPEN and expectation.reason == "bastion"
    assert after.scan == before.scan


def test_observations_of_an_address_the_endpoint_no_longer_holds_are_dropped():
    scans, *_ = collect([result(EP.id, "203.0.113.10", {"22": "SSH-2.0"})])
    before, _ = assess(EP, None, scans[EP.id], None, CFG)
    moved = replace(EP, probe=Tcp((OwnedIPv4("203.0.113.99", "eni-1 in 1/us-east-1"),)))
    after, _ = assess(moved, before, None, None, CFG)
    assert after.findings == {} and after.scan is None


def test_closing_the_path_turns_a_latent_port_into_nothing():
    scans, *_ = collect([result(EP.id, "203.0.113.10", closed=(22,))])
    before, _ = assess(EP, None, scans[EP.id], None, CFG)
    assert before.findings["tcp/22"].verdict is Verdict.LATENT_CONFIRMED
    after, _ = assess(replace(EP, paths=()), before, None, None, CFG)
    assert after.findings == {}


def test_scan_records_round_trip():
    record = ScanRecord(5, frozenset({22, 80, 443}), {"203.0.113.10": {22: "SSH"}}, {"203.0.113.10": frozenset({80})})
    assert ScanRecord.from_json(record.to_json()) == record
    s = state(EP)
    assert type(s).from_json(s.to_json()).endpoint == EP and PATH22 in EP.paths
