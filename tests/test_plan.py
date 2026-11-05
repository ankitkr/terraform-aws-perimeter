"""Which endpoints a run probes, and the scanner batches."""

from dataclasses import replace

import math

import pytest
from helpers import PATH22, config, eni_endpoint, front, state

import plan
from model import Kind, OwnedIPv4, Path, ScanSettings, Tcp
from plan import Request, batches, scopes, targets
from scanner import HTTP_TIMEOUT, parse_batch, port_set, ports_for

CFG = config(regions=["us-east-1", "ap-south-1"])


def test_requests():
    accounts = CFG.accounts
    assert Request.parse({"mode": "inventory"}, accounts).mode == "inventory"
    assert Request.parse({}, accounts).mode == "inventory"
    assert Request.parse(None, accounts).mode == "inventory"
    assert Request.parse({"full": True}, accounts).mode == "full"
    assert Request.parse({"mode": "full"}, accounts).mode == "full"
    assert Request.parse({"endpoints": ["prod/alb/api"]}, accounts) == Request("endpoints", ("prod/alb/api",))
    touch = Request.parse({"delay": 120, "touch": {"account": "prod", "region": "us-east-1", "resources": ["sg-1"], "global": False}}, accounts)
    assert touch == Request("touch", (), "prod", "us-east-1", ("sg-1",), False)


@pytest.mark.parametrize(
    "raw,message",
    [
        ({"touch": {"account": "nope", "region": "us-east-1"}}, "touch.account 'nope' isn't a configured account (prod, staging)"),
        ({"touch": {"region": "us-east-1"}}, "touch needs account and region"),
        ({"touch": {"account": "prod"}}, "touch needs account and region"),
        ({"touch": {"account": "prod", "region": "us-east-1", "resources": "sg-1"}}, "touch.resources is a list of resource ids"),
        ({"endpoints": []}, "endpoints is a non-empty list of endpoint ids"),
        ({"endpoints": "prod/alb/api"}, "endpoints is a non-empty list of endpoint ids"),
        ({"endpoints": ["nope/alb/api"]}, "endpoint nope/alb/api: 'nope' isn't a configured account (prod, staging)"),
        ({"mode": "fulll"}, "mode is \"full\" or \"inventory\""),
        (["full"], "the run input is a JSON object"),
    ],
)
def test_bad_run_inputs_are_refused_with_a_reason(raw, message):
    with pytest.raises(ValueError) as err:
        Request.parse(raw, CFG.accounts)
    assert message in str(err.value)


def test_endpoints_missing_from_the_last_inventory_are_refused():
    ep = eni_endpoint()
    with pytest.raises(ValueError, match="prod/eni/i-gone isn't in the last inventory"):
        scopes(Request("endpoints", (ep.id, "prod/eni/i-gone")), CFG, {ep.id: state(ep)})


def test_scopes():
    every = scopes(Request("full"), CFG, {})
    assert ("prod", "ap-south-1") in every and ("staging", "global") in every and len(every) == 6
    assert scopes(Request("touch", (), "prod", "us-east-1", (), True), CFG, {}) == [("prod", "us-east-1"), ("prod", "global")]
    # A CloudFront event arrives in us-east-1 even when that region isn't listed.
    assert scopes(Request("touch", (), "prod", "eu-west-1", (), True), CFG, {}) == [("prod", "global")]
    ep = eni_endpoint(region="ap-south-1")
    assert scopes(Request("endpoints", (ep.id,)), CFG, {ep.id: state(ep)}) == [("prod", "ap-south-1")]


BASTION = eni_endpoint()
WEB = eni_endpoint("prod/eni/i-web", ip="203.0.113.20", sgs=("sg-web",))
CF = front()
LISTED = replace(eni_endpoint("prod/nat/nat-1"), kind=Kind.NAT, probe=None)


def test_full_runs_probe_everything_with_a_probe():
    assert targets(Request("full"), [BASTION, WEB, CF, LISTED], {}) == [BASTION.id, WEB.id, CF.id]


def test_hourly_runs_probe_new_and_changed_endpoints_only():
    previous = {BASTION.id: state(BASTION), WEB.id: state(replace(WEB, paths=())), CF.id: state(CF)}
    moved = replace(CF, probe=replace(CF.probe, url="https://d999.cloudfront.net/"))
    new = eni_endpoint("prod/eni/i-new", ip="203.0.113.30")
    assert targets(Request("inventory"), [BASTION, WEB, moved, new], previous) == [WEB.id, CF.id, new.id]


def test_tripwire_runs_probe_what_the_event_touched_and_anything_new():
    tagged = replace(WEB, network=("vpc-1", "subnet-1", "rtb-9"))
    previous = {BASTION.id: state(BASTION), WEB.id: state(WEB)}
    new = eni_endpoint("prod/eni/i-new", ip="203.0.113.30")
    assert targets(Request("touch", (), "prod", "us-east-1", ("sg-1",)), [BASTION, tagged, new], previous) == [BASTION.id, new.id]
    assert targets(Request("touch", (), "prod", "us-east-1", ("rtb-9",)), [BASTION, tagged], previous) == [WEB.id]
    assert targets(Request("touch", (), "prod", "us-east-1", ("i-web",)), [BASTION, tagged], previous) == [WEB.id]


def test_manual_runs_probe_the_named_endpoints():
    assert targets(Request("endpoints", (WEB.id,)), [BASTION, WEB], {}) == [WEB.id]


def test_batches_carry_proof_and_extra_ports_but_no_window():
    cfg = config(expected=[["prod/eni/i-0abc", {"ports": [60001], "reason": "custom"}]])
    wide = Path((1, 65535), ("sg all",), "0.0.0.0/0")
    narrow = Path((40000, 40002), ("sg range",), "0.0.0.0/0")
    eps = [replace(BASTION, paths=(PATH22, narrow, wide)), WEB]
    [b] = batches(eps, cfg)
    assert "expires_at" not in b and b["profile"] == "top100" and b["rate"] == 100
    first = b["targets"][0]
    assert first == {"endpoint_id": BASTION.id, "ip": "203.0.113.10", "proof": "eni-1 in 111111111111/us-east-1", "also": [40000, 40001, 40002, 60001]}
    assert "also" not in b["targets"][1]


def test_a_database_is_scanned_on_its_port_only_and_fronts_are_spread():
    db = replace(BASTION, id="prod/rds/db", kind=Kind.RDS, probe=Tcp((OwnedIPv4("203.0.113.40", "eni-db in 111111111111/us-east-1"),), (5432,)))
    many = [eni_endpoint(f"prod/eni/i-{n}", ip=f"203.0.113.{n}") for n in range(1, 41)]
    out = batches([db] + many + [CF, front("prod/cloudfront/E2", url="https://d2.cloudfront.net/")], CFG)
    assert len(out) == 3 and [len(b["targets"]) for b in out] == [20, 20, 1]
    assert out[0]["targets"][0]["only"] == [5432]
    assert [len(b["http"]) for b in out] == [1, 1, 0]


def test_fronts_alone_get_batches_of_their_own_and_nothing_gets_none():
    assert [len(b["http"]) for b in batches([CF], CFG)] == [1]
    fronts = [front(f"prod/cloudfront/E{n}", url=f"https://d{n}.cloudfront.net/") for n in range(25)]
    assert [len(b["http"]) for b in batches(fronts, CFG)] == [9, 8, 8]
    assert batches([], CFG) == []


def test_an_address_too_slow_for_one_window_is_split_by_port_range():
    cfg = config(scan={"profile": "all", "rate": 100})
    out = batches([BASTION], cfg)
    assert [t["range"] for b in out for t in b["targets"]] == [[1, 32768], [32769, 65535]]


# Worst case, worked out from the scanner's side: each address is paced at `rate`, the batch's
# connections at `concurrency`, every attempt holds its slot for the connect timeout, the banner
# read and the close; HTTP probes run on at least 5 threads and take at most three socket
# timeouts each.
def _worst_case(raw, now):
    batch, _ = parse_batch(raw, now)
    counts = [len(ports_for(t, batch)) for t in batch.targets]
    hold = batch.timeout + 0.5 + 0.2
    tcp = max(max(counts) / batch.rate, sum(counts) * hold / batch.concurrency) + hold if counts else 0
    return tcp + math.ceil(len(batch.http) / 5) * 3 * HTTP_TIMEOUT


@pytest.mark.parametrize("profile", ["top100", "top1000", "all"])
@pytest.mark.parametrize("rate,concurrency,timeout", [(100, 256, 1.0), (10, 256, 1.0), (500, 16, 5.0), (500, 1024, 0.05)])
def test_every_batch_fits_its_window_and_every_port_is_scanned_once(profile, rate, concurrency, timeout):
    cfg = config(scan={"profile": profile, "extra_ports": [9090], "rate": rate, "concurrency": concurrency, "timeout": timeout})
    addresses = 3 if profile == "all" else 12
    eps = [eni_endpoint(f"prod/eni/i-{n}", ip=f"203.0.113.{n}") for n in range(1, addresses + 1)]
    eps += [front(f"prod/cloudfront/E{n}", url=f"https://d{n}.cloudfront.net/") for n in range(30)]
    now = 1_000
    scanned = {}
    for b in batches(eps, cfg):
        raw = {**b, "expires_at": now + plan.EXPIRES_AFTER}
        assert _worst_case(raw, now) <= plan.EXPIRES_AFTER
        batch, _ = parse_batch(raw, now)
        for t in batch.targets:
            ports = ports_for(t, batch)
            assert not scanned.setdefault(t.ip, set()) & set(ports)
            scanned[t.ip] |= set(ports)
    want = set(port_set(profile, (9090,)))
    assert len(scanned) == addresses and all(got == want for got in scanned.values())
