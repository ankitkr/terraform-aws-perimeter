"""The handlers end to end: planner -> scanner output -> judge over moto's DynamoDB and S3,
with inventory and member sessions replaced; and the tripwire handler."""

import json
import os
import time

import boto3
import pytest
import helpers
from helpers import RAW_CONFIG, Fake, eni_endpoint, front
from moto import mock_aws

import app
import aws
import inventory
from inventory import RegionInventory

REGION = "us-east-1"
HERE = os.path.dirname(__file__)


@pytest.fixture
def world(monkeypatch):
    os.environ.setdefault("AWS_DEFAULT_REGION", REGION)
    with mock_aws():
        ddb = boto3.client("dynamodb", region_name=REGION)
        ddb.create_table(TableName="t", KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}], AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}], BillingMode="PAY_PER_REQUEST")
        s3 = boto3.client("s3", region_name=REGION)
        s3.create_bucket(Bucket="perimeter-bucket")
        sns, sfn = Fake(publish={}), Fake(start_execution={})
        w = type("World", (), {})()
        monkeypatch.setattr(app, "_clients", {"dynamodb": ddb, "s3": s3, "sns": sns, "stepfunctions": sfn})
        monkeypatch.setenv("TABLE_NAME", "t")
        monkeypatch.setattr(aws, "_config_cache", {"at": 0.0, "value": None})
        w.unreachable = set()

        def accounts(cfg, names):
            reachable = {n: inventory.Account(n, cfg.accounts[n], None) for n in names if n not in w.unreachable}
            return reachable, [f"{n}: can't assume perimeter-member (AccessDenied); is the member module applied there?" for n in names if n in w.unreachable]

        monkeypatch.setattr(app, "_accounts", accounts)
        w.released = set()
        monkeypatch.setattr(inventory, "verify_ownership", lambda account, region, addresses: [a for a in addresses if a.ip not in w.released])

        w.ddb, w.s3, w.sns, w.sfn = ddb, s3, sns, sfn
        w.endpoints = {("prod", REGION): [eni_endpoint()], ("prod", "global"): [front()]}
        w.failing = set()

        def discover(scope):
            inv = RegionInventory(list(w.endpoints.get(scope, [])))
            if scope in w.failing:
                inv.problems.append(f"{scope}: AccessDenied")
            return inv

        monkeypatch.setattr(inventory, "discover_region", lambda account, region: discover((account.name, region)))
        monkeypatch.setattr(inventory, "discover_global", lambda account: discover((account.name, "global")))

        def configure(**overrides):
            raw = {**RAW_CONFIG, "accounts": {"prod": "111111111111"}, **overrides}
            ddb.put_item(TableName="t", Item={"pk": {"S": "config"}, "json": {"S": json.dumps(raw)}})

        w.configure = configure
        configure(mode="baseline")
        yield w


def scanned(batch, open_ports):
    """What the scanner would return for a batch: open_ports per endpoint id."""
    return {
        "at": 1_800_000_000,
        "targets": [{"endpoint_id": t["endpoint_id"], "ip": t["ip"], "scanned": [[1, 1024]], "open": open_ports.get(t["endpoint_id"], {}), "closed": []} for t in batch["targets"]],
        "http": [{"endpoint_id": h["endpoint_id"], "url": h["url"], "status": 403, "server": "CloudFront", "error": None} for h in batch["http"]],
        "refused": [],
        "not_scanned": batch["not_scanned"],
    }


def run(w, request, open_ports=None, name="run"):
    """Plan, verify and "scan" each batch, judge: the state machine's steps."""
    planned = app.planner({"input": request, "execution": name}, None)
    results = [scanned(app.planner({"verify": b}, None), open_ports or {}) for b in planned["batches"]]
    return planned, app.judge({"run": planned["run"], "results": results}, None)


def published(w):
    out = [json.loads(json.loads(c[1]["Message"])["default"]) for c in w.sns.calls]
    w.sns.calls.clear()
    return out


def test_baseline_then_enforce(world):
    planned, judged = run(world, {"full": True}, {"prod/eni/i-0abc": {"22": "SSH-2.0-OpenSSH_9.6"}})
    assert [t["endpoint_id"] for b in planned["batches"] for t in b["targets"]] == ["prod/eni/i-0abc"]
    assert planned["batches"][0]["http"][0]["endpoint_id"] == "prod/cloudfront/E1"

    # Baseline: one summary, the suggestion, and the inventory document.
    [summary] = published(world)
    assert summary["metadata"]["eventType"] == "perimeter-summary"
    assert "In enforce mode 1 would alert (1 critical)" in summary["content"]["description"]
    suggestion = world.s3.get_object(Bucket="perimeter-bucket", Key="suggested-expected.tf")["Body"].read().decode()
    assert "  # tcp/22: SSH-2.0-OpenSSH_9.6\n" in suggestion and '"prod/eni/i-0abc"' in suggestion
    doc = json.loads(world.s3.get_object(Bucket="perimeter-bucket", Key="inventory/latest.json")["Body"].read())
    bastion = next(e for e in doc["endpoints"] if e["id"] == "prod/eni/i-0abc")
    assert bastion["ports"]["22"]["verdict"] == "unexpected-open" and bastion["ports"]["22"]["paths"][0]["refs"][0].startswith("sg-1 rule sgr-9")
    assert bastion["addresses"] == [{"ip": "203.0.113.10", "proof": "eni-1 in 111111111111/us-east-1"}]
    assert next(e for e in doc["endpoints"] if e["id"] == "prod/cloudfront/E1")["http"]["status"] == 403

    # Enforce: the hourly run probes nothing new, and reports what isn't declared, once.
    world.configure(mode="enforce", expected=[["prod/cloudfront/*", {"ports": [443], "reason": "site"}]])
    planned, _ = run(world, {"mode": "inventory"}, name="run2")
    assert planned["batches"] == []
    alerts = published(world)
    assert [(a["metadata"]["additionalContext"]["kind"], a["metadata"]["additionalContext"].get("subject")) for a in alerts] == [("finding", "tcp/22")]
    assert "Why: sg-1 rule sgr-9 tcp/22 from 0.0.0.0/0" in alerts[0]["content"]["description"]
    run(world, {"mode": "inventory"}, name="run3")
    assert published(world) == []

    # Declaring it resolves it.
    world.configure(mode="enforce", expected=[["prod/eni/i-0abc", {"ports": [22], "reason": "bastion"}], ["prod/cloudfront/*", {"ports": [443], "reason": "site"}]])
    run(world, {"mode": "inventory"}, name="run4")
    [resolved] = published(world)
    assert resolved["metadata"]["additionalContext"]["kind"] == "resolved"


def test_removed_only_when_the_scope_was_listed(world):
    world.configure(mode="enforce")
    run(world, {"full": True})
    published(world)
    world.endpoints[("prod", REGION)] = []
    world.failing.add(("prod", REGION))
    run(world, {"mode": "inventory"}, name="r2")
    assert published(world) == []
    assert "endpoint#prod/eni/i-0abc" in {i["pk"]["S"] for i in world.ddb.scan(TableName="t")["Items"]}
    doc = json.loads(world.s3.get_object(Bucket="perimeter-bucket", Key="inventory/latest.json")["Body"].read())
    assert "prod/eni/i-0abc" in [e["id"] for e in doc["endpoints"]] and doc["incomplete"]

    world.failing.clear()
    run(world, {"mode": "inventory"}, name="r3")
    assert [a["metadata"]["additionalContext"]["kind"] for a in published(world)] == ["removed-endpoint"]
    assert "endpoint#prod/eni/i-0abc" not in {i["pk"]["S"] for i in world.ddb.scan(TableName="t")["Items"]}


def test_a_new_endpoint_is_probed_by_the_hourly_run(world):
    world.configure(mode="enforce")
    run(world, {"full": True})
    published(world)
    world.endpoints[("prod", REGION)].append(eni_endpoint("prod/eni/i-new", "new", ip="203.0.113.50"))
    planned, _ = run(world, {"mode": "inventory"}, {"prod/eni/i-new": {"22": None}}, name="r2")
    assert [t["endpoint_id"] for b in planned["batches"] for t in b["targets"]] == ["prod/eni/i-new"]
    [alert] = published(world)
    assert alert["metadata"]["additionalContext"]["kind"] == "new-endpoint" and "tcp/22 *open*" in alert["content"]["description"]


def test_tripwire_alerts_once_and_starts_a_targeted_run(world):
    world.configure(mode="enforce", accounts={"prod": "111111111111", "staging": "222222222222"})
    event = json.load(open(os.path.join(HERE, "fixtures", "cloudtrail.json")))["sg_ingress_ssh_world"]
    assert app.tripwire(event, None) == {"alerted": True}
    [alert] = published(world)
    assert alert["content"]["description"].startswith("*alice@acme.com (AWSReservedSSO_AdministratorAccess_0123456789abcdef)* opened tcp/22 to 0.0.0.0/0")
    [(_, start)] = world.sfn.calls
    assert start["stateMachineArn"] == RAW_CONFIG["state_machine_arn"] and start["name"] == f"tripwire-{event['detail']['eventID']}"
    assert json.loads(start["input"]) == {"delay": 120, "touch": {"account": "staging", "region": "ap-south-1", "resources": ["sg-0abc1234"], "global": False}}
    assert app.tripwire(event, None) == {"alerted": False}
    assert published(world) == [] and len(world.sfn.calls) == 1


def test_tripwire_ignores_harmless_events(world):
    event = json.load(open(os.path.join(HERE, "fixtures", "cloudtrail.json")))["sg_ingress_private"]
    assert app.tripwire(event, None) == {"alerted": False}
    assert published(world) == [] and world.sfn.calls == []


def test_targeted_run_after_a_tripwire_probes_the_touched_endpoint(world):
    world.configure(mode="enforce")
    run(world, {"full": True})
    published(world)
    world.endpoints[("prod", REGION)].append(eni_endpoint("prod/eni/i-web", "web", ip="203.0.113.20", sgs=("sg-web",)))
    planned, _ = run(world, {"delay": 120, "touch": {"account": "prod", "region": REGION, "resources": ["sg-1"], "global": False}}, name="t1")
    assert sorted(t["endpoint_id"] for b in planned["batches"] for t in b["targets"]) == ["prod/eni/i-0abc", "prod/eni/i-web"]
    assert planned["batches"][0]["http"] == []


def test_an_account_without_its_member_role_is_incomplete_not_removed(world):
    world.configure(mode="enforce")
    run(world, {"full": True})
    published(world)
    world.unreachable.add("prod")
    planned, _ = run(world, {"full": True}, name="r2")
    assert planned["batches"] == [] and published(world) == []
    doc = json.loads(world.s3.get_object(Bucket="perimeter-bucket", Key="inventory/latest.json")["Body"].read())
    assert doc["incomplete"] == ["prod: can't assume perimeter-member (AccessDenied); is the member module applied there?"]
    assert {e["id"] for e in doc["endpoints"]} == {"prod/eni/i-0abc", "prod/cloudfront/E1"}


def test_accounts_report_a_role_that_cant_be_assumed(monkeypatch):
    from helpers import client_error, config

    ok = {"Credentials": {"AccessKeyId": "AKIA", "SecretAccessKey": "s", "SessionToken": "t"}}
    sts = Fake(assume_role=lambda **kw: client_error("AccessDenied") if "222222222222" in kw["RoleArn"] else ok)
    monkeypatch.setattr(app, "_clients", {"sts": sts})
    accounts, problems = app._accounts(config(), ["prod", "staging"])
    assert list(accounts) == ["prod"]
    assert problems == ["staging: can't assume perimeter-member (AccessDenied); is the member module applied there?"]


def test_tripwire_leaves_routine_changes_to_the_hourly_inventory(world):
    # Live in staging, EKS re-attaches security groups to ENIs every few minutes (info).
    world.configure(mode="enforce", accounts={"prod": "111111111111", "staging": "222222222222"})
    event = json.load(open(os.path.join(HERE, "fixtures", "cloudtrail.json")))["modify_eni_groups"]
    assert app.tripwire(event, None) == {"alerted": False}
    assert published(world) == [] and world.sfn.calls == []
    world.configure(mode="enforce", accounts={"prod": "111111111111", "staging": "222222222222"}, min_severity="info")
    aws._config_cache["value"] = None
    assert app.tripwire(event, None) == {"alerted": True}


def test_a_tripwire_alert_survives_a_failed_publish(world):
    world.configure(mode="enforce", accounts={"prod": "111111111111", "staging": "222222222222"})
    failures = [helpers.client_error("Throttling", "Publish")]
    world.sns.responses["publish"] = lambda **kw: failures.pop() if failures else {}
    event = json.load(open(os.path.join(HERE, "fixtures", "cloudtrail.json")))["sg_ingress_ssh_world"]
    with pytest.raises(Exception):
        app.tripwire(event, None)
    world.sns.calls.clear()
    assert app.tripwire(event, None) == {"alerted": True}
    assert len(published(world)) == 1
    assert app.tripwire(event, None) == {"alerted": False}
    assert published(world) == []


def test_a_failed_publish_leaves_the_verdicts_unknown(world):
    world.configure(mode="enforce")
    failures = [helpers.client_error("Throttling", "Publish")]
    world.sns.responses["publish"] = lambda **kw: failures.pop() if failures else {}
    with pytest.raises(Exception):
        run(world, {"full": True}, {"prod/eni/i-0abc": {"22": "SSH-2.0-OpenSSH_9.6"}})
    world.sns.calls.clear()
    run(world, {"mode": "inventory"}, {"prod/eni/i-0abc": {"22": "SSH-2.0-OpenSSH_9.6"}}, name="r2")
    bastion = [a for a in published(world) if a["metadata"]["additionalContext"]["kind"] == "new-endpoint" and "bastion" in a["content"]["description"]]
    assert len(bastion) == 1 and "tcp/22 *open*" in bastion[0]["content"]["description"]


def test_endpoints_of_an_account_or_region_no_longer_configured_are_forgotten(world):
    world.configure(mode="enforce", regions=["us-east-1", "eu-west-1"])
    world.endpoints[("prod", "eu-west-1")] = [eni_endpoint("prod/eni/i-eu", "eu", ip="203.0.113.60", region="eu-west-1")]
    run(world, {"full": True})
    published(world)
    world.configure(mode="enforce")
    run(world, {"mode": "inventory"}, name="r2")
    assert published(world) == []
    doc = json.loads(world.s3.get_object(Bucket="perimeter-bucket", Key="inventory/latest.json")["Body"].read())
    assert "prod/eni/i-eu" not in {e["id"] for e in doc["endpoints"]}
    assert doc["unconfigured"] == ["1 endpoint in an account or region no longer configured was removed: prod/eni/i-eu"]
    assert "endpoint#prod/eni/i-eu" not in {i["pk"]["S"] for i in world.ddb.scan(TableName="t")["Items"]}

    world.configure(mode="enforce", accounts={"staging": "222222222222"}, self_account="staging")
    run(world, {"mode": "inventory"}, name="r3")
    assert published(world) == []
    doc = json.loads(world.s3.get_object(Bucket="perimeter-bucket", Key="inventory/latest.json")["Body"].read())
    assert doc["endpoints"] == [] and doc["unconfigured"] == ["2 endpoints in an account or region no longer configured were removed: prod/cloudfront/E1, prod/eni/i-0abc"]


def test_each_batch_reverifies_its_addresses_and_gets_its_window_when_it_starts(world):
    world.configure(mode="enforce")
    planned = app.planner({"input": {"full": True}, "execution": "r1"}, None)
    [batch] = planned["batches"]
    assert "expires_at" not in batch
    world.released.add("203.0.113.10")
    before = int(time.time())
    verified = app.planner({"verify": batch}, None)
    assert verified["targets"] == [] and verified["http"] == batch["http"]
    assert before + 600 <= verified["expires_at"] <= int(time.time()) + 600
    assert verified["not_scanned"] == ["prod/eni/i-0abc: 203.0.113.10 no longer held by eni-1 in 111111111111/us-east-1"]
    app.judge({"run": planned["run"], "results": [scanned(verified, {})]}, None)
    doc = json.loads(world.s3.get_object(Bucket="perimeter-bucket", Key="inventory/latest.json")["Body"].read())
    assert doc["not_scanned"] == verified["not_scanned"]


def test_verify_refuses_targets_of_unknown_or_unreachable_accounts(world):
    world.configure(mode="enforce", accounts={"prod": "111111111111", "staging": "222222222222"})
    world.unreachable.add("staging")
    batch = {"targets": [{"endpoint_id": "x/eni/i-1", "ip": "203.0.113.1", "proof": "eni-1 in 999999999999/us-east-1"}, {"endpoint_id": "staging/eni/i-2", "ip": "203.0.113.2", "proof": "eni-2 in 222222222222/us-east-1"}], "http": []}
    verified = app.planner({"verify": batch}, None)
    assert verified["targets"] == []
    assert verified["not_scanned"] == [
        "x/eni/i-1: 203.0.113.1: its proof names no configured account",
        "staging/eni/i-2: 203.0.113.2: ownership not verified (staging: can't assume perimeter-member (AccessDenied); is the member module applied there?)",
    ]
