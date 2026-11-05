"""The state table and bucket against moto; SNS and Step Functions shapes with fakes."""

import json
import os

import boto3
import pytest
from helpers import OPEN22, RAW_CONFIG, Fake, client_error, eni_endpoint, state
from moto import mock_aws

from aws import Bucket, DynamoStore, Publisher, member_account, start_run
from model import Alert, AlertKind, Severity

REGION = "us-east-1"


@pytest.fixture
def aws():
    os.environ.setdefault("AWS_DEFAULT_REGION", REGION)
    with mock_aws():
        yield


@pytest.fixture
def store(aws):
    ddb = boto3.client("dynamodb", region_name=REGION)
    ddb.create_table(TableName="t", KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}], AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}], BillingMode="PAY_PER_REQUEST")
    ddb.put_item(TableName="t", Item={"pk": {"S": "config"}, "json": {"S": json.dumps(RAW_CONFIG)}})
    return DynamoStore("t", ddb)


def test_config_and_states_round_trip(store):
    ep = eni_endpoint()
    assert store.config()["self_account"] == "prod"
    assert store.put(state(ep, OPEN22), 0, 1000)
    [(eid, got)] = store.states().items()
    assert eid == ep.id and got.version == 1 and got.endpoint == ep and got.findings["tcp/22"].verdict == OPEN22.verdict
    assert store.get(ep.id).findings["tcp/22"].banner == "SSH-2.0-OpenSSH_9.6"


def test_a_stale_version_loses(store):
    ep = eni_endpoint()
    assert store.put(state(ep), 0, 1000)
    assert not store.put(state(ep, OPEN22), 0, 1000)  # created meanwhile
    assert store.put(state(ep, OPEN22), 1, 1000)
    assert not store.put(state(ep), 1, 1000)
    assert store.get(ep.id).version == 2
    assert not store.delete(ep.id, 1)
    assert store.delete(ep.id, 2) and store.get(ep.id) is None


def test_states_pages_through_many_endpoints_and_skips_other_items(store):
    for n in range(60):
        store.put(state(eni_endpoint(f"prod/eni/i-{n}", ip=f"203.0.113.{n}")), 0, 1000)
    store.mark_sent("tripwire#e1", 1000)
    assert len(store.states()) == 60


def test_sent_markers_expire(store):
    assert not store.sent("tripwire#abc")
    store.mark_sent("tripwire#abc", 1000)
    assert store.sent("tripwire#abc")
    item = store.ddb.get_item(TableName="t", Key={"pk": {"S": "tripwire#abc"}})["Item"]
    assert int(item["expires"]["N"]) == 1000 + 86400


def test_endpoint_items_outlive_a_long_gap(store):
    store.put(state(eni_endpoint()), 0, 1000)
    item = store.ddb.get_item(TableName="t", Key={"pk": {"S": "endpoint#prod/eni/i-0abc"}})["Item"]
    assert int(item["expires"]["N"]) - 1000 >= 365 * 86400


def test_bucket(aws):
    s3 = boto3.client("s3", region_name=REGION)
    s3.create_bucket(Bucket="inventory")
    bucket = Bucket("inventory", s3)
    bucket.put_json("inventory/latest.json", {"endpoints": []})
    assert bucket.get_json("inventory/latest.json") == {"endpoints": []}
    bucket.put_text("suggested-expected.tf", "expected = {}\n")
    assert s3.get_object(Bucket="inventory", Key="suggested-expected.tf")["Body"].read() == b"expected = {}\n"
    assert bucket.url("x") == "s3://inventory/x"


def test_publisher_sends_amazon_q_json_and_plain_email():
    sns = Fake(publish={})
    alert = Alert(AlertKind.FINDING, Severity.CRITICAL, "prod", ":rotating_light: prod/eni/i-1: tcp/22 unexpected-open", "*prod/eni/i-1*: tcp/22 *open*", "prod/eni/i-1", {"subject": "tcp/22"})
    Publisher("arn:topic", True, sns)(alert)
    [(_, args)] = sns.calls
    body = json.loads(args["Message"])
    chat = json.loads(body["default"])
    assert args["MessageStructure"] == "json" and args["Subject"] == "prod/eni/i-1: tcp/22 unexpected-open"
    assert chat["version"] == "1.0" and chat["source"] == "custom" and chat["content"]["textType"] == "client-markdown"
    assert chat["metadata"]["additionalContext"] == {"kind": "finding", "severity": "critical", "account": "prod", "endpoint": "prod/eni/i-1", "subject": "tcp/22"}
    assert body["email"] == "prod/eni/i-1: tcp/22 unexpected-open\n\nprod/eni/i-1: tcp/22 open"
    Publisher("arn:topic", False, sns)(alert)
    assert json.loads(sns.calls[1][1]["Message"])["default"].startswith("prod/eni/i-1: tcp/22")


def test_start_run_is_idempotent_by_name():
    sfn = Fake(start_execution=client_error("ExecutionAlreadyExists"))
    start_run(sfn, "arn:sm", "tripwire-" + "x" * 100, {"delay": 120})
    assert len(sfn.calls[0][1]["name"]) == 80
    with pytest.raises(Exception):
        start_run(Fake(start_execution=client_error("AccessDenied")), "arn:sm", "n", {})


def test_member_account_assumes_the_member_role_with_the_external_id():
    sts = Fake(assume_role={"Credentials": {"AccessKeyId": "AKIA", "SecretAccessKey": "s", "SessionToken": "t"}})
    acct = member_account("staging", "222222222222", "perimeter-member", "ext-1", sts)
    assert sts.calls == [("assume_role", {"RoleArn": "arn:aws:iam::222222222222:role/perimeter-member", "RoleSessionName": "perimeter", "ExternalId": "ext-1"})]
    assert acct.client("ec2", "eu-west-1") is acct.client("ec2", "eu-west-1")
    assert acct.client("ec2", "eu-west-1").meta.region_name == "eu-west-1"


def test_start_run_before_the_state_machine_exists_is_not_an_error():
    # Live: the first apply's own resources fired tripwires before the state machine existed.
    start_run(Fake(start_execution=client_error("StateMachineDoesNotExist")), "arn:sm", "n", {})
