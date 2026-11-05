"""AWS adapters: member-account sessions, the state table, the inventory bucket, SNS and Step
Functions."""

import json
import logging
import os
import time

import boto3
from botocore.config import Config as BotoConfig
from botocore.exceptions import ClientError

from inventory import Account
from model import EndpointState

log = logging.getLogger(__name__)

RETRIES = BotoConfig(retries={"max_attempts": 8, "mode": "adaptive"})
# An endpoint's item outlives a long gap in runs; one that is gone is deleted by the judge.
STATE_TTL = 400 * 86400
TRIPWIRE_TTL = 86400


def _code(exc):
    return exc.response.get("Error", {}).get("Code", "")


# --- sessions -----------------------------------------------------------------------------------


def member_account(name, account_id, role_name, external_id=None, sts=None, partition="aws"):
    """An Account whose clients act through the member role in that account. The module's own
    account goes through its member role too, so every account is read the same way."""
    sts = sts or boto3.client("sts")
    args = {"RoleArn": f"arn:{partition}:iam::{account_id}:role/{role_name}", "RoleSessionName": "perimeter"}
    if external_id:
        args["ExternalId"] = external_id
    creds = sts.assume_role(**args)["Credentials"]
    session = boto3.Session(aws_access_key_id=creds["AccessKeyId"], aws_secret_access_key=creds["SecretAccessKey"], aws_session_token=creds["SessionToken"])
    cache = {}

    def client(service, region):
        key = (service, region)
        if key not in cache:
            cache[key] = session.client(service, region_name=region, config=RETRIES)
        return cache[key]

    return Account(name, account_id, client)


# --- the state table ----------------------------------------------------------------------------


class DynamoStore:
    """The config item, one item per endpoint ("endpoint#<id>"), and the tripwire events already alerted on."""

    def __init__(self, table, client=None):
        self.table = table
        self.ddb = client or boto3.client("dynamodb")

    def config(self):
        item = self.ddb.get_item(TableName=self.table, Key={"pk": {"S": "config"}}, ConsistentRead=True)
        return json.loads(item["Item"]["json"]["S"])

    @staticmethod
    def _state(item):
        return EndpointState.from_json(json.loads(item["json"]["S"]), int(item["version"]["N"]))

    def states(self):
        """Every endpoint's stored state, by endpoint id."""
        out, start = {}, None
        while True:
            args = {"TableName": self.table, "ConsistentRead": True, "FilterExpression": "begins_with(pk, :p)", "ExpressionAttributeValues": {":p": {"S": "endpoint#"}}}
            if start:
                args["ExclusiveStartKey"] = start
            page = self.ddb.scan(**args)
            for item in page.get("Items") or ():
                state = self._state(item)
                out[state.endpoint.id] = state
            start = page.get("LastEvaluatedKey")
            if not start:
                return out

    def get(self, endpoint_id):
        item = self.ddb.get_item(TableName=self.table, Key={"pk": {"S": f"endpoint#{endpoint_id}"}}, ConsistentRead=True).get("Item")
        return self._state(item) if item else None

    def _expect(self, version):
        if not version:
            return {"ConditionExpression": "attribute_not_exists(pk)"}
        return {"ConditionExpression": "#v = :v", "ExpressionAttributeNames": {"#v": "version"}, "ExpressionAttributeValues": {":v": {"N": str(version)}}}

    def put(self, state, version, now):
        """Write state if the stored version is still `version` (0: no item yet). False when
        another run wrote first."""
        try:
            self.ddb.put_item(
                TableName=self.table,
                Item={
                    "pk": {"S": f"endpoint#{state.endpoint.id}"},
                    "version": {"N": str(version + 1)},
                    "json": {"S": json.dumps(state.to_json())},
                    "expires": {"N": str(now + STATE_TTL)},
                },
                **self._expect(version),
            )
        except ClientError as exc:
            if _code(exc) == "ConditionalCheckFailedException":
                return False
            raise
        return True

    def delete(self, endpoint_id, version):
        try:
            self.ddb.delete_item(TableName=self.table, Key={"pk": {"S": f"endpoint#{endpoint_id}"}}, **self._expect(version))
        except ClientError as exc:
            if _code(exc) == "ConditionalCheckFailedException":
                return False
            raise
        return True

    def sent(self, key):
        """Whether key was marked sent: EventBridge delivers at least once."""
        return "Item" in self.ddb.get_item(TableName=self.table, Key={"pk": {"S": key}}, ConsistentRead=True)

    def mark_sent(self, key, now, ttl=TRIPWIRE_TTL):
        self.ddb.put_item(TableName=self.table, Item={"pk": {"S": key}, "expires": {"N": str(now + ttl)}})


# --- the bucket ---------------------------------------------------------------------------------


class Bucket:
    def __init__(self, name, client=None):
        self.name = name
        self.s3 = client or boto3.client("s3")

    def put_json(self, key, value):
        self.s3.put_object(Bucket=self.name, Key=key, Body=json.dumps(value, indent=1, sort_keys=False).encode(), ContentType="application/json")

    def get_json(self, key):
        return json.loads(self.s3.get_object(Bucket=self.name, Key=key)["Body"].read())

    def put_text(self, key, text, content_type="text/plain"):
        self.s3.put_object(Bucket=self.name, Key=key, Body=text.encode(), ContentType=content_type)

    def url(self, key):
        return f"s3://{self.name}/{key}"


# --- notifications and runs ---------------------------------------------------------------------


class Publisher:
    def __init__(self, topic_arn, slack, sns=None):
        self.topic_arn = topic_arn
        self.slack = slack
        self.sns = sns or boto3.client("sns")

    def __call__(self, alert):
        log.info("alert %s %s %s: %s", alert.kind.value, alert.severity.label, alert.endpoint_id or alert.account, alert.title)
        if not self.topic_arn:
            return
        subject, body = alert.sns(self.slack)
        self.sns.publish(TopicArn=self.topic_arn, Subject=subject, Message=body, MessageStructure="json")


def start_run(sfn, state_machine_arn, name, payload):
    """Start an execution; a second start with the same name and input is a no-op, so a
    redelivered tripwire event never starts two runs."""
    try:
        sfn.start_execution(stateMachineArn=state_machine_arn, name=name[:80], input=json.dumps(payload))
    except ClientError as exc:
        code = _code(exc)
        if code == "StateMachineDoesNotExist":
            # The first apply creates the tripwire before the state machine, and its own changes
            # fire tripwires; the hourly run sees them. Raising would make Lambda retry and alert twice.
            log.warning("no state machine yet (still deploying?); %s left to the hourly run", name)
            return
        if code != "ExecutionAlreadyExists":
            raise
        log.info("execution %s already exists", name)


_config_cache = {"at": 0.0, "value": None}


def load_config(store, max_age=60):
    if _config_cache["value"] is None or time.time() - _config_cache["at"] > max_age:
        _config_cache["value"], _config_cache["at"] = store.config(), time.time()
    return _config_cache["value"]


def table_name():
    return os.environ["TABLE_NAME"]
