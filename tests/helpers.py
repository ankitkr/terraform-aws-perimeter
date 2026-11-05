from model import Config, Endpoint, EndpointState, Finding, Http, Kind, OwnedIPv4, Path, Severity, Tcp, Verdict

RAW_CONFIG = {
    "mode": "enforce",
    "undeclared": "alert",
    "min_severity": "low",
    "alert_on_closed": False,
    "expected": [],
    "tag_prefix": "perimeter",
    "accounts": {"prod": "111111111111", "staging": "222222222222"},
    "self_account": "prod",
    "regions": ["us-east-1"],
    "member_role_name": "perimeter-member",
    "scan": {"profile": "top100", "extra_ports": [], "rate": 100, "concurrency": 256, "timeout": 1.0},
    "bucket": "perimeter-bucket",
    "sns_topic_arn": "arn:aws:sns:us-east-1:111111111111:perimeter",
    "slack": True,
    "state_machine_arn": "arn:aws:states:us-east-1:111111111111:stateMachine:perimeter",
}


def config(**overrides):
    return Config.parse({**RAW_CONFIG, **overrides})


PATH22 = Path((22, 22), ("sg-1 rule sgr-9 tcp/22 from 0.0.0.0/0", "acl-2 #100 allow", "acl-2 egress #100 allow 1024-65535", "rtb-3 0.0.0.0/0 → igw-4"), "0.0.0.0/0")


def eni_endpoint(id="prod/eni/i-0abc", display="bastion", paths=(PATH22,), ip="203.0.113.10", sgs=("sg-1",), tags=None, region="us-east-1"):
    account = id.split("/")[0]
    return Endpoint(
        id, display, account, region, Kind.ENI, f"arn:aws:ec2:{region}:111111111111:instance/{id.rsplit('/', 1)[-1]}", tags or {}, sgs,
        Tcp((OwnedIPv4(ip, f"eni-1 in 111111111111/{region}"),)), tuple(paths),
    )


def front(id="prod/cloudfront/E1", kind=Kind.CLOUDFRONT, url="https://d111.cloudfront.net/"):
    return Endpoint(id, id.rsplit("/", 1)[-1], id.split("/")[0], "global" if kind is Kind.CLOUDFRONT else "us-east-1", kind, probe=Http(url, url.split("/")[2]))


def finding(subject, verdict, severity, **kw):
    return Finding(subject, verdict, severity, kw.pop("detail", ""), **kw)


def state(endpoint, *findings, declared=False, http=None):
    return EndpointState(endpoint, declared, {f.subject: f for f in findings}, None, http)


OPEN22 = finding("tcp/22", Verdict.UNEXPECTED_OPEN, Severity.CRITICAL, paths=(PATH22,), banner="SSH-2.0-OpenSSH_9.6")


class Fake:
    """A boto3 client stand-in: canned responses (or callables, or exceptions) per method."""

    def __init__(self, **responses):
        self.responses = responses
        self.calls = []

    def can_paginate(self, method):
        return False

    def __getattr__(self, name):
        if name.startswith("_") or name not in self.responses:
            raise AttributeError(name)

        def call(**kwargs):
            self.calls.append((name, kwargs))
            r = self.responses[name]
            r = r(**kwargs) if callable(r) else r
            if isinstance(r, Exception):
                raise r
            return r

        return call


def client_error(code, op="Call"):
    from botocore.exceptions import ClientError

    return ClientError({"Error": {"Code": code, "Message": code}}, op)
