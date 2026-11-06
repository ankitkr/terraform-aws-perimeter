"""The domain: endpoints, why they are reachable, what the scanner saw, what was expected, and
the verdicts, findings and alerts that come out of them."""

import json
import re
from dataclasses import dataclass, field
from enum import Enum, IntEnum


class Kind(Enum):
    ENI = "eni"
    EIP = "eip"
    NAT = "nat"
    ALB = "alb"
    NLB = "nlb"
    CLB = "clb"
    CLOUDFRONT = "cloudfront"
    APIGW_REST = "apigw-rest"
    APIGW_HTTP = "apigw-http"
    APIGW_WS = "apigw-ws"
    LAMBDA_URL = "lambda-url"
    RDS = "rds"
    OPENSEARCH = "opensearch"
    S3_WEBSITE = "s3-website"
    EKS = "eks"
    LIGHTSAIL = "lightsail"


class State(Enum):
    OPEN = "open"
    CLOSED = "closed"  # answered with a reset
    FILTERED = "filtered"  # no answer before the timeout, or unreachable


class Severity(IntEnum):
    NONE = 0
    INFO = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5

    @classmethod
    def parse(cls, name):
        return cls[name.upper()]

    @property
    def label(self):
        return self.name.lower()


class Verdict(Enum):
    EXPECTED_OPEN = "expected-open"
    UNEXPECTED_OPEN = "unexpected-open"
    LATENT_CONFIRMED = "latent-confirmed"
    LATENT_FILTERED = "latent-filtered"
    ALLOWLISTED = "allowlisted"
    UNEXPLAINED_OPEN = "unexplained-open"
    EXPECTED_CLOSED = "expected-closed"
    # Endpoint-level verdicts for managed fronts.
    UNAUTHENTICATED_URL = "unauthenticated-url"
    PUBLIC_API = "public-api"
    EXPECTED_PUBLIC = "expected-public"
    HTTP_OPEN = "http-open"
    HTTP_DENIED = "http-denied"
    HTTP_UNREACHABLE = "http-unreachable"
    EXPECTATION_CONFLICT = "expectation-conflict"


# Inventoried once per account, not per region.
GLOBAL_KINDS = frozenset({Kind.CLOUDFRONT, Kind.S3_WEBSITE})


# --- endpoints ----------------------------------------------------------------------------------


@dataclass(frozen=True)
class OwnedIPv4:
    ip: str
    proof: str  # "eni-… in <account id>/<region>" or "lightsail:<name> in <account id>/<region>"


@dataclass(frozen=True)
class Tcp:
    addresses: tuple[OwnedIPv4, ...]
    # None: the scan profile. A database is scanned on its engine port only.
    ports: tuple[int, ...] | None = None


@dataclass(frozen=True)
class Http:
    url: str
    host: str


@dataclass(frozen=True)
class Path:
    """One configured way in from the internet, for a range of TCP ports."""

    ports: tuple[int, int]  # inclusive
    refs: tuple[str, ...]
    cidr: str
    verified: bool = True
    # The NACL lets only part of the client's ephemeral range back out.
    partial: bool = False

    def covers(self, port):
        return self.ports[0] <= port <= self.ports[1]


class Flag(Enum):
    UNAUTHENTICATED_URL = "unauthenticated-url"  # Lambda URL: AuthType NONE and a public policy
    PUBLIC_API = "public-api"  # EKS: public endpoint open to internet CIDRs


@dataclass(frozen=True)
class Endpoint:
    id: str  # "<account name>/<kind>/<stable id>"
    display: str
    account: str  # account name, e.g. "self"
    region: str
    kind: Kind
    arn: str = ""
    tags: dict = field(default_factory=dict, hash=False, compare=True)
    security_groups: tuple[str, ...] = ()
    probe: Tcp | Http | None = None
    paths: tuple[Path, ...] = ()
    flags: frozenset[Flag] = frozenset()
    notes: tuple[str, ...] = ()
    # Network ids a tripwire event can name: vpc, subnets, ENIs, route tables, NACLs.
    network: tuple[str, ...] = ()

    @property
    def scope(self):
        """(account, region) whose inventory owns this endpoint; global services have "global"."""
        return (self.account, "global" if self.kind in GLOBAL_KINDS else self.region)

    def paths_for(self, port):
        return [p for p in self.paths if p.covers(port)]

    @property
    def addresses(self):
        return self.probe.addresses if isinstance(self.probe, Tcp) else ()

    def to_json(self):
        probe = None
        if isinstance(self.probe, Tcp):
            probe = {"tcp": [[a.ip, a.proof] for a in self.probe.addresses], "ports": list(self.probe.ports) if self.probe.ports is not None else None}
        elif isinstance(self.probe, Http):
            probe = {"url": self.probe.url, "host": self.probe.host}
        return {
            "id": self.id,
            "display": self.display,
            "account": self.account,
            "region": self.region,
            "kind": self.kind.value,
            "arn": self.arn,
            "tags": self.tags,
            "security_groups": list(self.security_groups),
            "probe": probe,
            "paths": [{"ports": list(p.ports), "refs": list(p.refs), "cidr": p.cidr, "verified": p.verified, "partial": p.partial} for p in self.paths],
            "flags": sorted(f.value for f in self.flags),
            "notes": list(self.notes),
            "network": list(self.network),
        }

    @classmethod
    def from_json(cls, raw):
        probe = raw.get("probe")
        if probe and "tcp" in probe:
            ports = probe.get("ports")
            probe = Tcp(tuple(OwnedIPv4(ip, proof) for ip, proof in probe["tcp"]), tuple(ports) if ports is not None else None)
        elif probe:
            probe = Http(probe["url"], probe["host"])
        return cls(
            id=raw["id"],
            display=raw["display"],
            account=raw["account"],
            region=raw["region"],
            kind=Kind(raw["kind"]),
            arn=raw.get("arn", ""),
            tags=raw.get("tags") or {},
            security_groups=tuple(raw.get("security_groups") or ()),
            probe=probe,
            paths=tuple(Path(tuple(p["ports"]), tuple(p["refs"]), p["cidr"], p["verified"], p.get("partial", False)) for p in raw.get("paths") or ()),
            flags=frozenset(Flag(f) for f in raw.get("flags") or ()),
            notes=tuple(raw.get("notes") or ()),
            network=tuple(raw.get("network") or ()),
        )


# --- port sets ----------------------------------------------------------------------------------


def to_ranges(ports):
    """Sorted ports as [[lo, hi], …]: the compact form scans travel and are stored in."""
    ranges = []
    for p in sorted(set(ports)):
        if ranges and p == ranges[-1][1] + 1:
            ranges[-1][1] = p
        else:
            ranges.append([p, p])
    return ranges


def from_ranges(ranges):
    return {p for lo, hi in ranges for p in range(lo, hi + 1)}


# --- observations -------------------------------------------------------------------------------


@dataclass(frozen=True)
class Observation:
    endpoint_id: str
    ip: str
    port: int
    state: State
    banner: str | None = None
    at: int = 0


@dataclass(frozen=True)
class HttpObservation:
    endpoint_id: str
    url: str
    status: int | None  # None: no HTTP answer
    server: str | None = None
    error: str | None = None
    at: int = 0


@dataclass(frozen=True)
class ScanRecord:
    """The last scan of one endpoint's addresses, compact: open ports with banners and closed
    ports per address; every other scanned port was filtered. Both maps hold every scanned
    address, empty when nothing answered."""

    at: int
    scanned: frozenset[int]
    open: dict  # ip -> {port: banner or None}
    closed: dict  # ip -> frozenset of ports

    def observations(self, endpoint_id, interest):
        """Observations for the ports that matter: those open or closed anywhere, plus the
        scanned ones in interest (ports with a path or an expectation)."""
        ports = set(interest) & self.scanned
        for ip in self.open:
            ports |= set(self.open[ip])
        for ip in self.closed:
            ports |= set(self.closed[ip])
        out = []
        for ip in sorted(set(self.open) | set(self.closed)):
            opened, closed = self.open.get(ip, {}), self.closed.get(ip, frozenset())
            for port in sorted(ports):
                if port in opened:
                    out.append(Observation(endpoint_id, ip, port, State.OPEN, opened[port], self.at))
                elif port in closed:
                    out.append(Observation(endpoint_id, ip, port, State.CLOSED, None, self.at))
                elif port in self.scanned:
                    out.append(Observation(endpoint_id, ip, port, State.FILTERED, None, self.at))
        return out

    def to_json(self):
        return {
            "at": self.at,
            "scanned": to_ranges(self.scanned),
            "open": {ip: {str(p): b for p, b in ports.items()} for ip, ports in self.open.items()},
            "closed": {ip: to_ranges(ports) for ip, ports in self.closed.items()},
        }

    @classmethod
    def from_json(cls, raw):
        return cls(
            at=raw["at"],
            scanned=frozenset(from_ranges(raw["scanned"])),
            open={ip: {int(p): b for p, b in ports.items()} for ip, ports in raw["open"].items()},
            closed={ip: frozenset(from_ranges(r)) for ip, r in raw["closed"].items()},
        )


# --- expectations -------------------------------------------------------------------------------


@dataclass(frozen=True)
class Expectation:
    ports: frozenset[int]
    reason: str
    source: str  # 'expected["<key>"]' or "tag"


# --- verdicts and findings ----------------------------------------------------------------------


@dataclass(frozen=True)
class Finding:
    """One verdict on one subject of an endpoint: a port ("tcp/22") or the endpoint itself
    ("auth", "api", "http", "expectation")."""

    subject: str
    verdict: Verdict
    severity: Severity
    detail: str = ""
    paths: tuple[Path, ...] = ()
    banner: str | None = None
    status: int | None = None

    def to_json(self):
        out = {"verdict": self.verdict.value, "severity": self.severity.label, "detail": self.detail}
        if self.banner:
            out["banner"] = self.banner
        if self.status is not None:
            out["status"] = self.status
        return out

    @classmethod
    def from_json(cls, subject, raw):
        return cls(subject, Verdict(raw["verdict"]), Severity.parse(raw["severity"]), raw.get("detail", ""), (), raw.get("banner"), raw.get("status"))


def tcp(port):
    return f"tcp/{port}"


# --- stored state -------------------------------------------------------------------------------


@dataclass(frozen=True)
class EndpointState:
    """One endpoint as the table keeps it: the endpoint, whether anything declares it, the
    verdicts, and the last scan and HTTP probe they were judged from."""

    endpoint: Endpoint
    declared: bool
    findings: dict  # subject -> Finding
    scan: "ScanRecord | None" = None
    http: HttpObservation | None = None
    version: int = 0

    def to_json(self):
        return {
            "endpoint": self.endpoint.to_json(),
            "declared": self.declared,
            "findings": {s: f.to_json() for s, f in self.findings.items()},
            "scan": self.scan.to_json() if self.scan else None,
            "http": {"url": self.http.url, "status": self.http.status, "server": self.http.server, "error": self.http.error, "at": self.http.at} if self.http else None,
        }

    @classmethod
    def from_json(cls, raw, version=0):
        endpoint = Endpoint.from_json(raw["endpoint"])
        http = raw.get("http")
        return cls(
            endpoint=endpoint,
            declared=raw["declared"],
            findings={s: Finding.from_json(s, f) for s, f in raw["findings"].items()},
            scan=ScanRecord.from_json(raw["scan"]) if raw.get("scan") else None,
            http=HttpObservation(endpoint.id, http["url"], http["status"], http.get("server"), http.get("error"), http.get("at", 0)) if http else None,
            version=version,
        )


# --- alerts -------------------------------------------------------------------------------------


class AlertKind(Enum):
    FINDING = "finding"  # a new or changed verdict
    RESOLVED = "resolved"
    NEW_ENDPOINT = "new-endpoint"
    REMOVED_ENDPOINT = "removed-endpoint"
    GROUP = "group"  # more than a handful for one account in one run
    SUMMARY = "summary"  # baseline mode's one message per run
    TRIPWIRE = "tripwire"


@dataclass(frozen=True)
class Alert:
    kind: AlertKind
    severity: Severity
    account: str
    title: str
    description: str
    endpoint_id: str | None = None
    context: dict = field(default_factory=dict, hash=False)

    def chatbot(self):
        """An Amazon Q Developer custom notification."""
        return {
            "version": "1.0",
            "source": "custom",
            "content": {"textType": "client-markdown", "title": self.title[:250], "description": self.description[:8000]},
            "metadata": {
                "enableCustomActions": False,  # no buttons in v1; also hides Amazon Q's "manage actions" menu
                "eventType": f"perimeter-{self.kind.value}",
                "additionalContext": {
                    "kind": self.kind.value,
                    "severity": self.severity.label,
                    "account": self.account,
                    **({"endpoint": self.endpoint_id} if self.endpoint_id else {}),
                    **self.context,
                },
            },
        }

    def text(self):
        return f"{_plain(self.title)}\n\n{_plain(self.description)}"

    def sns(self, slack):
        """(subject, message) for SNS: Amazon Q gets the JSON, email subscribers plain text."""
        default = json.dumps(self.chatbot()) if slack else self.text()
        return _plain(self.title)[:100], json.dumps({"default": default, "email": self.text()})


def _plain(text):
    return re.sub(r":[a-z_]+: ", "", text).replace("`", "").replace("*", "")


# --- configuration ------------------------------------------------------------------------------

ACCOUNT_ID = re.compile(r"^\d{12}$")


@dataclass(frozen=True)
class ScanSettings:
    profile: str = "top1000"
    extra_ports: tuple[int, ...] = ()
    rate: int = 100
    concurrency: int = 256
    timeout: float = 1.0


@dataclass(frozen=True)
class Config:
    mode: str  # baseline | enforce
    undeclared: str  # alert | report
    min_severity: Severity
    alert_on_closed: bool
    expected: tuple[tuple[str, Expectation], ...]  # in key order
    tag_prefix: str
    accounts: dict  # name -> account id; includes the module's own account
    self_account: str  # the name of the module's own account
    regions: tuple[str, ...]
    member_role_name: str
    external_id: str | None
    scan: ScanSettings
    bucket: str
    sns_topic_arn: str | None
    slack: bool
    state_machine_arn: str | None

    @classmethod
    def parse(cls, raw):
        accounts = dict(raw["accounts"])
        for name, account_id in accounts.items():
            if not ACCOUNT_ID.match(account_id):
                raise ValueError(f"account {name}: {account_id!r} isn't a 12-digit account id")
        scan = raw.get("scan") or {}
        return cls(
            mode=raw.get("mode", "baseline"),
            undeclared=raw.get("undeclared", "alert"),
            min_severity=Severity.parse(raw.get("min_severity", "low")),
            alert_on_closed=bool(raw.get("alert_on_closed")),
            expected=tuple(
                (key, Expectation(frozenset(int(p) for p in value["ports"]), value.get("reason", ""), f'expected["{key}"]'))
                for key, value in raw.get("expected") or ()
            ),
            tag_prefix=raw.get("tag_prefix", "perimeter"),
            accounts=accounts,
            self_account=raw["self_account"],
            regions=tuple(raw["regions"]),
            member_role_name=raw["member_role_name"],
            external_id=raw.get("external_id"),
            scan=ScanSettings(
                profile=scan.get("profile", "top1000"),
                extra_ports=tuple(int(p) for p in scan.get("extra_ports") or ()),
                rate=int(scan.get("rate", 100)),
                concurrency=int(scan.get("concurrency", 256)),
                timeout=float(scan.get("timeout", 1.0)),
            ),
            bucket=raw.get("bucket", ""),
            sns_topic_arn=raw.get("sns_topic_arn"),
            slack=bool(raw.get("slack")),
            state_machine_arn=raw.get("state_machine_arn"),
        )
