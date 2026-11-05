"""What a run scans, and how the scan is cut into batches. Pure: the planner in app.py lists the
endpoints and calls these; the verify step re-checks each batch's ownership right before it
scans and gives it EXPIRES_AFTER seconds."""

import math
from dataclasses import dataclass

import ports as profiles
from classify import CRITICAL_PORTS, expectation_for
from model import Http, Tcp
from scanner import BANNER_TIMEOUT, CLOSE_TIMEOUT, port_set

EXPIRES_AFTER = 600
# A batch's worst case must fit its window: the HTTP probes first (a few rounds of threads, each
# probe a few socket timeouts), then the TCP scan, with the rest left for invocation latency.
MAX_HTTP = 10
TCP_SECONDS = 480
MAX_BATCH = 20
# Path ranges this narrow are scanned even outside the profile, so their verdicts aren't blind.
SMALL_RANGE = 32


@dataclass(frozen=True)
class Request:
    """What started the run."""

    mode: str  # full | inventory | endpoints | touch
    endpoints: tuple[str, ...] = ()
    account: str | None = None  # touch: the account name
    region: str | None = None
    resources: tuple[str, ...] = ()
    include_global: bool = False

    @classmethod
    def parse(cls, raw, accounts):
        """The execution input, checked against the configured account names: a manual run's
        typo fails the run with the reason instead of scanning nothing."""
        raw = raw or {}
        if not isinstance(raw, dict):
            raise ValueError("the run input is a JSON object, e.g. {\"full\": true}")
        if "touch" in raw:
            t = raw["touch"]
            if not isinstance(t, dict) or not t.get("account") or not t.get("region"):
                raise ValueError('touch needs account and region: {"touch": {"account": "<name>", "region": "<region>", "resources": ["sg-…"]}}')
            _known(accounts, t["account"], "touch.account")
            resources = t.get("resources") or []
            if not isinstance(resources, list) or not all(isinstance(r, str) for r in resources):
                raise ValueError("touch.resources is a list of resource ids")
            return cls("touch", (), t["account"], t["region"], tuple(resources), bool(t.get("global")))
        if "endpoints" in raw:
            ids = raw["endpoints"]
            if not isinstance(ids, list) or not ids or not all(isinstance(e, str) for e in ids):
                raise ValueError('endpoints is a non-empty list of endpoint ids, e.g. {"endpoints": ["self/alb/api"]}')
            for e in ids:
                _known(accounts, e.split("/", 1)[0], f"endpoint {e}:")
            return cls("endpoints", tuple(ids))
        if raw.get("mode") not in (None, "full", "inventory"):
            raise ValueError('mode is "full" or "inventory"')
        if raw.get("full") or raw.get("mode") == "full":
            return cls("full")
        return cls("inventory")


def _known(accounts, name, what):
    if name not in accounts:
        raise ValueError(f"{what} {name!r} isn't a configured account ({', '.join(sorted(accounts))})")


def scopes(request, cfg, previous):
    """The (account, region) scopes to list; "global" is CloudFront and S3 websites."""
    every = [(a, r) for a in cfg.accounts for r in cfg.regions] + [(a, "global") for a in cfg.accounts]
    if request.mode in ("full", "inventory"):
        return every
    if request.mode == "touch":
        regional = [(request.account, request.region)] if request.region in cfg.regions else []
        return regional + ([(request.account, "global")] if request.include_global else [])
    unknown = [e for e in request.endpoints if e not in previous]
    if unknown:
        raise ValueError(f"{', '.join(unknown)} isn't in the last inventory: see inventory/latest.json for ids, or run an inventory first")
    wanted = {previous[e].endpoint.scope for e in request.endpoints}
    return [s for s in every if s in wanted]


def _related(endpoint, resources):
    names = set(endpoint.id.split("/")[-1].split("@")) | set(endpoint.security_groups) | set(endpoint.network) | {endpoint.arn, endpoint.display}
    return any(r and (r in names or (endpoint.arn and endpoint.arn.endswith(f"/{r}"))) for r in resources)


def _changed(endpoint, before):
    return before is None or before.endpoint.paths != endpoint.paths or before.endpoint.addresses != endpoint.addresses or before.endpoint.probe != endpoint.probe


def targets(request, endpoints, previous):
    """Ids of the endpoints to probe this run: everything on a full run; what is new or whose
    exposure changed on an hourly run; the named ones on a manual run; what a tripwire touched,
    plus anything new in its scope."""
    probed = [e for e in endpoints if e.probe is not None]
    if request.mode == "full":
        return [e.id for e in probed]
    if request.mode == "endpoints":
        wanted = set(request.endpoints)
        return [e.id for e in probed if e.id in wanted]
    if request.mode == "touch":
        return [e.id for e in probed if _related(e, request.resources) or e.id not in previous]
    return [e.id for e in probed if _changed(e, previous.get(e.id))]


def _also(endpoint, cfg):
    exp, _ = expectation_for(endpoint, cfg.expected, cfg.tag_prefix)
    extra = set(exp.ports) if exp else set()
    for p in endpoint.paths:
        if p.ports[1] - p.ports[0] < SMALL_RANGE:
            extra |= set(range(max(1, p.ports[0]), p.ports[1] + 1))
    return sorted(extra - set(profiles.profile(cfg.scan.profile)) - set(cfg.scan.extra_ports) - CRITICAL_PORTS)[:256]


def _hold(scan):
    """Longest an attempt holds a connection slot: the connect, the banner read, the close."""
    return scan.timeout + BANNER_TIMEOUT + CLOSE_TIMEOUT


def _tcp_seconds(port_counts, scan):
    """A TCP batch's worst case: the rate paces each address, the concurrency the whole batch,
    and every attempt holds its slot as long as it can."""
    return max(max(port_counts) / scan.rate, sum(port_counts) * _hold(scan) / scan.concurrency) + _hold(scan)


def _chunks(ports, scan):
    """The ports as contiguous [lo, hi] ranges, each small enough to scan alone within TCP_SECONDS."""
    per_port = max(1 / scan.rate, _hold(scan) / scan.concurrency)
    most = max(1, int((TCP_SECONDS - _hold(scan)) / per_port))
    size = math.ceil(len(ports) / math.ceil(len(ports) / most))
    return [ports[i : i + size] for i in range(0, len(ports), size)]


def batches(endpoints, cfg):
    """Scanner batches for the given endpoints, without a window: the verify step stamps it. An
    address whose ports can't be scanned within the window is split across batches by port
    range ("all", or a low rate); batches are filled while their worst case still fits. HTTP
    probes are spread over the batches, at most MAX_HTTP each."""
    tcp, http = [], []
    for e in endpoints:
        if isinstance(e.probe, Tcp):
            also = _also(e, cfg)
            for a in e.probe.addresses:
                target = {"endpoint_id": e.id, "ip": a.ip, "proof": a.proof}
                if e.probe.ports:
                    target["only"] = list(e.probe.ports)
                elif also:
                    target["also"] = also
                chunks = _chunks(port_set(cfg.scan.profile, cfg.scan.extra_ports, also, e.probe.ports), cfg.scan)
                for c in chunks:
                    tcp.append(({**target, "range": [c[0], c[-1]]} if len(chunks) > 1 else target, len(c)))
        elif isinstance(e.probe, Http):
            http.append({"endpoint_id": e.id, "url": e.probe.url, "host": e.probe.host})
    groups, counts = [], []
    for target, n in tcp:
        if not groups or len(groups[-1]) >= MAX_BATCH or _tcp_seconds(counts[-1] + [n], cfg.scan) > TCP_SECONDS:
            groups.append([])
            counts.append([])
        groups[-1].append(target)
        counts[-1].append(n)
    groups += [[] for _ in range(math.ceil(len(http) / MAX_HTTP) - len(groups))]
    common = {
        "profile": cfg.scan.profile,
        "extra": list(cfg.scan.extra_ports),
        "rate": cfg.scan.rate,
        "concurrency": cfg.scan.concurrency,
        "timeout": cfg.scan.timeout,
    }
    out = [{**common, "targets": g, "http": []} for g in groups]
    for i, h in enumerate(http):
        out[i % len(out)]["http"].append(h)
    return out
