"""Verdicts: what the scanner saw, against what the paths explain and what was expected. Pure."""

import ipaddress
import re
from fnmatch import fnmatchcase

from model import EndpointState, Expectation, Finding, Flag, HttpObservation, Observation, ScanRecord, Severity, State, Verdict, tcp

# Ports where an unexpected listener is critical: remote shells and desktops, Docker's API,
# and databases and caches that are routinely left without authentication.
CRITICAL_PORTS = frozenset({22, 23, 3389, 5900, 2375, 2376, 3306, 5432, 1433, 6379, 9200, 11211, 27017})

PORT_LIST = re.compile(r"^\s*(\d{1,5}\s*(,\s*\d{1,5}\s*)*)?$")


# --- expectations -------------------------------------------------------------------------------


def _tag_expectation(endpoint, tag_prefix):
    """(Expectation or None, problem or None) from the endpoint's own tags."""
    raw = endpoint.tags.get(f"{tag_prefix}:expected")
    if raw is None:
        return None, None
    ports = [int(p) for p in raw.split(",") if p.strip()] if PORT_LIST.match(raw) else None
    if ports is None or not all(1 <= p <= 65535 for p in ports):
        return None, f"tag {tag_prefix}:expected={raw!r} isn't a comma-separated port list; ignored"
    return Expectation(frozenset(ports), endpoint.tags.get(f"{tag_prefix}:reason", ""), "tag"), None


def _variable_expectation(endpoint, expected):
    for key, exp in expected:
        if fnmatchcase(endpoint.id, key):
            return exp
    groups = [f"{endpoint.account}/sg/{sg}" for sg in endpoint.security_groups]
    for key, exp in expected:
        if any(fnmatchcase(g, key) for g in groups):
            return exp
    return None


def expectation_for(endpoint, expected, tag_prefix):
    """(Expectation or None, problem or None). expected: (glob key, Expectation) in key order.
    A key matching the endpoint id wins over one matching its security groups; a variable key
    wins over the endpoint's tags, and a disagreement between them is a problem."""
    variable = _variable_expectation(endpoint, expected)
    tagged, problem = _tag_expectation(endpoint, tag_prefix)
    if variable and tagged and variable.ports != tagged.ports:
        problem = (
            f"{variable.source} says ports {_ports(variable.ports)} but tag {tag_prefix}:expected says "
            f"{_ports(tagged.ports)}; the variable wins"
        )
    return variable or tagged, problem


def _ports(ports):
    return ",".join(str(p) for p in sorted(ports)) or "none"


# --- verdicts -----------------------------------------------------------------------------------

_STATE_RANK = {State.OPEN: 2, State.CLOSED: 1, State.FILTERED: 0}


def _port_states(observations):
    """{port: (state, banner)}: an endpoint's port is open if any of its addresses answered."""
    out = {}
    for o in observations:
        if o.port not in out or _STATE_RANK[o.state] > _STATE_RANK[out[o.port][0]]:
            out[o.port] = (o.state, o.banner)
        elif o.state is State.OPEN and not out[o.port][1] and o.banner:
            out[o.port] = (o.state, o.banner)
    return out


# A source range narrower than this is an allowlist (a partner's addresses, an office), not "the
# internet": the scanner, coming from AWS's addresses, can't be expected to reach it.
ALLOWLIST_PREFIX = {4: 16, 6: 48}


def _source(path):
    return path.cidr.rsplit(": ", 1)[-1]


def _allowlisted(paths):
    """True when every path admits only specific public sources."""
    if not paths:
        return False
    for p in paths:
        try:
            net = ipaddress.ip_network(_source(p), strict=False)
        except ValueError:
            return False
        if net.prefixlen <= ALLOWLIST_PREFIX[net.version]:
            return False
    return True


def _port_finding(endpoint, port, state, banner, expectation, alert_on_closed):
    paths = tuple(endpoint.paths_for(port))
    expected = expectation is not None and port in expectation.ports
    subject = tcp(port)
    if state is State.OPEN:
        if expected:
            return Finding(subject, Verdict.EXPECTED_OPEN, Severity.NONE, f"open, expected: {expectation.reason}".rstrip(": "), paths, banner)
        severity = Severity.CRITICAL if port in CRITICAL_PORTS else Severity.HIGH
        if paths:
            return Finding(subject, Verdict.UNEXPECTED_OPEN, severity, "open, not expected", paths, banner)
        return Finding(
            subject,
            Verdict.UNEXPLAINED_OPEN,
            severity,
            "open, but the analysis found no path: check prefix lists and load balancers, or report a module bug",
            paths,
            banner,
        )
    sources = ", ".join(dict.fromkeys(_source(p) for p in paths))
    allowlisted = state is not State.CLOSED and _allowlisted(paths)
    if expected:
        if allowlisted:
            return Finding(subject, Verdict.EXPECTED_OPEN, Severity.NONE, f"reachable only from {sources}, so not confirmed from outside; expected: {expectation.reason}".rstrip(": "), paths)
        severity = Severity.MEDIUM if alert_on_closed else Severity.INFO
        return Finding(subject, Verdict.EXPECTED_CLOSED, severity, f"expected open, but {state.value}", paths)
    if not paths:
        return None
    if allowlisted:
        return Finding(subject, Verdict.ALLOWLISTED, Severity.LOW, f"reachable only from {sources}", paths)
    if state is State.CLOSED:
        return Finding(subject, Verdict.LATENT_CONFIRMED, Severity.LOW, "reachable, nothing listening", paths)
    return Finding(subject, Verdict.LATENT_FILTERED, Severity.INFO, "a path is configured but something drops the probe (a host firewall?)", paths)


def _http_finding(obs):
    if obs.status is None:
        return Finding("http", Verdict.HTTP_UNREACHABLE, Severity.NONE, obs.error or "no answer", status=None)
    verdict = Verdict.HTTP_OPEN if obs.status < 400 else Verdict.HTTP_DENIED
    server = f" ({obs.server})" if obs.server else ""
    return Finding("http", verdict, Severity.NONE, f"HTTP {obs.status}{server}", status=obs.status)


def classify(endpoint, observations, expectation, alert_on_closed=False, problem=None):
    """{subject: Finding} for one endpoint. observations: its Observation and HttpObservation
    values. Ports without an observation are left alone: a port that wasn't scanned has no
    verdict."""
    findings = {}
    tcp_obs = [o for o in observations if isinstance(o, Observation)]
    for port, (state, banner) in sorted(_port_states(tcp_obs).items()):
        f = _port_finding(endpoint, port, state, banner, expectation, alert_on_closed)
        if f:
            findings[f.subject] = f

    http_obs = [o for o in observations if isinstance(o, HttpObservation)]
    if http_obs:
        findings["http"] = _http_finding(max(http_obs, key=lambda o: o.at))

    declared = expectation is not None
    if Flag.UNAUTHENTICATED_URL in endpoint.flags:
        findings["auth"] = (
            Finding("auth", Verdict.EXPECTED_PUBLIC, Severity.NONE, f"no authentication, expected: {expectation.reason}".rstrip(": "))
            if declared
            else Finding("auth", Verdict.UNAUTHENTICATED_URL, Severity.HIGH, "function URL with AuthType NONE and a policy that lets anyone invoke it")
        )
    if Flag.PUBLIC_API in endpoint.flags:
        findings["api"] = (
            Finding("api", Verdict.EXPECTED_PUBLIC, Severity.NONE, f"public API endpoint, expected: {expectation.reason}".rstrip(": "))
            if declared
            else Finding("api", Verdict.PUBLIC_API, Severity.HIGH, "Kubernetes API endpoint open to internet CIDRs")
        )
    if problem:
        findings["expectation"] = Finding("expectation", Verdict.EXPECTATION_CONFLICT, Severity.INFO, problem)
    return findings


def assess(endpoint, before, scan, http, cfg):
    """The endpoint's current state: its verdicts from this run's scan and probe, or the last
    ones when this run didn't probe it, judged against today's paths and expectations."""
    if scan is None and before is not None:
        scan = before.scan
    if http is None and before is not None:
        http = before.http
    held = {a.ip for a in endpoint.addresses}
    if scan is not None:
        # Observations of an address the endpoint no longer holds say nothing about it.
        scan = ScanRecord(scan.at, scan.scanned, {ip: v for ip, v in scan.open.items() if ip in held}, {ip: v for ip, v in scan.closed.items() if ip in held})
        if not scan.open:
            scan = None
    expectation, problem = expectation_for(endpoint, cfg.expected, cfg.tag_prefix)
    observations = []
    if scan is not None:
        interest = set(expectation.ports) if expectation else set()
        interest |= {p for p in scan.scanned if any(path.covers(p) for path in endpoint.paths)}
        observations = scan.observations(endpoint.id, interest)
    if http is not None:
        observations.append(http)
    findings = classify(endpoint, observations, expectation, cfg.alert_on_closed, problem)
    return EndpointState(endpoint, expectation is not None, findings, scan, http), expectation
