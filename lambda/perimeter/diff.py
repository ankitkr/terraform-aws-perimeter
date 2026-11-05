"""What changed since the last run, as alerts; the baseline summary and suggested `expected`
block. Pure: the judge in app.py loads the states, calls these, and sends the alerts."""

import re

from model import Alert, AlertKind, Kind, Severity, Verdict

GROUP_ABOVE = 5

ICONS = {
    Severity.CRITICAL: ":rotating_light:",
    Severity.HIGH: ":red_circle:",
    Severity.MEDIUM: ":large_orange_circle:",
    Severity.LOW: ":large_yellow_circle:",
    Severity.INFO: ":information_source:",
    Severity.NONE: ":information_source:",
}

HTTP_FRONTS = frozenset({Kind.CLOUDFRONT, Kind.APIGW_REST, Kind.APIGW_HTTP, Kind.APIGW_WS, Kind.LAMBDA_URL, Kind.S3_WEBSITE, Kind.EKS, Kind.OPENSEARCH})


def persisted(findings, min_severity):
    """The findings worth storing: port verdicts at or above min_severity (a port below it can
    never alert, and an endpoint scanned with every port open to the world has thousands of
    them), and every endpoint-level verdict (the HTTP status change rule needs the last one)."""
    return {s: f for s, f in findings.items() if not s.startswith("tcp/") or f.severity >= min_severity}


# --- rendering ----------------------------------------------------------------------------------


def _name(endpoint):
    return f"*{endpoint.id}*" + (f" ({endpoint.display})" if endpoint.display and endpoint.display not in endpoint.id else "")


def _why(finding):
    if not finding.paths:
        return ""
    path = finding.paths[0]
    more = f" (+{len(finding.paths) - 1} more)" if len(finding.paths) > 1 else ""
    flags = "".join(f" [{t}]" for t, on in (("unverified", not path.verified), ("partial", path.partial)) if on)
    return f" Why: {'; '.join(path.refs)}{flags}{more}."


def _banner(finding):
    return f" Banner: `{finding.banner}`." if finding.banner else ""


def _line(endpoint, finding):
    if finding.subject.startswith("tcp/"):
        state = {
            Verdict.UNEXPECTED_OPEN: "*open*, not expected",
            Verdict.UNEXPLAINED_OPEN: "*open*, and no path explains it",
            Verdict.EXPECTED_OPEN: "open, as expected",
            Verdict.LATENT_CONFIRMED: "reachable, nothing listening (latent)",
            Verdict.LATENT_FILTERED: "configured open, but the probe was dropped",
            Verdict.ALLOWLISTED: f"reachable only from specific sources ({finding.detail.removeprefix('reachable only from ')})",
            Verdict.EXPECTED_CLOSED: "expected open, but it isn't answering",
        }[finding.verdict]
        return f"{finding.subject} {state}.{_why(finding)}{_banner(finding)}"
    return f"{finding.detail}."


def _finding_alert(endpoint, finding, before):
    was = f" (was {before.verdict.value})" if before else ""
    return Alert(
        AlertKind.FINDING,
        finding.severity,
        endpoint.account,
        f"{ICONS[finding.severity]} {endpoint.display or endpoint.id}: {finding.subject} {finding.verdict.value}",
        f"{_name(endpoint)}: {_line(endpoint, finding)}{was}",
        endpoint.id,
        {"subject": finding.subject, "verdict": finding.verdict.value, "region": endpoint.region},
    )


def _resolved_alert(endpoint, before, after):
    now = f"now {after.verdict.value}" if after else "no longer seen"
    return Alert(
        AlertKind.RESOLVED,
        before.severity,
        endpoint.account,
        f":white_check_mark: {endpoint.id}: {before.subject} resolved",
        f"{_name(endpoint)}: {before.subject} was {before.verdict.value}, {now}.",
        endpoint.id,
        {"subject": before.subject, "verdict": after.verdict.value if after else "none", "region": endpoint.region},
    )


def _http_opened(endpoint, before, after):
    if not (before and after and before.status and after.status):
        return None
    if 400 <= before.status < 500 and 200 <= after.status < 300:
        return Alert(
            AlertKind.FINDING,
            Severity.HIGH,
            endpoint.account,
            f"{ICONS[Severity.HIGH]} {endpoint.id}: now answers HTTP {after.status}",
            f"{_name(endpoint)} answered HTTP {before.status} last time and *{after.status}* now: it may have lost its authentication.",
            endpoint.id,
            {"subject": "http", "verdict": after.verdict.value, "region": endpoint.region},
        )
    return None


# --- the diff -----------------------------------------------------------------------------------


def _alertable(subject, state, cfg):
    """In report mode an undeclared endpoint is noticed, but its ports don't alert one by one."""
    return state.declared or cfg.undeclared == "alert" or not subject.startswith("tcp/")


def new_endpoint_alert(state, cfg):
    ep = state.endpoint
    lines = [_line(ep, f) for f in state.findings.values() if f.severity >= cfg.min_severity]
    severity = max([Severity.INFO] + [f.severity for s, f in state.findings.items() if f.severity >= cfg.min_severity and _alertable(s, state, cfg)])
    where = ", ".join(a.ip for a in ep.addresses) or (ep.probe.url if ep.probe and hasattr(ep.probe, "url") else "")
    declared = "declared" if state.declared else "not declared in `expected`"
    body = f"New {ep.kind.value} {_name(ep)} in {ep.account}/{ep.region}{f' at {where}' if where else ''}, {declared}."
    if lines:
        body += "\n" + "\n".join(f"• {line}" for line in lines)
    return Alert(AlertKind.NEW_ENDPOINT, severity, ep.account, f"{ICONS[severity]} New endpoint {ep.id}", body, ep.id, {"region": ep.region})


def removed_alert(state):
    ep = state.endpoint
    return Alert(
        AlertKind.REMOVED_ENDPOINT,
        Severity.INFO,
        ep.account,
        f":wastebasket: {ep.id} is gone",
        f"{_name(ep)} ({ep.kind.value}, {ep.account}/{ep.region}) wasn't found in this run's inventory.",
        ep.id,
        {"region": ep.region},
    )


def diff_endpoint(before, after, cfg):
    """Alerts for one endpoint: before and after are EndpointState (before None when new).
    Unchanged verdicts never alert again."""
    if before is None:
        return [new_endpoint_alert(after, cfg)]
    ep, alerts, floor = after.endpoint, [], cfg.min_severity
    for subject in sorted(set(before.findings) | set(after.findings)):
        old, new = before.findings.get(subject), after.findings.get(subject)
        if subject == "http":
            opened = _http_opened(ep, old, new)
            if opened:
                alerts.append(opened)
            continue
        if not _alertable(subject, after, cfg):
            continue
        if new and (old is None or old.verdict is not new.verdict) and new.severity >= floor:
            alerts.append(_finding_alert(ep, new, old))
        elif old and old.severity >= floor and (new is None or new.severity < floor):
            alerts.append(_resolved_alert(ep, old, new))
    return alerts


def group(alerts):
    """More than GROUP_ABOVE alerts for one account become one message."""
    by_account = {}
    for a in alerts:
        by_account.setdefault(a.account, []).append(a)
    out = []
    for account, items in by_account.items():
        if len(items) <= GROUP_ABOVE:
            out += items
            continue
        items = sorted(items, key=lambda a: (-a.severity, a.title))
        severity = items[0].severity
        counts = {}
        for a in items:
            counts[a.kind.value] = counts.get(a.kind.value, 0) + 1
        summary = ", ".join(f"{n} {k}" for k, n in sorted(counts.items()))
        body = "\n".join(f"• {a.title}" for a in items[:40])
        if len(items) > 40:
            body += f"\n…and {len(items) - 40} more; see the inventory document."
        out.append(Alert(AlertKind.GROUP, severity, account, f"{ICONS[severity]} {len(items)} perimeter changes in {account}", f"{summary}.\n{body}", None, {"count": str(len(items))}))
    return out


def diff(previous, current, cfg, inventoried):
    """All alerts for a run. previous and current map endpoint id -> EndpointState; inventoried
    holds the (account, region) scopes this run listed completely, so an endpoint missing from a
    scope that failed or wasn't listed isn't reported as removed."""
    if cfg.mode == "baseline":
        return []
    alerts = []
    for eid in sorted(current):
        alerts += diff_endpoint(previous.get(eid), current[eid], cfg)
    for eid in sorted(previous):
        if eid not in current and previous[eid].endpoint.scope in inventoried:
            alerts.append(removed_alert(previous[eid]))
    return group(alerts)


# --- baseline -----------------------------------------------------------------------------------


def _hcl_string(text):
    escaped = text.replace("\\", "\\\\").replace('"', '\\"').replace("${", "$${").replace("%{", "%%{")
    return f'"{escaped}"'


def _comment(text):
    return re.sub(r"[^\x20-\x7e]", "?", text)[:120]


def _suggestion(state):
    """(ports, banners) worth declaring for one endpoint: what answered, or the scheme port of a
    front that answered over HTTP."""
    ep = state.endpoint
    open_ports = {int(s[4:]): f.banner for s, f in state.findings.items() if s.startswith("tcp/") and f.verdict in (Verdict.EXPECTED_OPEN, Verdict.UNEXPECTED_OPEN, Verdict.UNEXPLAINED_OPEN)}
    if ep.kind in HTTP_FRONTS and (state.http and state.http.status is not None or "auth" in state.findings or "api" in state.findings):
        url = ep.probe.url if ep.probe and hasattr(ep.probe, "url") else "https://"
        open_ports.setdefault(80 if url.startswith("http://") else 443, None)
    return open_ports


def suggested_expected(states, expected, generated_at):
    """An `expected` block declaring what answered in the last scan, banners as comments.
    states: EndpointState values; expected: the current (key, Expectation) pairs, whose reasons
    are kept for endpoints they already cover."""
    reasons = {}
    for key, exp in expected:
        reasons.setdefault(key, exp.reason)
    lines = [
        f"# Generated by terraform-aws-perimeter at {generated_at} from the last scan: every",
        "# endpoint that answered, with the ports that were open. Review each entry, say why it's",
        "# open, and paste the block into the module's `expected`, then set mode = \"enforce\".",
        "expected = {",
    ]
    width = 0
    entries = []
    for state in sorted(states, key=lambda s: s.endpoint.id):
        ports = _suggestion(state)
        if not ports:
            continue
        ep = state.endpoint
        reason = reasons.get(ep.id) or f"TODO: why is {ep.display or ep.id} open?"
        entries.append((ep, ports, reason))
        width = max(width, len(_hcl_string(ep.id)))
    for ep, ports, reason in entries:
        for port, banner in sorted(ports.items()):
            if banner:
                lines.append(f"  # tcp/{port}: {_comment(banner)}")
        port_list = ", ".join(str(p) for p in sorted(ports))
        lines.append(f"  {_hcl_string(ep.id).ljust(width)} = {{ ports = [{port_list}], reason = {_hcl_string(reason)} }}")
    lines.append("}")
    return "\n".join(lines) + "\n"


def baseline_summary(states, cfg, location):
    """Baseline mode's one message per full run."""
    states = list(states)
    accounts = {s.endpoint.account for s in states}
    findings = [(s.endpoint, f) for s in states for f in s.findings.values()]
    open_ports = sum(1 for _, f in findings if f.verdict in (Verdict.EXPECTED_OPEN, Verdict.UNEXPECTED_OPEN, Verdict.UNEXPLAINED_OPEN))
    would = sorted(
        ((ep, f) for ep, f in findings if f.severity >= cfg.min_severity and f.severity >= Severity.HIGH),
        key=lambda x: (-x[1].severity, x[0].id, x[1].subject),
    )
    critical = sum(1 for _, f in would if f.severity is Severity.CRITICAL)
    body = (
        f"{len(states)} endpoints in {len(accounts)} account{'s' if len(accounts) != 1 else ''}, {open_ports} open port{'s' if open_ports != 1 else ''}. "
        f"In enforce mode {len(would)} would alert ({critical} critical).\n"
        f"Suggested `expected` block: {location}"
    )
    if would:
        body += "\n" + "\n".join(f"• {ep.id}: {_line(ep, f)}" for ep, f in would[:15])
    return Alert(AlertKind.SUMMARY, Severity.INFO, "all", ":clipboard: Perimeter baseline", body, None, {"endpoints": str(len(states)), "wouldAlert": str(len(would))})



# --- the inventory document ---------------------------------------------------------------------


def _path_json(p):
    return {"ports": f"{p.ports[0]}-{p.ports[1]}" if p.ports[0] != p.ports[1] else str(p.ports[0]), "cidr": p.cidr, "refs": list(p.refs), "verified": p.verified, "partial": p.partial}


def document_entry(state, expectation):
    """One endpoint in inventory/latest.json: addresses, ports and verdicts, why reachable,
    and what was expected."""
    ep = state.endpoint
    ports, other = {}, {}
    for subject, f in sorted(state.findings.items(), key=lambda kv: (not kv[0].startswith("tcp/"), int(kv[0][4:]) if kv[0].startswith("tcp/") else 0, kv[0])):
        item = {"verdict": f.verdict.value, "severity": f.severity.label, "detail": f.detail}
        if f.banner:
            item["banner"] = f.banner
        if f.status is not None:
            item["status"] = f.status
        if subject.startswith("tcp/"):
            item["paths"] = [_path_json(p) for p in f.paths]
            ports[subject[4:]] = item
        else:
            other[subject] = item
    entry = {
        "id": ep.id,
        "display": ep.display,
        "kind": ep.kind.value,
        "account": ep.account,
        "region": ep.region,
        "arn": ep.arn,
        "addresses": [{"ip": a.ip, "proof": a.proof} for a in ep.addresses],
        "url": ep.probe.url if ep.probe is not None and hasattr(ep.probe, "url") else None,
        "security_groups": list(ep.security_groups),
        "declared": state.declared,
        "expectation": {"ports": sorted(expectation.ports), "reason": expectation.reason, "source": expectation.source} if expectation else None,
        "ports": ports,
        "findings": other,
        "paths": [_path_json(p) for p in ep.paths],
        "notes": list(ep.notes),
        "last_scan": state.scan.at if state.scan else None,
        "open_ports": sorted({p for ports_ in (state.scan.open.values() if state.scan else ()) for p in ports_}),
    }
    if state.http:
        entry["http"] = {"status": state.http.status, "server": state.http.server, "error": state.http.error, "at": state.http.at}
    return entry


def document(entries, meta):
    """The whole inventory document: meta (generated_at, run, mode, accounts, regions,
    incomplete) and the endpoints sorted by id."""
    return {**meta, "endpoints": sorted(entries, key=lambda e: e["id"])}
