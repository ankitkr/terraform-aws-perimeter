"""diff(): what alerts, what doesn't, grouping, report mode and baseline rendering."""

from helpers import OPEN22, PATH22, config, eni_endpoint, finding, front, state

from diff import baseline_summary, diff, persisted, suggested_expected
from model import AlertKind, Expectation, HttpObservation, Kind, Severity, Verdict

CFG = config()
EP = eni_endpoint()
SCOPES = {("prod", "us-east-1"), ("prod", "global")}


def kinds(alerts):
    return [(a.kind, a.endpoint_id, a.context.get("subject")) for a in alerts]


def test_unchanged_verdicts_never_realert():
    s = state(EP, OPEN22)
    assert diff({EP.id: s}, {EP.id: s}, CFG, SCOPES) == []


def test_a_new_verdict_alerts_with_why_and_banner():
    before = state(EP)
    alerts = diff({EP.id: before}, {EP.id: state(EP, OPEN22)}, CFG, SCOPES)
    assert kinds(alerts) == [(AlertKind.FINDING, EP.id, "tcp/22")]
    a = alerts[0]
    assert a.severity is Severity.CRITICAL
    assert a.description == (
        "*prod/eni/i-0abc* (bastion): tcp/22 *open*, not expected. Why: sg-1 rule sgr-9 tcp/22 from 0.0.0.0/0; "
        "acl-2 #100 allow; acl-2 egress #100 allow 1024-65535; rtb-3 0.0.0.0/0 → igw-4. Banner: `SSH-2.0-OpenSSH_9.6`."
    )


def test_a_changed_verdict_names_the_old_one():
    latent = finding("tcp/22", Verdict.LATENT_CONFIRMED, Severity.LOW, paths=(PATH22,))
    alerts = diff({EP.id: state(EP, latent)}, {EP.id: state(EP, OPEN22)}, CFG, SCOPES)
    assert alerts[0].description.endswith("(was reachable, nothing listening)")


def test_below_min_severity_doesnt_alert_and_dropping_below_resolves():
    filtered = finding("tcp/22", Verdict.LATENT_FILTERED, Severity.INFO, paths=(PATH22,))
    assert diff({EP.id: state(EP)}, {EP.id: state(EP, filtered)}, CFG, SCOPES) == []
    expected = finding("tcp/22", Verdict.EXPECTED_OPEN, Severity.NONE)
    resolved = diff({EP.id: state(EP, OPEN22)}, {EP.id: state(EP, expected)}, CFG, SCOPES)
    assert kinds(resolved) == [(AlertKind.RESOLVED, EP.id, "tcp/22")]
    assert "was open, not expected; now open, as expected." in resolved[0].description
    gone = diff({EP.id: state(EP, OPEN22)}, {EP.id: state(EP)}, CFG, SCOPES)
    assert "no longer seen" in gone[0].description


def test_min_severity_is_respected():
    latent = finding("tcp/8080", Verdict.LATENT_CONFIRMED, Severity.LOW)
    assert len(diff({EP.id: state(EP)}, {EP.id: state(EP, latent)}, config(min_severity="high"), SCOPES)) == 0
    assert len(diff({EP.id: state(EP)}, {EP.id: state(EP, latent)}, config(min_severity="low"), SCOPES)) == 1


def test_new_endpoint_alerts_once_with_its_findings():
    alerts = diff({}, {EP.id: state(EP, OPEN22)}, CFG, SCOPES)
    assert kinds(alerts) == [(AlertKind.NEW_ENDPOINT, EP.id, None)]
    assert alerts[0].severity is Severity.CRITICAL
    assert "at 203.0.113.10, not declared in `expected`" in alerts[0].description
    assert "tcp/22 *open*, not expected" in alerts[0].description


def test_removed_endpoint_only_when_its_scope_was_listed():
    previous = {EP.id: state(EP, OPEN22)}
    assert kinds(diff(previous, {}, CFG, SCOPES)) == [(AlertKind.REMOVED_ENDPOINT, EP.id, None)]
    assert diff(previous, {}, CFG, {("prod", "ap-south-1")}) == []
    assert diff(previous, {}, CFG, set()) == []


def test_report_mode_notices_undeclared_endpoints_without_port_alerts():
    report = config(undeclared="report")
    assert diff({EP.id: state(EP)}, {EP.id: state(EP, OPEN22)}, report, SCOPES) == []
    new = diff({}, {EP.id: state(EP, OPEN22)}, report, SCOPES)
    assert kinds(new) == [(AlertKind.NEW_ENDPOINT, EP.id, None)] and new[0].severity is Severity.INFO
    declared = diff({EP.id: state(EP, declared=True)}, {EP.id: state(EP, OPEN22, declared=True)}, report, SCOPES)
    assert kinds(declared) == [(AlertKind.FINDING, EP.id, "tcp/22")]


def test_report_mode_still_alerts_endpoint_level_verdicts():
    url = front("prod/lambda-url/hook", Kind.LAMBDA_URL, "https://abc.lambda-url.us-east-1.on.aws/")
    auth = finding("auth", Verdict.UNAUTHENTICATED_URL, Severity.HIGH, detail="function URL with AuthType NONE")
    assert kinds(diff({url.id: state(url)}, {url.id: state(url, auth)}, config(undeclared="report"), SCOPES)) == [(AlertKind.FINDING, url.id, "auth")]


def test_http_4xx_to_2xx_alerts_and_the_reverse_doesnt():
    cf = front()
    denied = finding("http", Verdict.HTTP_DENIED, Severity.NONE, status=403)
    ok = finding("http", Verdict.HTTP_OPEN, Severity.NONE, status=200)
    opened = diff({cf.id: state(cf, denied)}, {cf.id: state(cf, ok)}, CFG, SCOPES)
    assert [(a.kind, a.severity) for a in opened] == [(AlertKind.FINDING, Severity.HIGH)]
    assert "answered HTTP 403 last time and *200* now" in opened[0].description
    assert diff({cf.id: state(cf, ok)}, {cf.id: state(cf, denied)}, CFG, SCOPES) == []
    assert diff({cf.id: state(cf, ok)}, {cf.id: state(cf, ok)}, CFG, SCOPES) == []
    server_error = finding("http", Verdict.HTTP_DENIED, Severity.NONE, status=503)
    assert diff({cf.id: state(cf, server_error)}, {cf.id: state(cf, ok)}, CFG, SCOPES) == []


def test_more_than_five_alerts_for_one_account_are_grouped():
    eps = [eni_endpoint(f"prod/eni/i-{n}", ip=f"203.0.113.{n}") for n in range(6)]
    other = eni_endpoint("staging/eni/i-9", ip="198.51.100.9")
    previous = {e.id: state(e) for e in eps + [other]}
    current = {e.id: state(e, OPEN22) for e in eps + [other]}
    alerts = diff(previous, current, CFG, SCOPES)
    assert sorted((a.kind.value, a.account) for a in alerts) == [("finding", "staging"), ("group", "prod")]
    grouped = next(a for a in alerts if a.kind is AlertKind.GROUP)
    assert grouped.severity is Severity.CRITICAL and grouped.description.count("•") == 6
    five = {e.id: state(e, OPEN22) for e in eps[:5]}
    assert all(a.kind is AlertKind.FINDING for a in diff({e: state(eni_endpoint(e)) for e in five}, five, CFG, SCOPES))


def test_baseline_mode_sends_no_diff_alerts():
    assert diff({}, {EP.id: state(EP, OPEN22)}, config(mode="baseline"), SCOPES) == []


def test_persisted_drops_port_verdicts_below_the_floor_only():
    filtered = finding("tcp/23", Verdict.LATENT_FILTERED, Severity.INFO)
    http = finding("http", Verdict.HTTP_DENIED, Severity.NONE, status=403)
    assert set(persisted({f.subject: f for f in (OPEN22, filtered, http)}, Severity.LOW)) == {"tcp/22", "http"}


# --- baseline -----------------------------------------------------------------------------------


def test_suggested_expected_renders_open_ports_with_banners_as_comments():
    web = eni_endpoint("prod/eni/i-web", "web", ip="203.0.113.20")
    https = finding("tcp/443", Verdict.EXPECTED_OPEN, Severity.NONE)
    latent = finding("tcp/8080", Verdict.LATENT_CONFIRMED, Severity.LOW)
    cf = front()
    states = [
        state(EP, OPEN22),
        state(web, https, latent, declared=True),
        state(cf, finding("http", Verdict.HTTP_OPEN, Severity.NONE, status=200), http=HttpObservation(cf.id, cf.probe.url, 200)),
        state(eni_endpoint("prod/eni/i-quiet", ip="203.0.113.30"), latent),
    ]
    expected = (("prod/eni/i-web", Expectation(frozenset({443}), "public site", "x")),)
    assert suggested_expected(states, expected, "2026-11-05T02:00:00Z") == (
        "# Generated by terraform-aws-perimeter at 2026-11-05T02:00:00Z from the last scan: every\n"
        "# endpoint that answered, with the ports that were open. Review each entry, say why it's\n"
        "# open, and paste the block into the module's `expected`, then set mode = \"enforce\".\n"
        "expected = {\n"
        '  "prod/cloudfront/E1" = { ports = [443], reason = "TODO: why is E1 open?" }\n'
        "  # tcp/22: SSH-2.0-OpenSSH_9.6\n"
        '  "prod/eni/i-0abc"    = { ports = [22], reason = "TODO: why is bastion open?" }\n'
        '  "prod/eni/i-web"     = { ports = [443], reason = "public site" }\n'
        "}\n"
    )


def test_suggestion_escapes_hcl_and_sanitizes_banners():
    weird = eni_endpoint("prod/eni/i-1", 'say "${hi}"')
    banner = finding("tcp/80", Verdict.UNEXPECTED_OPEN, Severity.HIGH, banner="HTTP/1.1 200\r\nX: \x00")
    text = suggested_expected([state(weird, banner)], (), "t")
    assert '# tcp/80: HTTP/1.1 200??X: ?' in text
    assert 'reason = "TODO: why is say \\"$${hi}\\" open?"' in text


def test_baseline_summary_counts_what_would_alert():
    states = [state(EP, OPEN22), state(front(), finding("http", Verdict.HTTP_OPEN, Severity.NONE, status=200))]
    alert = baseline_summary(states, CFG, "s3://perimeter-bucket/suggested-expected.tf")
    assert alert.kind is AlertKind.SUMMARY
    assert alert.description.startswith("2 endpoints in 1 account, 1 open port. In enforce mode 1 would alert (1 critical).")
    assert "s3://perimeter-bucket/suggested-expected.tf" in alert.description



def test_titles_read_as_words_and_every_verdict_has_a_phrase():
    from diff import PHRASES

    assert set(PHRASES) == set(Verdict)
    [alert] = diff({EP.id: state(EP)}, {EP.id: state(EP, OPEN22)}, CFG, SCOPES)
    assert alert.title == f":rotating_light: {EP.display}: tcp/22 open, not expected"
    assert alert.chatbot()["metadata"]["enableCustomActions"] is False  # hides the actions menu
