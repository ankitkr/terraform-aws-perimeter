"""The verdict table, managed-front verdicts, and expectation matching and precedence."""

import pytest

from classify import classify, expectation_for
from model import Endpoint, Expectation, Flag, HttpObservation, Kind, Observation, Path, Severity, State, Verdict

PATH22 = Path((22, 22), ("sg-1 rule sgr-9 tcp/22 from 0.0.0.0/0", "acl-2 #100 allow", "rtb-3 0.0.0.0/0 → igw-4"), "0.0.0.0/0")
PATH_ANY = Path((0, 65535), ("sg-1 rule sgr-1 all from 0.0.0.0/0",), "0.0.0.0/0")


def endpoint(paths=(), flags=(), tags=None, sgs=("sg-0abc123",), id="prod/eni/i-0abc", kind=Kind.ENI):
    return Endpoint(id, "bastion", id.split("/")[0], "us-east-1", kind, tags=tags or {}, security_groups=sgs, paths=tuple(paths), flags=frozenset(flags))


def obs(port, state, ip="203.0.113.10", banner=None):
    return Observation("prod/eni/i-0abc", ip, port, state, banner)


def expect(*ports, reason="public"):
    return Expectation(frozenset(ports), reason, "test")


def verdict(ep, observations, expectation=None, **kw):
    return {s: (f.verdict, f.severity) for s, f in classify(ep, observations, expectation, **kw).items()}


# --- the table ----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "paths,state,expectation,want",
    [
        ((PATH22,), State.OPEN, expect(22), (Verdict.EXPECTED_OPEN, Severity.NONE)),
        ((), State.OPEN, expect(22), (Verdict.EXPECTED_OPEN, Severity.NONE)),
        ((PATH22,), State.OPEN, expect(443), (Verdict.UNEXPECTED_OPEN, Severity.CRITICAL)),
        ((PATH22,), State.OPEN, None, (Verdict.UNEXPECTED_OPEN, Severity.CRITICAL)),
        ((PATH22,), State.CLOSED, None, (Verdict.LATENT_CONFIRMED, Severity.LOW)),
        ((PATH22,), State.FILTERED, None, (Verdict.LATENT_FILTERED, Severity.INFO)),
        ((), State.OPEN, None, (Verdict.UNEXPLAINED_OPEN, Severity.CRITICAL)),
        ((), State.CLOSED, expect(22), (Verdict.EXPECTED_CLOSED, Severity.INFO)),
        ((PATH22,), State.FILTERED, expect(22), (Verdict.EXPECTED_CLOSED, Severity.INFO)),
    ],
)
def test_verdict_table(paths, state, expectation, want):
    assert verdict(endpoint(paths), [obs(22, state)], expectation) == {"tcp/22": want}


def test_non_critical_ports_are_high():
    assert verdict(endpoint([PATH_ANY]), [obs(8080, State.OPEN)]) == {"tcp/8080": (Verdict.UNEXPECTED_OPEN, Severity.HIGH)}
    assert verdict(endpoint(), [obs(8080, State.OPEN)]) == {"tcp/8080": (Verdict.UNEXPLAINED_OPEN, Severity.HIGH)}


@pytest.mark.parametrize("port", [22, 23, 3389, 5900, 2375, 2376, 3306, 5432, 1433, 6379, 9200, 11211, 27017])
def test_critical_ports(port):
    assert verdict(endpoint([PATH_ANY]), [obs(port, State.OPEN)])[f"tcp/{port}"][1] is Severity.CRITICAL


def test_closed_or_filtered_without_a_path_or_expectation_has_no_verdict():
    assert verdict(endpoint(), [obs(22, State.CLOSED), obs(23, State.FILTERED)]) == {}


def test_alert_on_closed_raises_expected_closed():
    assert verdict(endpoint(), [obs(443, State.FILTERED)], expect(443), alert_on_closed=True) == {"tcp/443": (Verdict.EXPECTED_CLOSED, Severity.MEDIUM)}


def test_an_expected_port_that_wasnt_scanned_has_no_verdict():
    assert verdict(endpoint(), [], expect(443)) == {}


def test_one_open_address_makes_the_port_open_and_keeps_its_banner():
    found = classify(endpoint([PATH22]), [obs(22, State.FILTERED, "203.0.113.1"), obs(22, State.OPEN, "203.0.113.2", "SSH-2.0-OpenSSH_9.6")], None)
    assert found["tcp/22"].verdict is Verdict.UNEXPECTED_OPEN
    assert found["tcp/22"].banner == "SSH-2.0-OpenSSH_9.6"
    assert found["tcp/22"].paths == (PATH22,)


# --- managed fronts -----------------------------------------------------------------------------


def test_unauthenticated_lambda_url_is_high_unless_declared():
    url = endpoint(flags=[Flag.UNAUTHENTICATED_URL], id="prod/lambda-url/hook", kind=Kind.LAMBDA_URL)
    assert verdict(url, []) == {"auth": (Verdict.UNAUTHENTICATED_URL, Severity.HIGH)}
    assert verdict(url, [], expect(443)) == {"auth": (Verdict.EXPECTED_PUBLIC, Severity.NONE)}


def test_public_eks_endpoint():
    eks = endpoint(flags=[Flag.PUBLIC_API], id="prod/eks/main", kind=Kind.EKS)
    assert verdict(eks, []) == {"api": (Verdict.PUBLIC_API, Severity.HIGH)}


@pytest.mark.parametrize("status,want", [(200, Verdict.HTTP_OPEN), (301, Verdict.HTTP_OPEN), (403, Verdict.HTTP_DENIED), (None, Verdict.HTTP_UNREACHABLE)])
def test_http_status_verdicts(status, want):
    cf = endpoint(id="prod/cloudfront/E1", kind=Kind.CLOUDFRONT)
    found = classify(cf, [HttpObservation("prod/cloudfront/E1", "https://d1.cloudfront.net/", status, "CloudFront", at=5)], None)
    assert found["http"].verdict is want and found["http"].status == status


# --- expectations -------------------------------------------------------------------------------

EXPECTED = (
    ("prod/alb/api-*", expect(80, 443, reason="public API")),
    ("prod/eni/i-0abc", expect(443, reason="exact id")),
    ("prod/sg/sg-0abc*", expect(8443, reason="web tier")),
    ("prod/sg/sg-0abc1*", expect(9443, reason="later sg key")),
    ("staging/eni/i-*", expect(reason="nothing should answer")),
)


def test_glob_over_the_endpoint_id():
    alb = endpoint(id="prod/alb/api-prod", sgs=())
    assert expectation_for(alb, EXPECTED, "perimeter")[0].reason == "public API"
    assert expectation_for(endpoint(id="staging/eni/i-9", sgs=()), EXPECTED, "perimeter")[0].ports == frozenset()


def test_an_endpoint_id_match_beats_a_security_group_match():
    assert expectation_for(endpoint(), EXPECTED, "perimeter")[0].reason == "exact id"


def test_security_group_keys_first_match_in_key_order():
    ep = endpoint(id="prod/eni/i-other", sgs=("sg-0abc123",))
    assert expectation_for(ep, EXPECTED, "perimeter")[0].reason == "web tier"
    other_account = endpoint(id="dev/eni/i-other", sgs=("sg-0abc123",))
    assert expectation_for(other_account, EXPECTED, "perimeter") == (None, None)


def test_tags_declare_an_expectation():
    ep = endpoint(id="dev/eni/i-1", tags={"perimeter:expected": "443, 80", "perimeter:reason": "web"}, sgs=())
    exp, problem = expectation_for(ep, EXPECTED, "perimeter")
    assert exp == Expectation(frozenset({80, 443}), "web", "tag") and problem is None


def test_variable_wins_over_tags_and_the_mismatch_is_reported():
    ep = endpoint(tags={"perimeter:expected": "22"})
    exp, problem = expectation_for(ep, EXPECTED, "perimeter")
    assert exp.reason == "exact id"
    assert "says ports 443 but tag perimeter:expected says 22" in problem
    found = classify(ep, [], exp, problem=problem)
    assert (found["expectation"].verdict, found["expectation"].severity) == (Verdict.EXPECTATION_CONFLICT, Severity.INFO)


def test_agreeing_tag_and_variable_is_no_problem():
    assert expectation_for(endpoint(tags={"perimeter:expected": "443"}), EXPECTED, "perimeter")[1] is None


@pytest.mark.parametrize("raw", ["https", "22;80", "70000"])
def test_bad_tags_are_ignored_and_reported(raw):
    ep = endpoint(id="dev/eni/i-1", tags={"perimeter:expected": raw}, sgs=())
    exp, problem = expectation_for(ep, EXPECTED, "perimeter")
    assert exp is None and "ignored" in problem


def test_an_empty_tag_expects_nothing_open():
    ep = endpoint(id="dev/eni/i-1", tags={"perimeter:expected": ""}, sgs=())
    assert expectation_for(ep, EXPECTED, "perimeter")[0].ports == frozenset()


def test_first_matching_id_key_in_key_order_wins():
    keys = (("prod/eni/*", expect(reason="all prod instances")), ("prod/eni/i-0abc", expect(443, reason="exact id")))
    assert expectation_for(endpoint(), keys, "perimeter")[0].reason == "all prod instances"


ALLOWLIST = Path((5432, 5432), ("sg-lb rule sgr-s tcp/5432 from 198.51.100.96/29",), "198.51.100.96/29")
PARTNER = Path((5432, 5432), ("pl-1 rule", ), "pl-0abc (partners): 203.0.113.38/32")
WIDE = Path((5432, 5432), ("sg-1 rule tcp/5432 from 3.0.0.0/8",), "3.0.0.0/8")


@pytest.mark.parametrize(
    "paths, state, expectation, want",
    [
        # Live in staging: 5432 open to a partner's ranges only; the scanner, from AWS, sees it filtered.
        ((ALLOWLIST, PARTNER), State.FILTERED, None, (Verdict.ALLOWLISTED, Severity.LOW)),
        ((ALLOWLIST,), State.FILTERED, expect(5432), (Verdict.EXPECTED_OPEN, Severity.NONE)),
        # A /8 is not an allowlist; one wide path among narrow ones isn't either.
        ((WIDE,), State.FILTERED, None, (Verdict.LATENT_FILTERED, Severity.INFO)),
        ((ALLOWLIST, WIDE), State.FILTERED, None, (Verdict.LATENT_FILTERED, Severity.INFO)),
        # If the probe got a reset, it reached the host: not an allowlist the scanner is outside of.
        ((ALLOWLIST,), State.CLOSED, None, (Verdict.LATENT_CONFIRMED, Severity.LOW)),
    ],
)
def test_allowlisted_ports(paths, state, expectation, want):
    f = classify(endpoint(paths), [obs(5432, state)], expectation)["tcp/5432"]
    assert (f.verdict, f.severity) == want
    if want[0] is Verdict.ALLOWLISTED:
        assert f.detail == "reachable only from 198.51.100.96/29, 203.0.113.38/32"
