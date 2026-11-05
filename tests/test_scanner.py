"""The scanner against local sockets: open, closed, filtered, the rate cap, and refusals."""

import asyncio
import http.server
import socket
import threading
import time

import pytest

from model import from_ranges
from scanner import Batch, HttpTarget, Refused, Target, handle, http_probe, parse_batch, ports_for, probe, run

NOW = 1_800_000_000
PROOF = "eni-0abc in 111111111111/us-east-1"


@pytest.fixture
def listener():
    """A local TCP service that greets like sshd."""
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(16)
    stop = threading.Event()

    def serve():
        server.settimeout(0.1)
        while not stop.is_set():
            try:
                conn, _ = server.accept()
            except OSError:
                continue
            conn.sendall(b"SSH-2.0-OpenSSH_9.6\r\n")
            conn.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    yield server.getsockname()[1]
    stop.set()
    thread.join()
    server.close()


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def batch(targets, **kw):
    base = dict(expires_at=int(time.time()) + 600, profile="top100", extra=(), rate=500, concurrency=64, timeout=0.3, targets=tuple(targets))
    return Batch(**{**base, **kw})


def test_open_closed_and_filtered(listener):
    closed = free_port()
    target = Target("prod/eni/i-1", "127.0.0.1", PROOF, only=(listener, closed))
    result = asyncio.run(run(batch([target])))["targets"][0]
    assert result["open"] == {str(listener): "SSH-2.0-OpenSSH_9.6"}
    assert from_ranges(result["closed"]) == {closed}
    assert from_ranges(result["scanned"]) == {listener, closed}


def test_an_unanswered_connect_is_filtered():
    # 10.255.255.1 isn't routed: the connect times out or the network is unreachable.
    state, banner = asyncio.run(probe("10.255.255.1", 22, 0.2))
    assert state.value == "filtered" and banner is None


def test_rate_is_capped_per_target():
    target = Target("prod/eni/i-1", "127.0.0.1", PROOF, only=tuple(range(40000, 40020)))
    started = time.monotonic()
    asyncio.run(run(batch([target], rate=50)))
    assert time.monotonic() - started >= 19 / 50


def test_concurrency_is_capped_across_the_batch():
    in_flight, peak = 0, 0

    async def slow_connect(ip, port):
        nonlocal in_flight, peak
        in_flight += 1
        peak = max(peak, in_flight)
        await asyncio.sleep(0.05)
        in_flight -= 1
        raise ConnectionRefusedError

    targets = [Target(f"prod/eni/i-{n}", "127.0.0.1", PROOF, only=tuple(range(1, 21))) for n in range(3)]
    asyncio.run(run(batch(targets, rate=500, concurrency=4), connect=slow_connect))
    assert peak == 4


def test_no_connect_starts_after_the_batch_expires():
    started = []

    async def connect(ip, port):
        started.append(time.monotonic())
        raise ConnectionRefusedError

    b = batch([Target("prod/eni/i-1", "203.0.113.9", PROOF, only=tuple(range(1, 41)))], rate=20)
    deadline = time.monotonic() + 0.3
    out = asyncio.run(run(b, connect=connect, wall=lambda: b.expires_at - 0.3))
    [result] = out["targets"]
    attempted = from_ranges(result["scanned"])
    assert 0 < len(attempted) < 40 and len(started) == len(attempted) and max(started) < deadline + 0.05
    assert result["expired"] == 40 - len(attempted)
    assert out["refused"] == [f"prod/eni/i-1: 203.0.113.9: {40 - len(attempted)} ports not scanned, the batch expired"]


def test_a_target_scans_only_its_port_range():
    t = Target("prod/eni/i-1", "203.0.113.10", PROOF, range=(1, 1000))
    ports = ports_for(t, batch([t], profile="all"))
    assert ports == tuple(range(1, 1001))


def test_the_verify_steps_notes_pass_through():
    assert handle(raw(not_scanned=["x: gone"], expires_at=NOW - 1), now=NOW)["not_scanned"] == ["x: gone"]


def test_ports_are_the_profile_plus_extra_critical_and_also():
    t = Target("prod/eni/i-1", "203.0.113.10", PROOF, also=(60001,))
    ports = ports_for(t, batch([t], extra=(9090,)))
    assert {80, 443, 9090, 60001, 6379, 27017, 11211, 2375} <= set(ports)
    assert ports_for(Target("prod/rds/db", "203.0.113.11", PROOF, only=(5432,)), batch([])) == (5432,)


# --- refusals -----------------------------------------------------------------------------------


def raw(**kw):
    base = {"expires_at": NOW + 600, "profile": "top100", "rate": 100, "targets": [{"endpoint_id": "prod/eni/i-1", "ip": "203.0.113.10", "proof": PROOF}]}
    return {**base, **kw}


def test_an_expired_batch_is_refused_and_nothing_is_scanned(monkeypatch):
    called = []
    monkeypatch.setattr("scanner.run", lambda *a, **k: called.append(a))
    result = handle(raw(expires_at=NOW - 1), now=NOW)
    assert result["targets"] == [] and called == []
    assert result["refused"] == [f"batch expired at {NOW - 1} (now {NOW}); ownership must be verified again"]
    with pytest.raises(Refused):
        parse_batch(raw(expires_at=NOW), NOW)


@pytest.mark.parametrize(
    "target,reason",
    [
        ({"endpoint_id": "x", "ip": "203.0.113.10"}, "has no ownership proof"),
        ({"endpoint_id": "x", "ip": "203.0.113.10", "proof": "trust me"}, "has no ownership proof"),
        ({"endpoint_id": "x", "ip": "10.0.0.5", "proof": PROOF}, "isn't a global IPv4 address"),
        ({"endpoint_id": "x", "ip": "169.254.169.254", "proof": PROOF}, "isn't a global IPv4 address"),
    ],
)
def test_unproven_or_internal_addresses_are_refused(target, reason):
    parsed, refusals = parse_batch(raw(targets=[target]), NOW)
    assert parsed.targets == () and len(refusals) == 1 and reason in refusals[0]


def test_http_probes_only_aws_hostnames():
    fronts = [
        {"endpoint_id": "a", "url": "https://d111.cloudfront.net/", "host": "d111.cloudfront.net"},
        {"endpoint_id": "b", "url": "https://example.com/", "host": "example.com"},
        {"endpoint_id": "c", "url": "https://10.0.0.1/", "host": "x.execute-api.us-east-1.amazonaws.com"},
    ]
    parsed, refusals = parse_batch(raw(http=fronts), NOW)
    assert [h.endpoint_id for h in parsed.http] == ["a"] and len(refusals) == 2


def test_rate_outside_the_cap_is_refused():
    assert handle(raw(rate=501), now=NOW)["refused"] == ["rate 501 is outside 1-500 per second"]


def test_a_proven_lightsail_address_is_accepted():
    parsed, refusals = parse_batch(raw(targets=[{"endpoint_id": "x", "ip": "203.0.113.10", "proof": "lightsail:blog in 111111111111/eu-west-1"}]), NOW)
    assert len(parsed.targets) == 1 and refusals == []


# --- HTTP ---------------------------------------------------------------------------------------


@pytest.fixture
def web():
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            code = {"/redirect": 302, "/denied": 403}.get(self.path, 200)
            self.send_response(code)
            if code == 302:
                self.send_header("Location", "/elsewhere")
            self.end_headers()

        def log_message(self, *args):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()


@pytest.mark.parametrize("path,status", [("/", 200), ("/denied", 403), ("/redirect", 302)])
def test_http_status_without_following_redirects(web, path, status):
    out = http_probe(HttpTarget("prod/cloudfront/E1", web + path, "127.0.0.1"))
    assert out["status"] == status and out["server"].startswith("BaseHTTP") and out["error"] is None


def test_http_no_answer_is_recorded():
    out = http_probe(HttpTarget("x", f"http://127.0.0.1:{free_port()}/", "127.0.0.1"), timeout=0.5)
    assert out["status"] is None and out["error"]


def test_http_probes_finish_before_any_connect_starts():
    # Live, TLS handshakes on threads alongside the scan starved the loop and open ports read as filtered.
    events = []

    def slow_http(h):
        time.sleep(0.2)
        events.append(("http-done", time.monotonic()))
        return {"endpoint_id": h.endpoint_id, "url": h.url, "status": 200}

    async def connect(ip, port):
        events.append(("connect", time.monotonic()))
        raise ConnectionRefusedError

    b = batch(
        targets=(Target("prod/eni/i-1", "203.0.113.9", "eni-1 in 111111111111/us-east-1", only=(22, 80)),),
        http=tuple(HttpTarget(f"prod/cloudfront/E{i}", f"https://d{i}.cloudfront.net/", f"d{i}.cloudfront.net") for i in range(3)),
    )
    out = asyncio.run(run(b, connect=connect, http=slow_http))
    last_http = max(t for kind, t in events if kind == "http-done")
    first_connect = min(t for kind, t in events if kind == "connect")
    assert len(out["http"]) == 3 and first_connect >= last_http
