"""The outside-in scan: TCP connects to ownership-proven addresses at a capped rate, and one
HTTP request per managed front. Touches only the addresses in this batch, and starts no connect
after the batch expires: the verify step re-proved their ownership EXPIRES_AFTER before that."""

import asyncio
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

import internet
import ports as profiles
from classify import CRITICAL_PORTS
from model import HttpObservation, ScanRecord, State, from_ranges, to_ranges

BANNER_BYTES = 256
BANNER_TIMEOUT = 0.5
CLOSE_TIMEOUT = 0.2
HTTP_TIMEOUT = 5.0

PROOF = re.compile(r"^(eni-[0-9a-f]+|lightsail:[A-Za-z0-9._-]+) in \d{12}/[a-z0-9-]+$")
# Managed fronts are probed on their AWS hostnames only, never on an address or custom domain.
AWS_HOST = re.compile(r"^[A-Za-z0-9.-]+\.(cloudfront\.net|amazonaws\.com|on\.aws|amazonaws\.com\.cn)$")


class Refused(Exception):
    pass


@dataclass(frozen=True)
class Target:
    endpoint_id: str
    ip: str
    proof: str
    also: tuple[int, ...] = ()  # expected ports and small path ranges outside the profile
    only: tuple[int, ...] | None = None  # a database: its engine port alone
    range: tuple[int, int] | None = None  # this batch's share of the ports, inclusive


@dataclass(frozen=True)
class HttpTarget:
    endpoint_id: str
    url: str
    host: str


@dataclass(frozen=True)
class Batch:
    expires_at: int
    profile: str
    extra: tuple[int, ...]
    rate: int  # attempts per second, per target
    concurrency: int  # connections in flight across the batch
    timeout: float  # seconds per connect
    targets: tuple[Target, ...]
    http: tuple[HttpTarget, ...] = ()


def parse_batch(raw, now, allow=internet.is_global_ipv4):
    """(Batch, refusals). Refuses the whole batch when it has expired, and any target that lacks
    the planner's proof, isn't a global IPv4 address, or isn't an AWS hostname."""
    if int(raw.get("expires_at", 0)) <= now:
        raise Refused(f"batch expired at {raw.get('expires_at')} (now {now}); ownership must be verified again")
    refusals, targets, http = [], [], []
    for t in raw.get("targets") or ():
        ip, proof = t.get("ip", ""), t.get("proof") or ""
        if not PROOF.match(proof):
            refusals.append(f"{t.get('endpoint_id')}: {ip} has no ownership proof")
        elif not allow(ip):
            refusals.append(f"{t.get('endpoint_id')}: {ip} isn't a global IPv4 address")
        else:
            only, part = t.get("only"), t.get("range")
            targets.append(Target(t["endpoint_id"], ip, proof, tuple(int(p) for p in t.get("also") or ()), tuple(int(p) for p in only) if only else None, (int(part[0]), int(part[1])) if part else None))
    for h in raw.get("http") or ():
        if not AWS_HOST.match(h.get("host", "")) or urllib.parse.urlsplit(h.get("url", "")).hostname != h.get("host"):
            refusals.append(f"{h.get('endpoint_id')}: {h.get('url')} isn't an AWS hostname")
        else:
            http.append(HttpTarget(h["endpoint_id"], h["url"], h["host"]))
    rate = int(raw.get("rate", 100))
    if not 1 <= rate <= 500:
        raise Refused(f"rate {rate} is outside 1-500 per second")
    return (
        Batch(
            expires_at=int(raw["expires_at"]),
            profile=raw.get("profile", "top1000"),
            extra=tuple(int(p) for p in raw.get("extra") or ()),
            rate=rate,
            concurrency=max(1, min(int(raw.get("concurrency", 256)), 1024)),
            timeout=max(0.05, min(float(raw.get("timeout", 1.0)), 5.0)),
            targets=tuple(targets),
            http=tuple(http),
        ),
        refusals,
    )


def port_set(profile, extra, also=(), only=None):
    """Every port an address is scanned on, ascending: the planner splits this list into ranges."""
    if only:
        return tuple(sorted(set(only)))
    return tuple(sorted(set(profiles.profile(profile)) | set(extra) | CRITICAL_PORTS | set(also)))


def ports_for(target, batch):
    ports = port_set(batch.profile, batch.extra, target.also, target.only)
    if target.range:
        ports = tuple(p for p in ports if target.range[0] <= p <= target.range[1])
    return ports


# --- TCP ----------------------------------------------------------------------------------------


def _printable(data):
    text = data.decode("utf-8", errors="replace")
    return "".join(c if c.isprintable() or c in "\r\n\t" else "." for c in text).strip() or None


async def probe(ip, port, timeout, connect=asyncio.open_connection):
    """(State, banner): open when the connect completes, closed on a reset, filtered on a
    timeout or an unreachable network."""
    try:
        reader, writer = await asyncio.wait_for(connect(ip, port), timeout)
    except ConnectionRefusedError:
        return State.CLOSED, None
    except (TimeoutError, asyncio.TimeoutError, OSError):
        return State.FILTERED, None
    banner = None
    try:
        banner = _printable(await asyncio.wait_for(reader.read(BANNER_BYTES), min(BANNER_TIMEOUT, timeout)))
    except (TimeoutError, asyncio.TimeoutError, OSError):
        pass
    finally:
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), CLOSE_TIMEOUT)
        except (TimeoutError, asyncio.TimeoutError, OSError):
            pass
    return State.OPEN, banner


async def scan_target(target, ports, batch, gate, deadline, connect=asyncio.open_connection, clock=time.monotonic):
    """One address: attempt i starts no earlier than i / rate seconds in, the gate caps the
    connections in flight across the whole batch, and no attempt starts after the deadline."""
    start = clock()
    results = {}

    async def one(port):
        async with gate:
            if clock() < deadline:
                results[port] = await probe(target.ip, port, batch.timeout, connect)

    tasks = []
    for i, port in enumerate(ports):
        delay = start + i / batch.rate - clock()
        if delay > 0:
            await asyncio.sleep(delay)
        if clock() >= deadline:
            break
        tasks.append(asyncio.create_task(one(port)))
    await asyncio.gather(*tasks)
    return {
        "endpoint_id": target.endpoint_id,
        "ip": target.ip,
        "scanned": to_ranges(results),
        "expired": len(ports) - len(results),
        "open": {str(p): b for p, (s, b) in sorted(results.items()) if s is State.OPEN},
        "closed": to_ranges(p for p, (s, _) in results.items() if s is State.CLOSED),
    }


# --- HTTP ---------------------------------------------------------------------------------------


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def _tls():
    # Only the status is read. EKS endpoints present the cluster's own CA, which no default
    # trust store holds, and a status is worth more here than a failed handshake.
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def http_probe(target, timeout=HTTP_TIMEOUT):
    """One GET without following redirects: the status and the Server header."""
    opener = urllib.request.build_opener(_NoRedirects, urllib.request.HTTPSHandler(context=_tls()))
    request = urllib.request.Request(target.url, method="GET", headers={"Host": target.host, "User-Agent": "terraform-aws-perimeter"})
    out = {"endpoint_id": target.endpoint_id, "url": target.url, "status": None, "server": None, "error": None}
    try:
        with opener.open(request, timeout=timeout) as response:
            out["status"], out["server"] = response.status, response.headers.get("Server")
    except urllib.error.HTTPError as exc:
        out["status"], out["server"] = exc.code, exc.headers.get("Server") if exc.headers else None
    except (urllib.error.URLError, TimeoutError, OSError, ssl.SSLError) as exc:
        out["error"] = str(getattr(exc, "reason", exc))[:200]
    return out


# --- the batch ----------------------------------------------------------------------------------


async def run(batch, connect=asyncio.open_connection, http=None, wall=time.time, clock=time.monotonic):
    # HTTP probes first, then the TCP scan, never both at once: TLS handshakes on threads starve the
    # event loop on Lambda's fraction of a CPU, and a connect that succeeded is then handled after
    # its timeout fired, so an open port reads as filtered (seen live with 27 fronts in one batch).
    http = http or http_probe
    https = await asyncio.gather(*(asyncio.to_thread(http, h) for h in batch.http))
    gate = asyncio.Semaphore(batch.concurrency)
    deadline = clock() + batch.expires_at - wall()
    targets = await asyncio.gather(*(scan_target(t, ports_for(t, batch), batch, gate, deadline, connect, clock) for t in batch.targets))
    refused = [f"{t['endpoint_id']}: {t['ip']}: {t['expired']} ports not scanned, the batch expired" for t in targets if t["expired"]]
    return {"targets": list(targets), "http": list(https), "refused": refused}


def handle(raw, now=None):
    """The scanner function's work: refuse or scan, and report both."""
    now = int(now if now is not None else time.time())
    not_scanned = list(raw.get("not_scanned") or ())
    try:
        batch, refusals = parse_batch(raw, now)
    except Refused as exc:
        return {"at": now, "targets": [], "http": [], "refused": [str(exc)], "not_scanned": not_scanned}
    results = asyncio.run(run(batch))
    return {"at": now, "targets": results["targets"], "http": results["http"], "refused": refusals + results["refused"], "not_scanned": not_scanned}


def collect(results):
    """Scanner outputs -> ({endpoint id: ScanRecord}, {endpoint id: HttpObservation}, refusals,
    not scanned). An endpoint's addresses, and an address's port ranges, may have been scanned in
    different batches."""
    scans, https, refusals, not_scanned = {}, {}, [], []
    for r in results:
        refusals += r.get("refused") or []
        not_scanned += r.get("not_scanned") or []
        at = r.get("at", 0)
        for t in r.get("targets") or ():
            s = scans.setdefault(t["endpoint_id"], {"at": at, "scanned": set(), "open": {}, "closed": {}})
            s["at"] = max(s["at"], at)
            s["scanned"] |= from_ranges(t["scanned"])
            s["open"].setdefault(t["ip"], {}).update({int(p): b for p, b in t["open"].items()})
            s["closed"][t["ip"]] = s["closed"].get(t["ip"], frozenset()) | from_ranges(t["closed"])
        for h in r.get("http") or ():
            https[h["endpoint_id"]] = HttpObservation(h["endpoint_id"], h["url"], h["status"], h.get("server"), h.get("error"), at)
    records = {e: ScanRecord(s["at"], frozenset(s["scanned"]), s["open"], s["closed"]) for e, s in scans.items()}
    return records, https, refusals, not_scanned
