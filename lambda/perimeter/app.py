"""Lambda handlers.

planner:  lists every endpoint in the run's scopes, works out its paths, picks what to probe,
          and returns scanner batches. Step Functions passes {"input": <execution input>,
          "execution": <execution name>}. With {"verify": <batch>} it re-checks the batch's
          addresses right before the scan instead, and gives the batch its window.
scanner:  scans one batch; invocable only by the state machine.
judge:    classifies, diffs against the stored state, alerts, and writes the inventory
          document and, in baseline mode, the suggested `expected` block.
tripwire: judges one forwarded CloudTrail event, alerts, and starts a targeted run.
"""

import datetime as dt
import logging
import time
from concurrent.futures import ThreadPoolExecutor

import boto3
from botocore.exceptions import ClientError

import aws
import diff
import inventory
import plan
import scanner as scan
import tripwire as tw
from classify import assess
from model import Config, Endpoint, EndpointState, OwnedIPv4

logging.getLogger().setLevel(logging.INFO)
for noisy in ("botocore", "boto3", "urllib3"):
    logging.getLogger(noisy).setLevel(logging.WARNING)
log = logging.getLogger(__name__)

_clients = {}


def _client(name):
    if name not in _clients:
        _clients[name] = boto3.client(name, config=aws.RETRIES)
    return _clients[name]


def _setup(max_age=0):
    store = aws.DynamoStore(aws.table_name(), _client("dynamodb"))
    return Config.parse(aws.load_config(store, max_age)), store


def _accounts(cfg, names):
    """{name: Account} for the accounts whose member role could be assumed, and problems for
    the rest (most often: the member module isn't applied there yet)."""
    sts, accounts, problems = _client("sts"), {}, []
    for n in names:
        try:
            accounts[n] = aws.member_account(n, cfg.accounts[n], cfg.member_role_name, cfg.external_id, sts)
        except ClientError as exc:
            problems.append(f"{n}: can't assume {cfg.member_role_name} ({exc.response.get('Error', {}).get('Code', 'error')}); is the member module applied there?")
    return accounts, problems


# --- planner ------------------------------------------------------------------------------------


def _list(accounts, scopes):
    """Inventory every scope of the reachable accounts in parallel: (endpoints, complete
    scopes, problems)."""
    scopes = [s for s in scopes if s[0] in accounts]

    def one(scope):
        account, region = accounts[scope[0]], scope[1]
        return scope, inventory.discover_global(account) if region == "global" else inventory.discover_region(account, region)

    endpoints, complete, problems = [], [], []
    with ThreadPoolExecutor(max_workers=8) as pool:
        for scope, inv in pool.map(one, scopes):
            endpoints += inv.endpoints
            problems += inv.problems
            if not inv.problems:
                complete.append(list(scope))
    return inventory.disambiguate(endpoints), complete, problems


def planner(event, context):
    if "verify" in event:
        return _verify(event["verify"])
    cfg, store = _setup()
    now = int(time.time())
    request = plan.Request.parse(event.get("input"), cfg.accounts)
    run_id = event.get("execution") or f"manual-{now}"
    previous = store.states()
    scopes = plan.scopes(request, cfg, previous)
    accounts, unreachable = _accounts(cfg, sorted({a for a, _ in scopes}))
    endpoints, complete, problems = _list(accounts, scopes)
    problems = unreachable + problems
    chosen = set(plan.targets(request, endpoints, previous))
    batches = plan.batches([e for e in endpoints if e.id in chosen], cfg)
    key = f"runs/{run_id}.json"
    aws.Bucket(cfg.bucket, _client("s3")).put_json(
        key,
        {
            "run_id": run_id,
            "mode": request.mode,
            "at": now,
            "scopes": complete,
            "problems": problems,
            "endpoints": [e.to_json() for e in endpoints],
            "targets": sorted(chosen),
        },
    )
    log.info("run %s (%s): %d endpoints in %d scopes, %d probed in %d batches; problems: %s", run_id, request.mode, len(endpoints), len(scopes), len(chosen), len(batches), problems or "none")
    return {"run": {"run_id": run_id, "key": key, "mode": request.mode}, "batches": batches}


def _verify(batch):
    """The batch with only the addresses their account still holds, and EXPIRES_AFTER seconds
    from now to scan them: an address released since the inventory may be someone else's."""
    cfg, _ = _setup()
    started = int(time.time())
    names = {v: k for k, v in cfg.accounts.items()}
    by_scope, not_scanned = {}, []
    for t in batch.get("targets") or ():
        account_id, region = inventory.proof_scope(t.get("proof") or "")
        if account_id in names:
            by_scope.setdefault((names[account_id], region), []).append(t)
        else:
            not_scanned.append(f"{t.get('endpoint_id')}: {t.get('ip')}: its proof names no configured account")
    accounts, problems = _accounts(cfg, sorted({a for a, _ in by_scope}))
    kept = []
    for (name, region), targets in by_scope.items():
        if name not in accounts:
            why = "; ".join(p for p in problems if p.startswith(f"{name}:"))
            not_scanned += [f"{t['endpoint_id']}: {t['ip']}: ownership not verified ({why})" for t in targets]
            continue
        held = {(a.ip, a.proof) for a in inventory.verify_ownership(accounts[name], region, [OwnedIPv4(t["ip"], t["proof"]) for t in targets])}
        for t in targets:
            if (t["ip"], t["proof"]) in held:
                kept.append(t)
            else:
                not_scanned.append(f"{t['endpoint_id']}: {t['ip']} no longer held by {t['proof']}")
    log.info("verified %d of %d addresses; not scanned: %s", len(kept), len(batch.get("targets") or ()), not_scanned or "none")
    return {**batch, "targets": kept, "expires_at": started + plan.EXPIRES_AFTER, "not_scanned": not_scanned}


# --- scanner ------------------------------------------------------------------------------------


def scanner(event, context):
    result = scan.handle(event)
    log.info("scanned %d addresses and %d fronts; refused: %s", len(result["targets"]), len(result["http"]), result["refused"] or "none")
    return result


# --- judge --------------------------------------------------------------------------------------


def _judge_endpoint(cfg, endpoint, before, scan_record, http):
    """(current state, expectation, alerts, state to store) for one endpoint."""
    current, expectation = assess(endpoint, before, scan_record, http, cfg)
    if cfg.mode == "enforce":
        alerts, findings = diff.diff_endpoint(before, current, cfg), diff.persisted(current.findings, cfg.min_severity)
    else:
        # Baseline stores no verdicts: the first enforce run then reports every finding
        # that isn't expected, once, instead of treating it as already known.
        alerts, findings = [], {}
    return current, expectation, alerts, EndpointState(endpoint, current.declared, findings, current.scan, current.http)


def _commit(store, cfg, judged, now, publish):
    """Store each endpoint's state. One a concurrent run wrote first is judged again against
    what that run stored, and whatever that shows is published before it's stored."""
    for ep, before, scan_record, http, stored in judged:
        for _ in range(3):
            if store.put(stored, before.version if before else 0, now):
                break
            before = store.get(ep.id)
            *_, alerts, stored = _judge_endpoint(cfg, ep, before, scan_record, http)
            for a in alerts:
                publish(a)
        else:
            raise RuntimeError(f"{ep.id}: state kept changing under concurrent runs")


def _unconfigured_note(states):
    ids = sorted(s.endpoint.id for s in states)
    many = len(ids) != 1
    return f"{len(ids)} endpoint{'s' if many else ''} in an account or region no longer configured {'were' if many else 'was'} removed: {', '.join(ids)}"


def judge(event, context):
    """Alerts go out before any state is stored: a run that fails to publish leaves the verdicts
    unknown, so the next run reports them again."""
    cfg, store = _setup()
    now = int(time.time())
    bucket = aws.Bucket(cfg.bucket, _client("s3"))
    run = bucket.get_json(event["run"]["key"])
    scans, https, refusals, not_scanned = scan.collect(event.get("results") or [])
    previous = store.states()
    complete = {tuple(s) for s in run["scopes"]}

    states, expectations, alerts, judged, gone, unconfigured = {}, {}, [], [], [], []
    for raw in run["endpoints"]:
        ep = Endpoint.from_json(raw)
        before, scan_record, http = previous.get(ep.id), scans.get(ep.id), https.get(ep.id)
        current, expectation, found, stored = _judge_endpoint(cfg, ep, before, scan_record, http)
        states[ep.id], expectations[ep.id] = current, expectation
        alerts += found
        judged.append((ep, before, scan_record, http, stored))
    for eid, before in previous.items():
        if eid in states:
            continue
        account, region = before.endpoint.scope
        if account not in cfg.accounts or (region != "global" and region not in cfg.regions):
            unconfigured.append(before)
        elif before.endpoint.scope in complete:
            gone.append(before)
            if cfg.mode == "enforce":
                alerts.append(diff.removed_alert(before))
        else:
            states[eid], expectations[eid] = assess(before.endpoint, before, None, None, cfg)
    alerts = diff.group(alerts)

    generated = dt.datetime.fromtimestamp(now, dt.timezone.utc)
    stamp = generated.strftime("%Y-%m-%dT%H:%M:%SZ")
    if cfg.mode == "baseline" and run["mode"] == "full":
        bucket.put_text("suggested-expected.tf", diff.suggested_expected(states.values(), cfg.expected, stamp))
        alerts.append(diff.baseline_summary(states.values(), cfg, bucket.url("suggested-expected.tf")))
    doc = diff.document(
        [diff.document_entry(s, expectations.get(eid)) for eid, s in states.items()],
        {
            "generated_at": stamp,
            "run": run["run_id"],
            "run_mode": run["mode"],
            "mode": cfg.mode,
            "accounts": cfg.accounts,
            "regions": list(cfg.regions),
            "incomplete": run["problems"],
            "refused": refusals,
            "not_scanned": not_scanned,
            "unconfigured": [_unconfigured_note(unconfigured)] if unconfigured else [],
        },
    )
    bucket.put_json("inventory/latest.json", doc)
    bucket.put_json(f"inventory/{generated:%Y-%m-%d}.json", doc)

    publish = aws.Publisher(cfg.sns_topic_arn, cfg.slack, _client("sns"))
    for a in alerts:
        publish(a)
    _commit(store, cfg, judged, now, publish)
    for before in gone + unconfigured:
        store.delete(before.endpoint.id, before.version)
    log.info("run %s: %d endpoints, %d alerts, refused: %s", run["run_id"], len(states), len(alerts), refusals or "none")
    return {"endpoints": len(states), "alerts": len(alerts)}


# --- tripwire -----------------------------------------------------------------------------------


def _prefix_lists(cfg, account_name, region, ids):
    if not ids or account_name not in cfg.accounts:
        return None
    accounts, _ = _accounts(cfg, [account_name])
    if account_name not in accounts:
        return None
    ec2 = accounts[account_name].client("ec2", region)
    return {pl: [e["Cidr"] for e in ec2.get_managed_prefix_list_entries(PrefixListId=pl).get("Entries") or ()] for pl in ids}


def tripwire(event, context):
    cfg, store = _setup(max_age=60)
    names = {v: k for k, v in cfg.accounts.items()}
    account_name = names.get(event.get("account"), event.get("account", "unknown"))
    resolved = _prefix_lists(cfg, account_name, event.get("region"), tw.prefix_list_ids(event))
    finding = tw.judge(event, resolved)
    if finding is None:
        return {"alerted": False}
    if finding.change.severity < cfg.min_severity:
        # Routine changes (an EKS node re-attaching security groups, every few minutes) would
        # flood the channel and queue a run each; the hourly inventory sees their effect.
        log.info("below min_severity, left to the hourly inventory: %s %s", event.get("detail", {}).get("eventName"), finding.change.text)
        return {"alerted": False}
    # Marked only once the alert and the run are out: a failure is retried, and a rare concurrent
    # redelivery may alert twice.
    key = f"tripwire#{finding.event_id}"
    if store.sent(key):
        log.info("event %s already handled", finding.event_id)
        return {"alerted": False}
    aws.Publisher(cfg.sns_topic_arn, cfg.slack, _client("sns"))(tw.alert(finding, account_name))
    if finding.change.rescan and cfg.state_machine_arn and account_name in cfg.accounts:
        aws.start_run(
            _client("stepfunctions"),
            cfg.state_machine_arn,
            f"tripwire-{finding.event_id}",
            {
                "delay": tw.RESCAN_DELAY,
                "touch": {
                    "account": account_name,
                    "region": finding.region,
                    "resources": list(finding.change.touched),
                    "global": event.get("source") in ("aws.cloudfront", "aws.s3"),
                },
            },
        )
    store.mark_sent(key, int(time.time()))
    return {"alerted": True}
