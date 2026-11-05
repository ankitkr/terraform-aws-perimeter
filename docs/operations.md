# Operations

Commands below use the default `name`, `perimeter`, and the scanner account's credentials.

## Reading an alert

Every finding names the endpoint, the port, the verdict, and why the port is reachable:

```
prod/eni/i-0abc (bastion): tcp/22 open, not expected. Why: sg-1 rule sgr-9 tcp/22 from
0.0.0.0/0; acl-2 #100 allow; acl-2 egress #100 allow 1024-65535; rtb-3 0.0.0.0/0 → igw-4.
Banner: SSH-2.0-OpenSSH_9.6.
```

The "Why" lists one path: the security group rule and its source, the NACL entry that let the
client in, the NACL entry that lets replies out, and the route back. "(+2 more)" means other
rules open the same port; the inventory document lists them all. "[unverified]" means the
route passes through a firewall or load balancer appliance or a transit gateway that the
module doesn't analyse. "[partial]" means the NACL lets replies out on only part of the
ephemeral range, so some clients connect and others time out.

What to do:

- **unexpected-open**: close it (the rule in "Why"), or declare it in `expected` with a reason.
- **unexplained-open**: something answered that the analysis can't explain. See
  [troubleshooting](#unexplained-open).
- **latent-confirmed**: nothing listens yet, but anything that starts listening on that port is
  exposed. Close the rule unless you expect a listener.
- **allowlisted**: the port is open only to specific public sources: a partner's ranges, an
  office. The scanner, coming from AWS's addresses, can't reach it, so the inventory lists the
  sources instead. It is low, so a new allowlist entry alerts once. Declare it in `expected` to
  record why.
- **latent-filtered**: the configuration allows the port, and something on the path (often a
  host firewall) drops the probe. Usually harmless; it is info and doesn't alert by default.
- **expected-closed**: a declared port doesn't answer. The service may be down.
- **resolved**: a finding went away, or fell below `min_severity`.

## The inventory document

`s3://<bucket>/inventory/latest.json` (the `inventory_url` output) is rewritten by every run, and
`inventory/<date>.json` keeps one per day. It is the exposure document:

```json
{
  "generated_at": "2026-11-05T02:03:11Z",
  "run": "a1b2c3", "run_mode": "full", "mode": "enforce",
  "accounts": {"self": "111111111111", "staging": "222222222222"},
  "regions": ["us-east-1", "ap-south-1"],
  "incomplete": [],
  "refused": [],
  "not_scanned": [],
  "unconfigured": [],
  "endpoints": [
    {
      "id": "self/eni/i-0abc", "display": "bastion", "kind": "eni",
      "account": "self", "region": "us-east-1", "arn": "arn:aws:ec2:...:instance/i-0abc",
      "addresses": [{"ip": "203.0.113.10", "proof": "eni-0123 in 111111111111/us-east-1"}],
      "url": null,
      "security_groups": ["sg-1"],
      "declared": true,
      "expectation": {"ports": [22], "reason": "bastion", "source": "expected[\"self/eni/i-0abc\"]"},
      "ports": {
        "22": {"verdict": "expected-open", "severity": "none", "detail": "open, expected: bastion",
               "banner": "SSH-2.0-OpenSSH_9.6", "paths": [{"ports": "22", "cidr": "0.0.0.0/0", "refs": ["..."], "verified": true, "partial": false}]}
      },
      "findings": {},
      "paths": [{"ports": "22", "cidr": "0.0.0.0/0", "refs": ["..."], "verified": true, "partial": false}],
      "notes": [],
      "last_scan": 1793851391,
      "open_ports": [22]
    }
  ]
}
```

- `incomplete` lists the scopes a run couldn't list in full, and why. Nothing in them is
  reported as removed.
- `refused` lists what the scanner refused (an expired batch, an address without proof).
- `not_scanned` lists addresses that changed hands between the inventory and the scan.
- `unconfigured` says which endpoints this run removed from the state because their account or
  region was taken out of the configuration. They don't alert as removed.
- `findings` holds endpoint-level verdicts: `http` (status of the front), `auth` (Lambda URL),
  `api` (EKS), `expectation` (a tag that disagrees with `expected`, or can't be parsed).

```sh
aws s3 cp "$(terraform output -raw inventory_url)" - | jq '.endpoints[] | select(.ports | to_entries | any(.value.verdict == "unexpected-open")) | .id'
```

## Manual runs

Start a full run, or probe some endpoints by id (never by address):

```sh
SM=$(terraform output -raw state_machine_arn)
aws stepfunctions start-execution --state-machine-arn "$SM" --input '{"full": true}'
aws stepfunctions start-execution --state-machine-arn "$SM" --input '{"endpoints": ["self/alb/api-prod", "staging/eni/i-0abc"]}'
```

The ids must be in the last inventory document. An unknown account name or endpoint id, or a
malformed input, fails the run at the planner with the reason in the execution's error.

The Step Functions console shows each run: the planner's batches, every scanner result, and the
judge's summary. The functions log one line per run:

```sh
aws logs tail /aws/lambda/perimeter-planner --since 1h
aws logs tail /aws/lambda/perimeter-judge --since 1h
```

## Troubleshooting

### unexplained-open

The scanner connected, but no path explains it. In order of likelihood:

1. **A prefix list.** A rule names a customer-managed prefix list that the planner couldn't read,
   or that changed between the inventory and the scan. Look for "prefix list ... unreadable" in
   the endpoint's `notes`.
2. **A network load balancer.** An address you think belongs to an instance is actually an NLB's,
   or an NLB forwards to it with client-IP preservation off. Compare `addresses[].proof` with
   the interface in the console.
3. **A change in between.** The configuration changed after the inventory. The next hourly run
   re-judges it.
4. **A module bug.** If none of these applies, open an issue with the endpoint's entry from the
   inventory document, and the security group, NACL and route table (`aws ec2 describe-...`).

### latent-filtered on many ports

A security group open to all ports from the internet, with a host firewall in front, makes every
scanned port latent-filtered. They are info and stay out of alerts. Narrow the security group.

### A whole account or region is missing

Check `incomplete` in the inventory document. "can't assume perimeter-member" means the member
module isn't applied in that account, or its `name` or `external_id` differs from the main
module's. An API name with `AccessDenied` in a member account usually means an SCP denies it.

### No tripwire alerts

1. The account needs a CloudTrail trail logging management events
   ([configuration](configuration.md#tripwires-need-cloudtrail)).
2. The member module's rules must exist in the region of the change (CloudFront: us-east-1).
3. The tripwire function's log shows every event it received and why it didn't alert:

   ```sh
   aws logs tail /aws/lambda/perimeter-tripwire --since 1h
   ```

### Alarms

- `perimeter-failed-runs`, `perimeter-timedout-runs`: open the failed execution in the Step
  Functions console; the failing state shows the error.
- `perimeter-silent`: no successful run in three inventory intervals (three hours at the
  default `rate(1 hour)`). Check that the schedules are enabled and the state machine isn't
  failing.
- `perimeter-<function>-errors`: see that function's log.

### Pausing

Disable the schedules to stop scanning; tripwires keep alerting:

```sh
aws events disable-rule --name perimeter-full
aws events disable-rule --name perimeter-inventory
```
