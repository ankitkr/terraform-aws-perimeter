# Changelog

## v1.0.1

- Notification titles read as words ("bastion: tcp/22 open, not expected") instead of verdict
  slugs; "was …" and resolved notes use the same wording. The inventory document keeps the slugs.
- Notifications no longer show Amazon Q's actions menu, since v1 has no buttons.

## v1.0.0

First release.

- Inventory of every public endpoint in the listed accounts and regions: instances and other
  network interfaces with public IPv4, internet-facing ALB, NLB and CLB, CloudFront, API
  Gateway (REST, HTTP, WebSocket), Lambda function URLs, public RDS and OpenSearch, S3 websites,
  EKS public API endpoints and Lightsail instances; NAT gateways and unattached Elastic IPs
  listed.
- Why-reachable analysis for every port: security group rules (with customer prefix lists
  expanded and AWS-managed ones named), NACLs in rule order with the ephemeral return range,
  the most specific route to an attached internet gateway (narrowing the source to what that
  route returns), and load balancer listeners, with NLB client-IP preservation. Paths through firewall or GWLB endpoints and transit gateways are
  marked unverified.
- Outside-in TCP connect scan of ownership-proven IPv4 addresses (top 100, top 1,000 or all
  ports, plus critical ports), with open, closed and filtered states and banners; one HTTP
  request per managed front. Each batch re-verifies its addresses right before it scans and
  starts no connection more than 10 minutes after that; batches are sized, and an address split
  by port range, so that each fits.
- Verdicts against `expected` (globs over endpoint ids and security groups) and resource tags;
  alerts on new, changed and resolved verdicts, new and removed endpoints, and fronts whose
  status went from 4xx to 2xx, grouped above five per account.
- Baseline mode with a generated `suggested-expected.tf`.
- Tripwires on CloudTrail events from every listed account, including bucket- and
  account-level S3 public access blocks, alerting in seconds with the caller, source IP and
  exact change, then a targeted rescan. A failed publish is retried rather than lost.
- Daily full and hourly inventory runs on Step Functions; state in DynamoDB with versioned
  conditional writes, stored only after the run's alerts are published; inventory documents
  in a versioned S3 bucket. Endpoints of accounts or regions taken out of the configuration
  are forgotten.
- CloudWatch alarms on failed, timed-out and missing runs (the window follows a `rate()`
  inventory schedule) and on each function's errors.
- Alerts to SNS and Slack (Amazon Q Developer custom notifications) and email.
- The `member` submodule: a read-only role pinned to the scanner's roles, and tripwire
  forwarding.
- `deploy/` and `deploy/member/` stacks for clone-and-apply.
