# terraform-aws-perimeter

[![CI](https://github.com/ankitkr/terraform-aws-perimeter/actions/workflows/ci.yml/badge.svg)](https://github.com/ankitkr/terraform-aws-perimeter/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Finds everything your AWS accounts expose to the internet, checks from the outside what
actually answers, compares it with what you declared should be open, and tells you in Slack
when the two differ, with the security group rule, NACL entry and route that make the port
reachable. One `terraform apply` in a security account, and a small read-only module in each
other account.

```
daily / hourly ──▶ Step Functions run
                     plan:  list every public endpoint in every account and region,
                            work out why each port is reachable (SG + NACL + route)
                     scan:  per batch, re-check that each address still belongs to you, then
                            TCP connect scan it (open / closed / filtered),
                            one HTTP request to each managed front (CloudFront, API Gateway, ...)
                     judge: verdict per port against `expected`, diff against the last run,
                            alert on differences, write inventory/latest.json

someone opens tcp/22 to 0.0.0.0/0 ──▶ CloudTrail ──▶ EventBridge ──▶ tripwire
                                     alert in seconds, naming who did it, then a rescan
```

A finding in Slack reads like this:

> *prod/eni/i-0abc* (bastion): tcp/22 *open*, not expected. Why: sg-1 rule sgr-9 tcp/22 from
> 0.0.0.0/0; acl-2 #100 allow; acl-2 egress #100 allow 1024-65535; rtb-3 0.0.0.0/0 → igw-4.
> Banner: `SSH-2.0-OpenSSH_9.6`.

And a tripwire:

> *alice@acme.com (AWSReservedSSO_AdministratorAccess_…)* opened tcp/22 to 0.0.0.0/0 on
> sg-0abc1234 (sgr-0f00d), from 203.0.113.9. Rescanning in 2 min.

## Read this first: what it is and isn't

It answers three questions for a team of 5 to 50 people: what do we expose, what actually
answers, and is that what we meant?

- **Configuration checkers** (Prowler, Security Hub CSPM, AWS Config rules) report that a
  security group allows 0.0.0.0/0. They can't tell whether anything listens on the port, or
  whether you meant it. This module scans from outside and judges against your declaration.
- **Security Hub Network Scanning** also scans from outside, but covers only EC2 public IPs,
  Elastic IPs and load balancers, probes 20 fixed TCP ports, costs $3.75 per resource a month,
  and can only exclude a resource by tag. This module also lists CloudFront, API Gateway,
  Lambda URLs, public RDS and OpenSearch, S3 websites, EKS API endpoints and Lightsail, scans
  the top 1,000 ports (or all of them), explains each open port, and costs under a dollar a
  month for a typical small setup.
- **It is not a vulnerability scanner.** It finds open ports and reads up to 256 bytes of
  banner. It doesn't test the services behind them.
- **It is not a remediation tool.** Exposure is declared in code, and fixes belong there too.
- **It uses no paid AWS security services.** Pair it with GuardDuty, Security Hub or Inspector
  if you use those; it doesn't replace them.

## Quick start

### Option 1: clone and apply

```sh
git clone https://github.com/ankitkr/terraform-aws-perimeter.git
cd terraform-aws-perimeter/deploy
cp terraform.tfvars.example terraform.tfvars   # region, regions, accounts, Slack IDs, emails
terraform init
terraform apply
```

Then, in each other account you listed:

```sh
cd terraform-aws-perimeter/deploy/member
cp terraform.tfvars.example terraform.tfvars   # values from: terraform -chdir=.. output member
terraform init
terraform apply                                # with credentials for that account
```

### Option 2: use it as a module

```hcl
module "perimeter" {
  source = "github.com/ankitkr/terraform-aws-perimeter?ref=v1.0.1"

  regions  = ["us-east-1", "ap-south-1"]
  accounts = { staging = "222222222222" }   # optional; this account is always included as "self"

  mode = "baseline"                          # first a baseline, then "enforce"

  expected = {
    "self/alb/api-prod" = { ports = [80, 443], reason = "public API" }
    "self/sg/sg-0abc*"  = { ports = [443], reason = "web tier" }
    "staging/eni/i-*"   = { ports = [], reason = "nothing should answer" }
  }

  slack        = { workspace_id = "T0123ABCD", channel_id = "C0123ABCD" }
  alert_emails = ["security@example.com"]
}

# In each other account, with that account's provider:
module "perimeter_member" {
  source = "github.com/ankitkr/terraform-aws-perimeter//modules/member?ref=v1.0.1"

  scanner_account_id = "111111111111"
  scanner_region     = "us-east-1"
  regions            = ["us-east-1", "ap-south-1"]
}
```

[examples/multi-account](examples/multi-account/main.tf) shows both in one root with two
providers. Every input is described in [docs/configuration.md](docs/configuration.md).

### Slack, once

Slack goes through Amazon Q Developer in chat applications (formerly AWS Chatbot). Before the
first apply with `slack` set, open the Amazon Q Developer console in the scanner account,
choose **Configure new client**, pick Slack and approve the workspace. Copy the workspace ID
into `slack.workspace_id`, and the channel ID (from the channel's link) into
`slack.channel_id`. Invite `@Amazon Q` to the channel. The channel can only display
notifications; v1 has no commands.

### Prerequisite for tripwires: CloudTrail

Tripwires read management events from EventBridge, which receives them only when a CloudTrail
trail logs management events in that account. An organization trail counts. Without one, the
daily and hourly runs still find every change, just not within seconds.

## From baseline to enforce

1. Apply with `mode = "baseline"` (the default). Every run inventories and scans, and nothing
   alerts except one summary per daily run.
2. After the first daily run (02:00 UTC by default, or start one by hand, see
   [docs/operations.md](docs/operations.md#manual-runs)), read
   `s3://<bucket>/suggested-expected.tf`. It declares every port that answered, with the
   banner as a comment:

   ```hcl
   expected = {
     # tcp/22: SSH-2.0-OpenSSH_9.6
     "self/eni/i-0abc"    = { ports = [22], reason = "TODO: why is bastion open?" }
     "self/cloudfront/E1" = { ports = [443], reason = "TODO: why is www.acme.com open?" }
   }
   ```

3. Keep the entries you mean, write a real reason for each, and close what you don't mean.
4. Set `mode = "enforce"` and apply. The next run alerts once on every finding that isn't
   expected; after that, only on changes.

## Declaring what should be open

`expected` is a map from glob keys to `{ ports, reason }`. `ports = []` means nothing should
answer.

- **Endpoint ids** are `<account>/<kind>/<id>`: `self/eni/i-0abc` (an instance, by instance
  id), `self/alb/api-prod`, `self/nlb/edge`, `self/clb/legacy`, `self/rds/reports`,
  `self/cloudfront/E2QWRUHEXAMPLE`, `self/apigw-rest/a1b2c3d4e5`, `self/lambda-url/webhook`,
  `self/eks/main`, `self/s3-website/acme-site`, `self/lightsail/blog`. The inventory
  document lists every id. A name used in two regions gets `@<region>`, as in
  `self/alb/api@eu-west-1`.
- **Globs** use `*`, `?` and `[...]`: `self/alb/api-*`, `staging/*`.
- **Security groups**: when no key matches the endpoint id, keys are matched against each of the
  endpoint's security groups as `<account>/sg/<sg-id>`, so `self/sg/sg-0abc*` declares every
  instance and load balancer in that group.
- **Order**: the first matching key in key order (Terraform sorts map keys) wins, and an id
  match always beats a security group match.
- **Tags**: a resource can declare itself with `perimeter:expected = "443,80"` and
  `perimeter:reason = "..."` (the prefix is `tag_prefix`). A variable key wins over a tag; if
  they disagree, the module reports it once.

## Verdicts

| Path found? | Scan | Expected? | Verdict | Severity |
|---|---|---|---|---|
| yes or no | open | yes | expected-open | none |
| yes | open | no | unexpected-open | high; critical for 22, 23, 3389, 5900, 2375, 2376, 3306, 5432, 1433, 6379, 9200, 11211, 27017 |
| no | open | no | unexplained-open: no path explains it | high, critical on the same ports |
| yes | closed (RST) | no | latent-confirmed: reachable, nothing listening | low |
| yes, only from specific public sources (narrower than /16) | filtered | no | allowlisted: reachable only from those sources, which are listed | low |
| yes | filtered | no | latent-filtered: a path is configured, something drops the probe | info |
| any | closed or filtered | yes | expected-closed | info; medium with `alert_on_closed` |
| allowlist only | filtered | yes | expected-open: can't be confirmed from outside, so the allowlist is trusted | none |

Managed fronts get endpoint-level verdicts: an unauthenticated Lambda URL, an EKS API endpoint
open to the internet, and an HTTP status that went from 4xx to 2xx. New and removed endpoints
always alert. More than five alerts for one account in one run arrive as one message.

`undeclared = "report"` keeps endpoints that nothing declares out of the per-port alerts: they
are announced as new endpoints and their ports appear in the inventory document.

## How the scan behaves

- **Only your addresses.** The scanner touches an IPv4 address only if the planner found it on
  a network interface (or Lightsail instance) in your account, and the batch's verify step
  confirmed that it still holds the address right before the batch's scan. The scanner starts
  no connection more than 10 minutes after that check: ports it hasn't reached by then are
  reported as not scanned. It refuses private, shared and link-local addresses outright.
- **Gentle by default.** 100 connection attempts per second per address (`scan.rate`, 1 to 500),
  at most 256 connections in flight per scanner invocation, a one-second timeout, and four
  invocations at a time. The top 1,000 ports take about 10 seconds per address.
- **Managed fronts get one request.** CloudFront, API Gateway, Lambda URLs, S3 websites, EKS
  and public OpenSearch domains share AWS's addresses, so they get one HTTPS GET to their AWS
  hostname instead of a port scan, without following redirects.
- **AWS's penetration testing policy** allows scanning your own EC2, ELB, RDS, CloudFront, API
  Gateway, Lambda, Lightsail, ECS/Fargate and OpenSearch resources without approval, and
  forbids flooding ([policy](https://aws.amazon.com/security/penetration-testing/)). EKS and S3
  websites aren't on that list, which is one reason they get a single HTTP request. Keep
  `scan.rate` modest.
- **IPv4 and TCP only.** IPv6 security group rules and routes are analysed and appear as paths,
  but IPv6 addresses aren't scanned. Nothing scans UDP.

How each step works: [docs/how-it-works.md](docs/how-it-works.md).

## Tripwires

Rules in each listed region (and us-east-1, where CloudFront's API lives) forward these calls
from every account to an event bus in the scanner account. The tripwire function alerts when the
call exposed something, naming the caller, their source IP, the resource and the exact change,
then starts a targeted run two minutes later.

| Calls | Alerts when |
|---|---|
| `AuthorizeSecurityGroupIngress`, `ModifySecurityGroupRules` | An internet CIDR, or a prefix list holding one |
| `CreateNetworkAclEntry`, `ReplaceNetworkAclEntry`, `ReplaceNetworkAclAssociation` | An inbound allow from the internet; a subnet moved to another NACL |
| `CreateRoute`, `ReplaceRoute`, `AssociateRouteTable`, `ReplaceRouteTableAssociation`, `AttachInternetGateway` | An internet route to an internet gateway; association changes |
| `ModifyInstanceAttribute`, `ModifyNetworkInterfaceAttribute`, `ModifySubnetAttribute` | Security groups changed; public IPs turned on at launch |
| `RunInstances`, `AssociateAddress` | A public IP in the request or response. An instance that gets one only from its subnet's auto-assign setting doesn't show it in the event; the next hourly inventory finds it |
| `CreateLoadBalancer`, `CreateListener`, `SetSecurityGroups`, `ApplySecurityGroupsToLoadBalancer` | An internet-facing load balancer; listener and group changes |
| `CreateFunctionUrlConfig`, `UpdateFunctionUrlConfig`, `AddPermission` | AuthType NONE; a policy letting anyone invoke a URL |
| `CreateDBInstance`, `ModifyDBInstance`, `RestoreDBInstance*`, `CreateDBInstanceReadReplica` | Publicly accessible; for `ModifyDBInstance`, only when the request sets it |
| OpenSearch `CreateDomain`, `UpdateDomainConfig` | No VPC options |
| EKS `CreateCluster`, `UpdateClusterConfig` | A public endpoint open to internet CIDRs. An update that turns the public endpoint on without naming CIDRs alerts as "with its existing CIDRs" and the rescan reads them |
| `PutBucketWebsite`, `PutBucketPolicy`, `(Put|Delete)BucketPublicAccessBlock`, `(Put|Delete)AccountPublicAccessBlock` | Website hosting on; a policy anyone can read through; a bucket's or the account's public access block weakened |
| `CreateDistribution`, API Gateway `CreateRestApi`, `CreateApi`, `CreateStage`, Lightsail `OpenInstancePublicPorts`, `PutInstancePublicPorts` | Always (info) |

Tripwires alert in baseline mode too, but only at or above `min_severity` (default `low`).
Routine changes stay quiet and are left to the hourly inventory, such as the EKS VPC CNI
re-attaching security groups every few minutes. So do calls AWS makes itself through service
principals or service-linked roles, such as ELB or RDS attaching their own Elastic IPs; the human
call that started them alerts on its own.

A load balancer created minutes before a scan may not answer yet. Its declared ports read as
expected-closed until the next run.

## What's not covered

- Global Accelerator, Redshift, App Runner, Amplify, AppSync, Transfer Family, Cognito hosted-UI
  domains, Amazon MQ and MSK public access, and Client VPN endpoints aren't inventoried.
- Paths through Transit Gateway, Gateway Load Balancer and Network Firewall endpoints are
  marked unverified rather than analysed.
- IPv6 addresses aren't scanned, and nothing scans UDP. An interface with only IPv6 addresses
  isn't listed at all; a dual-stack one is, with its IPv6 paths (`::/0` rules and routes) shown
  but only its IPv4 address scanned.
- Accounts are listed by hand; there is no AWS Organizations discovery.
- There are no Slack commands, buttons or weekly digest: v1 sends notifications only.
- A Lambda URL's own tags can't declare an expectation (the read-only role doesn't list
  function tags); declare it in `expected`.

What may come next: [ROADMAP.md](ROADMAP.md).

## Costs

For 3 accounts, 2 regions and 70 public addresses, the total is under $1 a month (estimate):

- the daily scan, about 12 minutes of Lambda at 256 MB: about $0.05;
- hourly inventories: about $0.10;
- Step Functions Standard: about 5 state transitions per hourly run, so about 4,000 a month,
  near the 4,000 free (then $0.025 per 1,000);
- DynamoDB on demand and S3: cents;
- cross-account events to the scanner's bus: $1 per million, so effectively nothing;
- 7 CloudWatch alarms at $0.10 each: $0.70 a month once the account's 10 free alarms are used.

The `all` port profile scans 65,535 ports per address, about 11 minutes each at the default
rate, which costs roughly 60 times as much Lambda time as `top1000` (about $5 a month for 70
addresses). Each address is split into two batches of about 5.5 minutes, so that every batch
finishes within its 10-minute ownership window, and four batches run at a time. A run then
takes about 3 minutes per address, and a run is stopped after an hour: with `all`, keep a full
run to about 20 addresses, or raise `scan.rate`.

## More

- [docs/how-it-works.md](docs/how-it-works.md): the run, the path analysis, the scanner, state
  and alerts.
- [docs/configuration.md](docs/configuration.md): every input, the deployer's permissions and
  the member setup.
- [docs/operations.md](docs/operations.md): reading alerts, the inventory document, manual
  runs and troubleshooting.
- [docs/development.md](docs/development.md): layout and tests.
- [SECURITY.md](SECURITY.md): what the module can do in your accounts.
- [docs/design.md](docs/design.md): the design this version was built from.
