# Design: terraform-aws-perimeter

Status: revised after review, 2026-11-05. This is the build spec.

## Problem

A 5–50 person team on AWS doesn't know what it exposes to the internet. Exposure comes from
security groups, NACLs, public IPs, load balancers, managed fronts (CloudFront, API Gateway,
Lambda URLs), databases marked public, EKS API endpoints and Lightsail, and it drifts.

- **Configuration checkers** (Prowler, Security Hub CSPM, Config rules) say "this security group
  has 0.0.0.0/0". They can't say whether anything listens, or whether the exposure is intended.
- **Security Hub Network Scanning** (July 2026) scans from outside, with limits:
  - it covers only EC2 public IPs, EIPs and load balancers;
  - it probes exactly 20 TCP ports;
  - it costs $3.75 per resource unit a month;
  - its only notion of "intended" is a tag that excludes a resource from scanning.
- **The fallback is a hand-written exposure document** that goes stale.

The module gives the team:

1. **An inventory** of every public endpoint, in every listed account and region, written to S3
   as a JSON document. This *is* the exposure document, generated rather than written by hand.
2. **What actually answers**, from an outside-in TCP scan with three states: open, closed (RST),
   and filtered.
3. **What should be open**, declared as code.
4. **An alert only on difference**, with *why* the port is reachable: rule, NACL, route and the
   matched CIDR.
5. **A tripwire within seconds** when someone opens something to the internet, naming who did it.
6. **No paid AWS security services.** It costs under a dollar a month.

## Decisions (with the user)

| | Decision |
|---|---|
| Scope | Perimeter tooling only, without AWS's security services. A separate repo will configure those. |
| Accounts | Single account by default. Other accounts are added by list, each with a read-only role from the `member` submodule. |
| Scanner | Pure-Python TCP connect scan in Lambda. No container, no VPC, no UDP. |

## v1 scope

| In | Out (later or never) |
|---|---|
| ENIs with public IPv4 (EC2, Fargate, other services), internet-facing ALB/NLB/CLB, CloudFront, API Gateway (REST, HTTP, WebSocket), Lambda URLs, public RDS and OpenSearch, S3 websites, EKS public API endpoints, Lightsail instances | Global Accelerator, Redshift, App Runner, Amplify, AppSync, Transfer Family, Cognito domains, MQ/MSK public, Client VPN (documented as not covered) |
| Daily scan, hourly inventory, tripwires with targeted rescans | Slack commands, buttons, weekly digest |
| Own why-reachable analysis | Network Access Analyzer, Transit Gateway, GWLB and Network Firewall paths (flagged "unverified") |
| Accounts by list | Organization discovery |
| IPv4 scanning; IPv6 in the configuration analysis | IPv6 scanning, UDP |

## Interface

```hcl
module "perimeter" {
  source = "github.com/ankitkr/terraform-aws-perimeter?ref=v1.0.0"

  regions  = ["us-east-1", "ap-south-1"]
  accounts = { staging = "222222222222" }   # optional; this account is always included as "self" or account_name

  mode = "baseline"                          # first: inventory + scan + suggested `expected`, no alerts; then "enforce"

  expected = {                               # keys are globs over endpoint ids or security-group ids
    "self/alb/api-prod"     = { ports = [80, 443], reason = "public API" }
    "self/sg/sg-0abc*"      = { ports = [443],     reason = "web tier" }
    "staging/eni/i-*"       = { ports = [],        reason = "nothing should answer" }
  }
  undeclared = "alert"                       # or "report": new endpoints are noticed, not alerted per port

  scan = {
    schedule    = "cron(0 2 * * ? *)"
    ports       = "top1000"                  # "top100" | "top1000" | "all"
    extra_ports = [2375, 5601, 9090, 11211]
    rate        = 100                        # attempts per second, per target
  }

  slack = { workspace_id = "T…", channel_id = "C…" }   # or sns_topic_arn, alert_emails
}

module "perimeter_member" {                   # in each extra account
  source             = "github.com/ankitkr/terraform-aws-perimeter//modules/member?ref=v1.0.0"
  scanner_account_id = "111111111111"
  scanner_role_name  = "perimeter-planner"   # output of the main module
  regions            = ["us-east-1", "ap-south-1"]
}
```

A tag on a resource can declare its own expectation: `perimeter:expected = "443,80"`, and
`perimeter:reason`. Variable keys win over tags; a mismatch between them is reported once.

## Data model

### Endpoint

```
Endpoint {
  id        "<account>/<kind>/<stable id>"    e.g. self/eni/i-0abc… (instance id when attached),
                                               self/alb/<name>, self/eip/eipalloc-…, self/eks/<cluster>
  display   Name tag or service name
  account, region, kind, arn, tags, security_groups [sg-…]
  probe     Tcp{addresses: [OwnedIPv4], ports} | Http{url, host} | None
  paths     {port: [Path]}                      configured exposure, why reachable
}
OwnedIPv4 { ip, proof: "eni-… in <account>/<region>" }   only ENI- or address-backed IPs
Path      { refs: [str], cidr, verified: bool }          e.g. ["sg-1 rule sgr-9 tcp/22 from 0.0.0.0/0",
                                                          "acl-2 #100 allow", "rtb-3 0.0.0.0/0 → igw-4"]
```

| Kind | Found by | Probe | Why-reachable |
|---|---|---|---|
| `eni` (EC2, Fargate, other services) | `DescribeNetworkInterfaces`, `association.public-ip` | TCP over the profile | ENI security groups + subnet NACL + route |
| `alb` | `elbv2 DescribeLoadBalancers` (internet-facing); addresses from its ENIs (description `ELB app/<name>/<id>`) | TCP over the profile | Listener + LB security groups + NACLs of its subnets |
| `nlb` | Same, ENIs `ELB net/…` | TCP | Listener + NLB SG (if any) + **target SG when client-IP preservation is on** (default for instance targets) + target subnet NACL; unhealthy or absent targets noted |
| `clb` | `elb DescribeLoadBalancers`, ENIs `ELB <name>` | TCP | Listener + LB security groups + NACLs |
| `cloudfront`, `apigw-*`, `lambda-url`, `s3-website` | Service list APIs; Lambda URLs need `ListFunctions` + `ListFunctionUrlConfigs` + `GetPolicy` | **HTTP** request to the hostname: status and selected headers. Never a TCP scan of shared edge IPs | The endpoint existing is the exposure. A Lambda URL is flagged when AuthType is NONE **and** the policy allows `lambda:InvokeFunctionUrl` to `*` |
| `rds`, `opensearch` | `PubliclyAccessible`; OpenSearch domains without VPC options | TCP on the engine port, to addresses from the DB's ENI | Security group + NACL + route |
| `eks` | `DescribeCluster` with `endpointPublicAccess` | HTTP to the API endpoint (expect 401/403) | `publicAccessCidrs` matched against "internet" |
| `lightsail` | `GetInstances`, `GetInstancePortStates`, `GetStaticIps` | TCP over the public IP | Lightsail firewall (port states) |
| `nat`, `eip` without attachment | Describe | none | Listed only |

**"Internet":** any CIDR outside RFC 1918, RFC 6598 and the VPC's own ranges, and `::/0` or global
IPv6. Customer-managed prefix lists are expanded (`GetManagedPrefixListEntries`). AWS-managed
lists, such as CloudFront origin-facing, are named in the path ("only CloudFront can reach this").
Security groups referencing other groups are not internet paths.

**Route check:**
- the subnet's route table (explicit association, or the main table);
- the most specific route matching an internet address leads to an internet gateway attached to
  this VPC;
- a route to a NAT gateway means no inbound path;
- a route to a GWLB or Network Firewall endpoint marks the path `verified: false`.

**NACL check:** inbound rules in rule order for the port and an internet CIDR. Outbound must allow
the client's ephemeral range (1024–65535). An NACL allowing only part of it is reported as a
partial path.

### Observation (scanner output)

```
Observation { endpoint_id, ip, port, state: open | closed | filtered, banner?, at }
Http        { endpoint_id, status, server?, at }
```

### Expectation

From `expected` (glob keys matched against the endpoint id, then against each of its security
group ids as `<account>/sg/<sg-id>`; the first match in key order wins), or from tags.

### Verdict: the pure core

```
classify(endpoint, observations, expectation) -> {port: Verdict}
```

| Path found? | Scan | Expected? | Verdict | Severity |
|---|---|---|---|---|
| yes / no | open | yes | expected-open | none |
| yes / no | open | no | unexpected-open | high; critical for 22, 3389, 23, 2375/2376, 3306, 5432, 1433, 6379, 9200, 11211, 27017, 5900 |
| yes | closed (RST) | no | latent-confirmed: reachable, nothing listening | low |
| yes | filtered | no | latent-filtered: path configured, something drops it (host firewall?) | info |
| no | open | — | unexplained-open: analysis found no path, the scan says open; check prefix lists, an NLB, or report a module bug | high |
| — | closed / filtered | yes | expected-closed | info; warn with `alert_on_closed` |

Managed fronts get endpoint-level verdicts: new, removed, unauthenticated Lambda URL, EKS
endpoint open to the internet, HTTP status changed from 4xx to 2xx.

### State and diff

DynamoDB holds the last verdict per (endpoint, port) and the last inventory.

```
diff(previous, current) -> [Alert]
```

Alerts fire on:
- a new or changed verdict at or above `min_severity`;
- a new endpoint;
- a removed endpoint (info);
- a resolved finding.

Unchanged verdicts never re-alert.

The run writes `inventory/latest.json` and `inventory/<date>.json` to the module's S3 bucket. The
bucket is versioned, with lifecycle expiry. Each entry lists the endpoint, its addresses, its
ports and their verdicts, the paths, and the expectation with its reason.

### Baseline mode

`mode = "baseline"` (the default) runs everything but sends no per-port alerts. Each run
publishes one summary message and writes `suggested-expected.tf` to S3:
- an `expected` block with the currently open ports per endpoint;
- the observed banner as a comment.

The user reviews it, pastes it in, and switches to `"enforce"`.

## Runs

| Trigger | Work |
|---|---|
| Daily schedule | Full: inventory → paths → scan → classify → diff → alert → inventory document |
| Hourly schedule | Inventory and paths only. New endpoints and latent changes are alerted, and new endpoints queue a targeted scan |
| Tripwire | Alert in seconds, then a targeted run on the affected resources after 2 minutes |
| Manual | `aws stepfunctions start-execution` with `{"endpoints": ["self/alb/api-prod"]}` or `{"full": true}`. Inputs are endpoint ids, never addresses |

Step Functions Standard drives the run: plan, an inline Map over scan batches, then judge. It is
free at this volume and gives retries, timeouts and a visible run history.

### Functions

| Function | Job |
|---|---|
| `planner` | Assumes the member role per account and inventories each region in parallel. Global services: CloudFront from us-east-1, Lightsail per region. It computes paths and writes the inventory. Invoked again per batch by the Map, right before that batch scans, it **re-verifies ownership** of every IP (`DescribeNetworkInterfaces` for that IP in that account, or Lightsail's `GetInstance`) and stamps the batch with an expiry of 10 minutes |
| `scanner` | Invocable **only by the state machine's role**. Refuses an expired batch, starts no connect after the expiry, and refuses any address not carrying the planner's proof. It runs an `asyncio` TCP connect at a capped rate (100/s per target) and concurrency (256), with a 1 s timeout. The result is open, closed (RST) or filtered (timeout). It grabs up to 256 bytes of banner on open ports. HTTP probes run here too |
| `judge` | Classify, diff, alert, write the inventory document and the baseline suggestion |
| `tripwire` | Judges a forwarded CloudTrail event, alerts, and starts a targeted run |

Batch sizing: each batch's worst case must fit its 10-minute window. `top1000` at 100/s is about
10 s per address plus timeouts, so about 20 addresses per batch. `all` splits each address
into port ranges that fit, two at 100/s.

### Scan etiquette

- Port scanning of your own resources is allowed without approval on EC2, ELB, RDS, CloudFront,
  API Gateway, Lambda, Lightsail, ECS/Fargate and OpenSearch
  ([policy](https://aws.amazon.com/security/penetration-testing/)). Flooding is not.
- EKS and S3 websites aren't on that list, so they get a single HTTP request each, not a scan.
- The scanner only touches ownership-proven addresses from the same run.
- The README documents the policy and the defaults.

## Tripwires

These need a CloudTrail trail logging management events in each scanned account; an organization
trail counts. Rules match `AWS API Call via CloudTrail` events and forward them to an event bus in
the scanner account:
- in member accounts, through an IAM role created by the `member` submodule;
- the bus policy allows only the listed accounts.

Rules live in each listed region, plus us-east-1 for CloudFront.

| Events | Exposure when |
|---|---|
| `AuthorizeSecurityGroupIngress`, `ModifySecurityGroupRules` (including flipping an existing rule) | An internet CIDR, or a prefix list containing one |
| `CreateNetworkAclEntry`, `ReplaceNetworkAclEntry`, `ReplaceNetworkAclAssociation` | An ingress allow from the internet, or a subnet moved onto such an NACL |
| `CreateRoute`, `ReplaceRoute`, `AssociateRouteTable`, `ReplaceRouteTableAssociation`, `AttachInternetGateway` | An internet route to an IGW, or a subnet moved onto a public route table |
| `ModifyInstanceAttribute` (groupSet), `ModifyNetworkInterfaceAttribute` (groups), `ModifySubnetAttribute` (MapPublicIpOnLaunch) | Always; targeted run |
| `RunInstances`, `AssociateAddress` | A public IP in `responseElements`; targeted run |
| `CreateLoadBalancer` (internet-facing), `CreateListener`, `SetSecurityGroups`, `ApplySecurityGroupsToLoadBalancer` | Always; targeted run |
| `CreateFunctionUrlConfig`, `UpdateFunctionUrlConfig`, `AddPermission` | AuthType NONE with public invoke |
| `CreateDBInstance`, `ModifyDBInstance`, `RestoreDBInstance*` | PubliclyAccessible true |
| `CreateDomain`, `UpdateDomainConfig` (OpenSearch) | No VPC options |
| `CreateCluster`, `UpdateClusterConfig` (EKS) | Public endpoint with internet `publicAccessCidrs` |
| `PutBucketWebsite`, `PutBucketPolicy`, `(Put|Delete)BucketPublicAccessBlock`, `(Put|Delete)AccountPublicAccessBlock` | The bucket becomes publicly readable as a website |
| `CreateDistribution`, API Gateway create API/stage, Lightsail `OpenInstancePublicPorts`/`PutInstancePublicPorts` | Always (info); targeted run |

Each alert names:
- the caller (`userIdentity.arn` and session name, or the role it assumed);
- the source IP;
- the resource;
- the exact rule.

## IAM

- **Member role, in each account and also used in the module's own account.** The trust policy
  names the scanner account's root as principal, with `ArnEquals aws:PrincipalArn` = the planner
  and tripwire roles (as in letsencrypt-acm). An external ID is optional. Read-only:
  - ec2 Describe*;
  - elasticloadbalancing Describe*;
  - cloudfront List/Get;
  - apigateway GET;
  - lambda `ListFunctions`, `ListFunctionUrlConfigs`, `GetPolicy`;
  - rds Describe;
  - es Describe/List;
  - s3 `ListAllMyBuckets`, `GetBucketLocation`, `GetBucketWebsite`, `GetBucketPolicyStatus`;
  - eks List/Describe;
  - lightsail Get;
  - `ec2:GetManagedPrefixListEntries`.
- **Member forwarding role:** `events:PutEvents` on the scanner bus only.
- **Planner:** `sts:AssumeRole` on member roles; writes to S3 and DynamoDB.
- **Scanner:** logs only.
- **Judge:** DynamoDB, S3, SNS.
- **Tripwire:** DynamoDB, SNS, `states:StartExecution`.
- **State machine:** invokes the four functions.

## Notifications

SNS topic and optional Amazon Q Slack channel, reusing the devboxes stack:
- CloudFormation in the module's region (overridable);
- a channel role that can't invoke anything;
- notifications only;
- audit log group pre-created with retention;
- one configuration per channel.

Alerts are custom notifications:
- **Tripwire:** "*alice@acme* opened tcp/22 to 0.0.0.0/0 on sg-0abc (web-prod), from 203.0.113.9.
  Rescanning in 2 min."
- **Finding:** "*prod/eni/i-0abc* (bastion): tcp/22 **open**, not expected. Why: sg-1 rule
  sgr-9 from 0.0.0.0/0; acl-2 #100 allow; rtb-3 0.0.0.0/0 → igw-4."

When a run produces more than 5 alerts for one account, they are grouped.

## Resources

- Main module:
  - four Lambda functions (Python 3.14, arm64, boto3 only, `archive_file`);
  - a Step Functions state machine;
  - a DynamoDB table;
  - an S3 bucket for the inventory;
  - an EventBridge bus with its policy, schedules and own-account tripwire rules;
  - an SNS topic, the optional Amazon Q stack, and alarms on failed runs and failed functions.
- `member` submodule: read-only role, forwarding role, tripwire rules per region.

## Costs (estimate)

For 3 accounts, 2 regions and 70 addresses, the total is under $1 a month:
- the daily scan: about 12 minutes of Lambda at 256 MB, about $0.05;
- hourly inventories: about $0.10;
- Step Functions: free;
- DynamoDB and S3: cents;
- cross-account events: $1 per million.

## Testing

- **Unit tests:**
  - the classifier table;
  - the diff;
  - expectation glob matching and precedence;
  - "internet" CIDR logic;
  - path analysis over fixture VPCs: NACL order and deny, main versus explicit route table, NAT,
    a more specific route, prefix lists, NLB with and without an SG and client-IP preservation;
  - tripwire judgments over real CloudTrail event samples for every listed event;
  - the scanner against local sockets (open, closed, filtered, rate cap, expired batch and
    unproven address refused);
  - baseline suggestion rendering.
- **Live test in the sandbox, two accounts:**
  - an instance with sshd on 22 open to the world: found, unexpected, explained;
  - 8080 open in its SG with nothing listening: latent-confirmed;
  - an iptables DROP on 8081: latent-filtered;
  - a declared ALB on 443: no alert;
  - opening 3389 by hand: tripwire, then a rescan;
  - a Lambda URL with no auth;
  - an RDS instance made public;
  - the member submodule in the second account;
  - baseline, then enforce;
  - teardown.
