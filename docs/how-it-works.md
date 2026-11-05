# How it works

## One run

A Step Functions Standard state machine named after the module (`perimeter` by default) runs
three Lambda functions:

1. **Plan.** The planner assumes `<name>-member` in each account, including its own, and lists
   the run's scopes in parallel: every listed region of every account, plus one "global" scope
   per account for CloudFront and S3 websites. For each endpoint it works out the paths from
   the internet. It picks the endpoints to probe, cuts them into batches, and writes the run's
   working document to `runs/<execution>.json` in the bucket.
2. **Scan.** An inline Map works through the batches, four at a time. For each batch it first
   invokes the planner again to verify: it re-checks that every address still belongs to its
   account, drops (and notes) any that doesn't, and stamps the batch with
   `expires_at` = now + 10 minutes. The scanner then scans the batch.
3. **Judge.** The judge reads the working document and the scanner results, classifies every
   endpoint, compares the verdicts with the stored ones, writes `inventory/latest.json` and
   `inventory/<date>.json`, publishes the alerts, and only then stores the new verdicts: a run
   that fails to publish leaves them unknown, so the next run reports them again.

What starts a run decides what it probes:

| Start | Input | Probes |
|---|---|---|
| Daily schedule (`scan.schedule`) | `{"mode": "full"}` | Every endpoint |
| Hourly schedule (`scan.inventory_schedule`) | `{"mode": "inventory"}` | New endpoints, and endpoints whose paths, addresses or URL changed |
| Tripwire | `{"delay": 120, "touch": {...}}` | After two minutes, what the event touched in that account and region, plus anything new there |
| By hand | `{"full": true}` or `{"endpoints": ["self/alb/api"]}` | Everything, or the named endpoints (ids, never addresses) |

Endpoints a run doesn't probe are judged again from their last scan against today's paths and
`expected`. A security group change that closes a latent port, or a new `expected` entry,
takes effect on the next hourly run without a scan.

## The inventory

| Kind | Found by | Probe |
|---|---|---|
| `eni` | `DescribeNetworkInterfaces` with a public IPv4 association, grouped by instance (Fargate tasks and other services' interfaces by interface id). Interfaces belonging to load balancers, NAT gateways, RDS, VPC endpoints and Global Accelerator are left to those kinds. An interface with only IPv6 addresses isn't listed; a dual-stack one shows its IPv6 paths too, but only its IPv4 address is scanned | TCP over the port profile |
| `alb`, `nlb` | `elbv2 DescribeLoadBalancers`, internet-facing. Addresses from the interfaces described `ELB app/<name>/<id>` or `ELB net/<name>/<id>` | TCP over the port profile |
| `clb` | `elb DescribeLoadBalancers`, internet-facing; interfaces described `ELB <name>` | TCP over the port profile |
| `rds` | `DescribeDBInstances` with `PubliclyAccessible`. The endpoint's DNS name is resolved, and an address counts only when a network interface described `RDSNetworkInterface` in the account holds it | TCP on the engine port |
| `opensearch` | Domains without VPC options | One HTTPS GET |
| `cloudfront` | `ListDistributions` (enabled), with tags | One HTTPS GET to `dxxx.cloudfront.net` |
| `apigw-rest`, `apigw-http`, `apigw-ws` | `GetRestApis` with a deployed stage (not private), `GetApis` | One HTTPS GET to the execute-api hostname |
| `lambda-url` | `ListFunctions`, `ListFunctionUrlConfigs`, and `GetPolicy` when AuthType is NONE, at most 15 calls a second | One HTTPS GET |
| `s3-website` | `ListBuckets`, `GetBucketWebsite`, `GetBucketPolicyStatus` | One HTTP GET to the website endpoint |
| `eks` | `DescribeCluster` with `endpointPublicAccess` | One HTTPS GET (401 or 403 is normal) |
| `lightsail` | `GetInstances`, `GetInstancePortStates` | TCP over the port profile |
| `nat`, `eip` | NAT gateway interfaces; Elastic IPs and Lightsail static IPs attached to nothing | None, listed only |

When a step fails (an API denied, a service not offered in a region), the scope is marked
incomplete: its endpoints stay as they were, and none of them is reported as removed.

## Why a port is reachable

The path analysis (`lambda/perimeter/paths.py`) works over one region's snapshot: VPCs and
their CIDRs, security groups and their rules, NACLs, route tables, internet gateways, prefix
lists, network interfaces, load balancers with listeners, target groups, target health and the
`preserve_client_ip.enabled` attribute.

**The internet** is any address outside RFC 1918, RFC 6598 (100.64.0.0/10), loopback,
link-local, multicast and the VPC's own CIDRs; for IPv6, global unicast (2000::/3). A rule
matters when its source contains any internet address: 0.0.0.0/0 does, 10.0.0.0/8 doesn't.

**Security groups.** Every ingress rule over TCP (or all traffic) with an internet source is a
grant for its port range. Customer-managed prefix lists are expanded to their entries. An
AWS-managed prefix list, such as CloudFront's origin-facing list, is named in a note ("tcp/443
reachable only from com.amazonaws.global.cloudfront.origin-facing"), not counted as the
internet. A rule referencing another security group is never an internet path.

**NACLs.** The subnet's NACL is evaluated in rule-number order for the port and the grant's
sources. Each entry takes the addresses it matches, so a deny on 0.0.0.0/1 before an allow on
0.0.0.0/0 still lets 128.0.0.0/1 in. Replies must leave on the client's ephemeral ports,
1024 to 65535: an outbound side that allows only part of that range makes the path partial.

**Routes.** The subnet's route table (its explicit association, or the VPC's main table) must
send replies to the client through an internet gateway attached to the VPC, by the most specific
matching route. A NAT gateway route means no inbound path. A route to a Gateway Load Balancer or
Network Firewall endpoint, a transit gateway, or ingress routing on the internet gateway, marks
the path unverified.

**Load balancers.** An ALB or CLB is reachable on its listener ports through its own security
groups and its subnets' NACLs and routes. An NLB without security groups admits everyone on its
listener ports. With client-IP preservation (on by default for instance targets, off for IP
targets over TCP and TLS), the target's security group and subnet NACL see the client's address
and must admit it too, by CIDR or, when the NLB has security groups, by a rule that references
them (the usual setup). The target's subnet needs no internet route: the load balancer carries
the replies. Without preservation the target sees the load balancer. Missing or unhealthy
targets are noted.

**Lightsail.** The instance's firewall (its port states) is the only control.

Each path is stored as a port range with its references, the source CIDR as written in the rule,
and whether it is verified or partial.

## The scanner

The scanner gets a batch:

```json
{
  "expires_at": 1793851200,
  "profile": "top1000", "extra": [2375, 5601], "rate": 100, "concurrency": 256, "timeout": 1.0,
  "targets": [{"endpoint_id": "self/eni/i-0abc", "ip": "203.0.113.10",
               "proof": "eni-0123 in 111111111111/us-east-1", "also": [40000]}],
  "not_scanned": [],
  "http": [{"endpoint_id": "self/cloudfront/E1", "url": "https://d111.cloudfront.net/", "host": "d111.cloudfront.net"}]
}
```

It refuses the batch once `expires_at` has passed, starts no connection attempt after it (the
ports it hadn't reached are listed as refused), and refuses any target without the planner's proof,
with an address that isn't global IPv4, or with an HTTP host that isn't an AWS hostname. The
ports for an address are the profile, `extra`, the critical ports (several aren't in the top
1,000), and `also`: ports an `expected` entry names and narrow path ranges outside the profile.
A database gets its engine port only. A target with a `range` gets only its ports in that
range: the planner splits an address across batches when its ports can't be scanned within
one batch's window.

Each connect is open when it completes, closed on a reset and filtered on a timeout or an
unreachable network. On an open port the scanner reads up to 256 bytes for half a second.
HTTP probes for managed fronts run first, and the port scan after them, never both at once. On
Lambda's share of a CPU, TLS handshakes on threads starve the event loop. A connection that
succeeded is then handled after its timeout fired, and an open port reads as filtered: seen in
the live test with 27 fronts in one batch.
Attempts on one address start no faster than `rate` per second, and a semaphore caps the
connections in flight across the batch at `concurrency`.

The planner sizes each batch from its worst case: every attempt held for the timeout plus the
banner read, paced by `rate` per address and by `concurrency` across the batch. The TCP scan
must fit in 8 minutes, leaving the rest of the 10-minute window to at most 10 HTTP probes and
invocation latency. At the default settings a batch holds up to 20 addresses. With the `all`
profile at 100 per second an address takes about 11 minutes, so it is split into two batches
of about 32,768 ports; lower rates or concurrency split it further. The ports come from Nmap's
`nmap-services` frequency ranking (`tools/gen_ports.py` regenerates `ports.py`).

## State and alerts

DynamoDB holds one item per endpoint (`endpoint#<id>`): the endpoint, its last scan in compact
form (open ports with banners and closed ports per address), its last HTTP probe, and its
verdicts at or above `min_severity`. Writes are conditional on the item's version, so two runs
judging the same endpoint at once can't lose each other's work; the loser re-reads and judges
again.

`diff` alerts on a new or changed verdict at or above `min_severity`, a verdict that falls
below it (resolved), a new endpoint, a removed endpoint, and a front whose HTTP status went
from 4xx to 2xx. An unchanged verdict never alerts again. More than five alerts for one account
in a run become one grouped message.

In baseline mode the judge stores the scans but no verdicts, sends one summary per daily run,
and writes `suggested-expected.tf`. The first enforce run then sees every verdict as new and
reports, once, each one that isn't expected.

Alerts go to the SNS topic as Amazon Q custom notifications (JSON for the Slack channel, plain
text for email subscribers).

## Tripwires

Each account's member module has EventBridge rules, one per event source per listed region,
plus CloudFront's in us-east-1, that match `AWS API Call via CloudTrail` events by event name
prefix (CloudTrail appends API versions to some names, such as `AddPermission20150331v2`). The
rules forward to the scanner's bus through the account's `<name>-forward` role. The bus policy
accepts events only from the listed accounts and only with those sources.

The tripwire function resolves any prefix list the event names (through the member role) and
judges the event (`lambda/perimeter/tripwire.py`). A change below `min_severity` stops there: the
hourly inventory sees its effect. Calls by AWS service principals or service-linked roles always
count as info. Otherwise, unless DynamoDB already marks the event id as sent, it publishes the
alert, starts a run named after the event id with a two-minute delay, and then marks the event
sent for a day. A failed publish leaves no mark, so Lambda's retry alerts again; a redelivery
that races the first delivery can alert twice. Step Functions treats a second start with the
same name and input as the same execution.
