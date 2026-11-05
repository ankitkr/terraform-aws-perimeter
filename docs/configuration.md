# Configuration

## Main module inputs

| Input | Default | Meaning |
|---|---|---|
| `regions` | required | Regions to inventory and watch in every account. CloudFront and S3 websites are listed once per account regardless |
| `accounts` | `{}` | Other accounts as `{ name = "123456789012" }`. Names start endpoint ids. Each needs the member submodule |
| `account_name` | `"self"` | This account's name in endpoint ids |
| `mode` | `"baseline"` | `baseline` sends one summary per daily run and writes `suggested-expected.tf`; `enforce` alerts on differences |
| `expected` | `{}` | Glob keys to `{ ports, reason }`; see the README's [Declaring what should be open](../README.md#declaring-what-should-be-open) |
| `undeclared` | `"alert"` | `report` keeps endpoints nothing declares out of per-port alerts |
| `min_severity` | `"low"` | Lowest severity of a new or changed verdict that alerts: `info`, `low`, `medium`, `high`, `critical` |
| `alert_on_closed` | `false` | Raise expected-closed from info to medium |
| `scan.schedule` | `"cron(0 2 * * ? *)"` | The full run, as an EventBridge schedule expression in UTC |
| `scan.inventory_schedule` | `"rate(1 hour)"` | The inventory run. The silent-run alarm fires after three intervals of a `rate()` schedule without a successful run (counted in whole days, at most seven, past a day). A `cron()` schedule has no interval the module can read, so the alarm keeps 3 hours: with a cron schedule sparser than hourly, expect it to fire between runs |
| `scan.ports` | `"top1000"` | `top100`, `top1000` or `all` |
| `scan.extra_ports` | `[]` | Added to the profile |
| `scan.rate` | `100` | Attempts per second per address, 1 to 500 |
| `scan.concurrency` | `256` | Connections in flight per scanner invocation, 1 to 1024 |
| `scan.timeout_ms` | `1000` | Per connect, 50 to 5000 |
| `tag_prefix` | `"perimeter"` | Tags `<prefix>:expected` and `<prefix>:reason` |
| `external_id` | `null` | Required by the member roles when set; pass the same value to every member |
| `slack` | `null` | `{ workspace_id, channel_id }` for Amazon Q Developer |
| `chat_region` | module's region | Region of the channel's CloudFormation stack |
| `sns_topic_arn` | `null` | Publish to this existing topic instead of creating one |
| `alert_emails` | `[]` | Email subscriptions to the topic |
| `name` | `"perimeter"` | Prefix for every resource, 1 to 32 characters. Members take the same value |
| `log_retention_days` | `30` | Lambda and Amazon Q log retention |
| `force_destroy` | `false` | Let `terraform destroy` delete the inventory bucket while it holds inventory documents |
| `inventory_retention_days` | `90` | Dated inventory documents and old object versions |
| `tags` | `{}` | Tags on every resource |

Outputs: `topic_arn`, `bucket_name`, `inventory_url`, `state_machine_arn`, `table_name`,
`event_bus_arn`, `planner_role_name`, and `member`, which holds the inputs for each member
module.

## What the main module creates

In the scanner account and its region, unless noted:

- four Lambda functions, `<name>-planner`, `-scanner`, `-judge` and `-tripwire` (Python 3.14,
  arm64), with log groups and one IAM role each, named like the function;
- the `<name>` Step Functions state machine, its `<name>-states` role, and two EventBridge
  schedules with the `<name>-schedule` role;
- the `<name>` DynamoDB table (on demand, point-in-time recovery, TTL on `expires`) holding the
  configuration item and the per-endpoint state;
- an S3 bucket `<name>-<suffix>`: versioned, SSE-S3, public access blocked, TLS only, with
  lifecycle expiry;
- the `<name>` EventBridge bus, its policy, and a rule that sends tripwire events to the
  tripwire function;
- the `<name>` SNS topic (unless `sns_topic_arn`), email subscriptions, and CloudWatch alarms on
  failed, timed-out and missing runs and on each function's errors;
- with `slack`, the `<name>-chat` role and guardrail policy, a CloudFormation stack with the
  channel configuration, and the `/aws/chatbot/<name>-<hash>` log group in us-east-1;
- the member submodule for this account itself (`<name>-member`, `<name>-forward`, and the
  tripwire rules in each listed region and us-east-1).

## Deployer permissions

Applying the main module needs, in the scanner account: IAM roles, role policies and one managed
policy (`iam:CreateRole`, `PutRolePolicy`, `CreatePolicy`, `PassRole` for the roles it creates);
Lambda; Step Functions; DynamoDB; S3; EventBridge rules, targets, buses and bus policies in
each listed region and us-east-1; SNS; CloudWatch alarms; CloudWatch Logs (in us-east-1 too,
with Slack); and CloudFormation plus `chatbot:*` with Slack. An administrator role in the
security account is the simple choice.

The member submodule needs IAM roles and role policies, and EventBridge rules and targets in
each listed region and us-east-1.

## Member accounts

Apply `modules/member` (or `deploy/member`) in every account in `accounts`, with values from the
main module's `member` output:

```hcl
module "perimeter_member" {
  source = "github.com/ankitkr/terraform-aws-perimeter//modules/member?ref=v1.0.0"

  scanner_account_id = "111111111111"   # member.scanner_account_id
  scanner_region     = "us-east-1"      # member.scanner_region
  regions            = ["us-east-1", "ap-south-1"]
  # name             = "perimeter"      # when the main module's name isn't the default
  # external_id      = "..."            # when the main module sets one
}
```

It creates:

- `<name>-member`, a read-only role. It trusts the scanner account's root, but only for the
  `<name>-planner` and `<name>-tripwire` roles (`ArnEquals` on `aws:PrincipalArn`), and the
  external ID when one is set. It reads with named actions rather than `Describe*`. The
  inventory needs listings that also return Lambda environment variables, CloudFront origin
  custom headers and API Gateway stage variables, so the role can read those; it can't read
  instance user data, Lightsail access details, API Gateway API keys or S3 object contents;
- `<name>-forward`, which EventBridge uses to put events on the scanner's bus and nothing else;
- one EventBridge rule per event source in each listed region, and CloudFront's in us-east-1.

The member and main modules can be applied in either order. Until a member is applied, the
planner can't assume its role, so that account's scopes are marked incomplete in the inventory
document and nothing in them is reported.

## Tripwires need CloudTrail

EventBridge receives `AWS API Call via CloudTrail` events only from accounts with a trail
logging management events. An organization trail covers every account. Check with:

```sh
aws cloudtrail describe-trails --query 'trailList[].[Name,IsOrganizationTrail,IsMultiRegionTrail]'
```
