data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_partition" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.region
  partition  = data.aws_partition.current.partition

  # This account is scanned like any other, under account_name.
  accounts = merge(var.accounts, { (var.account_name) = local.account_id })

  topic_arn = var.sns_topic_arn != null ? var.sns_topic_arn : aws_sns_topic.this[0].arn

  member_role_name = "${var.name}-member"

  # Built from the name: the tripwire function's policy needs it, and the state machine depends
  # on the functions.
  state_machine_arn = "arn:${local.partition}:states:${local.region}:${local.account_id}:stateMachine:${var.name}"

  # Read by the functions from DynamoDB: `expected` can outgrow an environment variable.
  config = {
    mode            = var.mode
    undeclared      = var.undeclared
    min_severity    = var.min_severity
    alert_on_closed = var.alert_on_closed
    # Pairs in key order: the first matching key wins.
    expected         = [for k in sort(keys(var.expected)) : [k, var.expected[k]]]
    tag_prefix       = var.tag_prefix
    accounts         = local.accounts
    self_account     = var.account_name
    regions          = var.regions
    member_role_name = local.member_role_name
    external_id      = var.external_id
    scan = {
      profile     = var.scan.ports
      extra_ports = var.scan.extra_ports
      rate        = var.scan.rate
      concurrency = var.scan.concurrency
      timeout     = var.scan.timeout_ms / 1000
    }
    bucket            = aws_s3_bucket.this.bucket
    sns_topic_arn     = local.topic_arn
    slack             = var.slack != null
    state_machine_arn = local.state_machine_arn
  }
}

# The module's own account gets the same read-only role and tripwire rules as a member account,
# so the planner reads every account the same way.
module "self" {
  source = "./modules/member"

  scanner_account_id = local.account_id
  scanner_region     = local.region
  name               = var.name
  regions            = var.regions
  external_id        = var.external_id
  tags               = var.tags

  depends_on = [aws_cloudwatch_event_bus.this]
}
