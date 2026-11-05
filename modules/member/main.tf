# In each scanned account: a read-only role the scanner's planner and tripwire functions assume,
# and EventBridge rules that forward exposure-relevant CloudTrail events to the scanner's bus.

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

locals {
  partition = data.aws_partition.current.partition
  scanner   = "arn:${local.partition}:iam::${var.scanner_account_id}"
  bus_arn   = "arn:${local.partition}:events:${var.scanner_region}:${var.scanner_account_id}:event-bus/${var.name}"

  # One list of event names per source, shared with the tripwire function's judgments.
  events = jsondecode(file("${path.module}/events.json"))

  # Every source in every listed region; CloudFront's API lives in us-east-1 only.
  rules = merge(
    { for pair in setproduct(var.regions, [for s in keys(local.events) : s if s != "aws.cloudfront"]) : "${pair[0]}/${pair[1]}" => { region = pair[0], source = pair[1] } },
    { "us-east-1/aws.cloudfront" = { region = "us-east-1", source = "aws.cloudfront" } },
  )
}

# --- read-only role -----------------------------------------------------------------------------

# Trusts the scanner account and pins the callers by ARN, so this role can be created before (or
# in the same apply as) the scanner's roles without a dependency cycle.
resource "aws_iam_role" "member" {
  name        = "${var.name}-member"
  description = "Lets the perimeter scanner in ${var.scanner_account_id} list this account's public endpoints (read-only)"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { AWS = "${local.scanner}:root" }
      Condition = merge(
        { ArnEquals = { "aws:PrincipalArn" = ["${local.scanner}:role/${var.name}-planner", "${local.scanner}:role/${var.name}-tripwire"] } },
        var.external_id == null ? {} : { StringEquals = { "sts:ExternalId" = var.external_id } },
      )
    }]
  })
  tags = var.tags
}

# Named actions, not Describe*/Get*: those would include instance user data, Lightsail access
# details and API Gateway key values.
resource "aws_iam_role_policy" "member" {
  name = "perimeter-read"
  role = aws_iam_role.member.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Network"
        Effect = "Allow"
        Action = [
          "ec2:DescribeVpcs",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeSecurityGroupRules",
          "ec2:DescribeNetworkAcls",
          "ec2:DescribeRouteTables",
          "ec2:DescribeInternetGateways",
          "ec2:DescribeManagedPrefixLists",
          "ec2:GetManagedPrefixListEntries",
          "ec2:DescribeNetworkInterfaces",
          "ec2:DescribeInstances",
          "ec2:DescribeAddresses",
          "elasticloadbalancing:DescribeLoadBalancers",
          "elasticloadbalancing:DescribeListeners",
          "elasticloadbalancing:DescribeTargetGroups",
          "elasticloadbalancing:DescribeTargetHealth",
          "elasticloadbalancing:DescribeTargetGroupAttributes",
          "elasticloadbalancing:DescribeTags",
        ]
        Resource = "*"
      },
      {
        Sid    = "Services"
        Effect = "Allow"
        Action = [
          "cloudfront:ListDistributions",
          "cloudfront:ListTagsForResource",
          "lambda:ListFunctions",
          "lambda:ListFunctionUrlConfigs",
          "lambda:GetPolicy",
          "rds:DescribeDBInstances",
          "es:ListDomainNames",
          "es:DescribeDomains",
          "s3:ListAllMyBuckets",
          "s3:GetBucketLocation",
          "s3:GetBucketWebsite",
          "s3:GetBucketPolicyStatus",
          "eks:ListClusters",
          "eks:DescribeCluster",
          "lightsail:GetInstances",
          "lightsail:GetInstance",
          "lightsail:GetInstancePortStates",
          "lightsail:GetStaticIps",
        ]
        Resource = "*"
      },
      {
        Sid      = "ApiGatewayApis"
        Effect   = "Allow"
        Action   = ["apigateway:GET"]
        Resource = [for p in ["/restapis", "/restapis/*", "/apis", "/apis/*"] : "arn:${local.partition}:apigateway:*::${p}"]
      },
    ]
  })
}

# --- tripwire forwarding ------------------------------------------------------------------------

resource "aws_iam_role" "forward" {
  name        = "${var.name}-forward"
  description = "Lets EventBridge forward exposure-relevant CloudTrail events to the perimeter bus in ${var.scanner_account_id}"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "events.amazonaws.com" }
      Condition = { StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id } }
    }]
  })
  tags = var.tags
}

resource "aws_iam_role_policy" "forward" {
  name = "put-events"
  role = aws_iam_role.forward.id
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "events:PutEvents", Resource = local.bus_arn }]
  })
}

resource "aws_cloudwatch_event_rule" "tripwire" {
  for_each = local.rules

  region      = each.value.region
  name        = "${var.name}-${replace(each.value.source, "aws.", "")}"
  description = "Forward ${each.value.source} calls that can expose something to the internet"
  event_pattern = jsonencode({
    source        = [each.value.source]
    "detail-type" = ["AWS API Call via CloudTrail"]
    # Prefixes: CloudTrail appends API versions to some names (AddPermission20150331v2).
    detail = { eventName = [for n in local.events[each.value.source] : { prefix = n }] }
  })
  tags = var.tags
}

resource "aws_cloudwatch_event_target" "tripwire" {
  for_each = local.rules

  region   = each.value.region
  rule     = aws_cloudwatch_event_rule.tripwire[each.key].name
  arn      = local.bus_arn
  role_arn = aws_iam_role.forward.arn
}
