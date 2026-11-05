resource "aws_sns_topic" "this" {
  count = var.sns_topic_arn == null ? 1 : 0

  name = var.name
  tags = var.tags
}

# The module's CloudWatch alarms publish to the topic too. Principals in the account (the
# functions, Amazon Q's service-linked role) keep the access their IAM policies grant.
resource "aws_sns_topic_policy" "this" {
  count = var.sns_topic_arn == null ? 1 : 0

  arn = aws_sns_topic.this[0].arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "CloudWatchAlarms"
      Effect    = "Allow"
      Action    = "SNS:Publish"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Resource  = aws_sns_topic.this[0].arn
      Condition = { StringEquals = { "aws:SourceAccount" = local.account_id } }
    }]
  })
}

resource "aws_sns_topic_subscription" "email" {
  for_each = toset(var.alert_emails)

  topic_arn = local.topic_arn
  protocol  = "email"
  endpoint  = each.value
}
