# Slack through Amazon Q Developer in chat applications, for notifications only. The channel role
# can read what Amazon Q needs to render notifications and nothing else; the guardrail policy caps
# every channel member at the same.

locals {
  chat_configuration = var.slack == null ? null : "${var.name}-${substr(sha1("${var.slack.workspace_id}/${var.slack.channel_id}"), 0, 6)}"

  chat_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "NotificationDetails"
      Effect   = "Allow"
      Action   = ["cloudwatch:DescribeAlarms", "cloudwatch:GetMetricData", "cloudwatch:GetMetricWidgetImage"]
      Resource = "*"
    }]
  })
}

resource "aws_iam_role" "chat" {
  count = var.slack != null ? 1 : 0

  name = "${var.name}-chat"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "chatbot.amazonaws.com" }
      Condition = { StringEquals = { "aws:SourceAccount" = local.account_id } }
    }]
  })
  tags = var.tags
}

resource "aws_iam_role_policy" "chat" {
  count = var.slack != null ? 1 : 0

  name   = "notification-reads"
  role   = aws_iam_role.chat[0].id
  policy = local.chat_policy
}

resource "aws_iam_policy" "chat_guardrail" {
  count = var.slack != null ? 1 : 0

  name        = "${var.name}-chat-guardrail"
  description = "Channel guardrail for ${var.name}: notification reads only"
  policy      = local.chat_policy
  tags        = var.tags
}

# Amazon Q writes the channel's audit log here, always in us-east-1, and would otherwise create
# the group itself with no expiry. Created first, so Amazon Q finds it.
resource "aws_cloudwatch_log_group" "chat" {
  count = var.slack != null ? 1 : 0

  region            = "us-east-1"
  name              = "/aws/chatbot/${local.chat_configuration}"
  retention_in_days = var.log_retention_days
  tags              = var.tags
}

# A CloudFormation stack, as in terraform-aws-devboxes, so the configuration's lifecycle matches
# the sibling module's and both can share one Slack workspace authorization.
resource "aws_cloudformation_stack" "chat" {
  count = var.slack != null ? 1 : 0

  region = coalesce(var.chat_region, local.region)
  name   = "${var.name}-chat"
  template_body = jsonencode({
    AWSTemplateFormatVersion = "2010-09-09"
    Description              = "${var.name}: perimeter alerts in Slack through Amazon Q Developer"
    Resources = {
      Channel = {
        Type = "AWS::Chatbot::SlackChannelConfiguration"
        Properties = {
          # Workspace and channel in the name: changing either replaces the configuration, and the
          # replacement is created before the old one is deleted, so it needs a new name.
          ConfigurationName = local.chat_configuration
          SlackWorkspaceId  = var.slack.workspace_id
          SlackChannelId    = var.slack.channel_id
          IamRoleArn        = aws_iam_role.chat[0].arn
          GuardrailPolicies = [aws_iam_policy.chat_guardrail[0].arn]
          SnsTopicArns      = [local.topic_arn]
          LoggingLevel      = "INFO"
          UserRoleRequired  = false
        }
      }
    }
    Outputs = {
      ChannelArn = { Value = { Ref = "Channel" } }
    }
  })
  tags = var.tags

  depends_on = [aws_iam_role_policy.chat, aws_cloudwatch_log_group.chat]
}
