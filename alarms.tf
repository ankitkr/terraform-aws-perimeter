# A perimeter monitor that silently stops is worse than none. These make failures loud.

resource "aws_cloudwatch_metric_alarm" "runs_failed" {
  for_each = toset(["ExecutionsFailed", "ExecutionsTimedOut"])

  alarm_name          = "${var.name}-${lower(trimprefix(each.key, "Executions"))}-runs"
  alarm_description   = "A perimeter run ${each.key == "ExecutionsFailed" ? "failed" : "timed out"}: the inventory and alerts may be stale. See the state machine's execution history."
  namespace           = "AWS/States"
  metric_name         = each.key
  dimensions          = { StateMachineArn = aws_sfn_state_machine.this.arn }
  statistic           = "Sum"
  period              = 3600
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [local.topic_arn]
  tags                = var.tags
}

locals {
  # Three missed inventory runs: 3x a rate() schedule's interval. A cron() schedule has no fixed
  # interval to read, so it gets the hourly default's 3 hours.
  inventory_rate = try(regex("^rate\\((\\d+) (minute|hour|day)s?\\)$", var.scan.inventory_schedule), null)
  silent_seconds = local.inventory_rate == null ? 10800 : 3 * tonumber(local.inventory_rate[0]) * { minute = 60, hour = 3600, day = 86400 }[local.inventory_rate[1]]
  # CloudWatch evaluates at most a day in one period and at most seven days in all.
  silent_periods  = min(7, ceil(local.silent_seconds / 86400))
  silent_period   = local.silent_periods > 1 ? 86400 : local.silent_seconds
  silent_window   = local.silent_period * local.silent_periods
  silent_duration = local.silent_window >= 172800 ? "${local.silent_window / 86400} days" : local.silent_window % 3600 == 0 ? "${local.silent_window / 3600} hours" : "${local.silent_window / 60} minutes"
}

# Missing data breaches: a schedule that stopped firing looks the same as runs that all fail.
resource "aws_cloudwatch_metric_alarm" "runs_silent" {
  alarm_name          = "${var.name}-silent"
  alarm_description   = "No successful perimeter run in ${local.silent_duration}: inventory and alerts are stale."
  namespace           = "AWS/States"
  metric_name         = "ExecutionsSucceeded"
  dimensions          = { StateMachineArn = aws_sfn_state_machine.this.arn }
  statistic           = "Sum"
  period              = local.silent_period
  evaluation_periods  = local.silent_periods
  datapoints_to_alarm = local.silent_periods
  threshold           = 1
  comparison_operator = "LessThanThreshold"
  treat_missing_data  = "breaching"
  alarm_actions       = [local.topic_arn]
  ok_actions          = [local.topic_arn]
  tags                = var.tags
}

resource "aws_cloudwatch_metric_alarm" "function_errors" {
  for_each = local.functions

  alarm_name          = "${var.name}-${each.key}-errors"
  alarm_description   = "The perimeter ${each.key} function failed. See its logs."
  namespace           = "AWS/Lambda"
  metric_name         = "Errors"
  dimensions          = { FunctionName = aws_lambda_function.this[each.key].function_name }
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [local.topic_arn]
  tags                = var.tags
}
