# Plans the module against a mocked AWS provider: no credentials, nothing created.

mock_provider "aws" {
  mock_data "aws_caller_identity" {
    defaults = { account_id = "111111111111" }
  }
  mock_data "aws_region" {
    defaults = { region = "eu-west-1" }
  }
  mock_data "aws_partition" {
    defaults = { partition = "aws" }
  }
  mock_resource "aws_lambda_function" {
    defaults = { arn = "arn:aws:lambda:eu-west-1:111111111111:function:perimeter-fn" }
  }
  mock_resource "aws_iam_role" {
    defaults = { arn = "arn:aws:iam::111111111111:role/perimeter-role" }
  }
  mock_resource "aws_iam_policy" {
    defaults = { arn = "arn:aws:iam::111111111111:policy/perimeter-chat-guardrail" }
  }
  mock_resource "aws_sns_topic" {
    defaults = { arn = "arn:aws:sns:eu-west-1:111111111111:perimeter" }
  }
  mock_resource "aws_sfn_state_machine" {
    defaults = { arn = "arn:aws:states:eu-west-1:111111111111:stateMachine:perimeter" }
  }
  mock_resource "aws_cloudwatch_event_bus" {
    defaults = { arn = "arn:aws:events:eu-west-1:111111111111:event-bus/perimeter" }
  }
  mock_resource "aws_cloudwatch_event_rule" {
    defaults = { arn = "arn:aws:events:eu-west-1:111111111111:rule/perimeter" }
  }
  mock_resource "aws_cloudwatch_log_group" {
    defaults = { arn = "arn:aws:logs:eu-west-1:111111111111:log-group:/aws/lambda/perimeter" }
  }
  mock_resource "aws_dynamodb_table" {
    defaults = { arn = "arn:aws:dynamodb:eu-west-1:111111111111:table/perimeter" }
  }
  mock_resource "aws_s3_bucket" {
    defaults = { arn = "arn:aws:s3:::perimeter-abc", bucket = "perimeter-abc" }
  }
}

override_resource {
  target = aws_iam_role.states
  values = { arn = "arn:aws:iam::111111111111:role/perimeter-states" }
}

variables {
  regions  = ["eu-west-1", "ap-south-1"]
  accounts = { staging = "222222222222" }
  expected = {
    "self/sg/sg-0abc*" = { ports = [443], reason = "web tier" }
    "self/alb/api-*"   = { ports = [80, 443], reason = "public API" }
  }
  slack = {
    workspace_id = "T0123ABCD"
    channel_id   = "C0123ABCD"
  }
}

run "scanner_is_invocable_only_by_the_state_machine" {
  command = apply

  assert {
    condition     = aws_lambda_permission.scanner.principal == "arn:aws:iam::111111111111:role/perimeter-states" && aws_lambda_permission.scanner.function_name == aws_lambda_function.this["scanner"].function_name
    error_message = "The scanner's only resource-policy grant is to the state machine's role."
  }

  assert {
    condition     = aws_lambda_permission.tripwire.function_name == aws_lambda_function.this["tripwire"].function_name
    error_message = "The event bus may invoke the tripwire function, never the scanner."
  }

  assert {
    condition     = length(jsondecode(aws_iam_role_policy.function["scanner"].policy).Statement) == 1 && jsondecode(aws_iam_role_policy.function["scanner"].policy).Statement[0].Sid == "Logs"
    error_message = "The scanner's role may write its logs and nothing else."
  }

  assert {
    condition = (
      jsondecode(aws_iam_role_policy.states.policy).Statement[0].Action == ["lambda:InvokeFunction"] &&
      length(jsondecode(aws_iam_role_policy.states.policy).Statement[0].Resource) == 6
    )
    error_message = "The state machine invokes the planner, scanner and judge (and their versions) only."
  }
}

run "bus_accepts_the_listed_accounts_only" {
  command = apply

  assert {
    condition = jsondecode(aws_cloudwatch_event_bus_policy.this.policy).Statement[0].Principal.AWS == [
      "arn:aws:iam::111111111111:root",
      "arn:aws:iam::222222222222:root",
    ]
    error_message = "Only this account and the listed accounts may put events on the bus."
  }

  assert {
    condition     = contains(jsondecode(aws_cloudwatch_event_bus_policy.this.policy).Statement[0].Condition.StringEquals["events:source"], "aws.ec2") && !contains(jsondecode(aws_cloudwatch_event_bus_policy.this.policy).Statement[0].Condition.StringEquals["events:source"], "aws.iam")
    error_message = "The bus accepts only the tripwire sources."
  }

  assert {
    condition = alltrue([
      for s in jsondecode(aws_iam_role_policy.function["planner"].policy).Statement :
      s.Sid != "AssumeMemberRoles" || toset(s.Resource) == toset(["arn:aws:iam::111111111111:role/perimeter-member", "arn:aws:iam::222222222222:role/perimeter-member"])
    ])
    error_message = "The planner may assume the member role in the listed accounts and its own, nothing else."
  }
}

run "configuration_for_the_functions" {
  command = apply

  assert {
    condition = jsondecode(jsondecode(aws_dynamodb_table_item.config.item).json.S).expected == [
      ["self/alb/api-*", { ports = [80, 443], reason = "public API" }],
      ["self/sg/sg-0abc*", { ports = [443], reason = "web tier" }],
    ]
    error_message = "expected reaches the functions as pairs in key order."
  }

  assert {
    condition     = jsondecode(jsondecode(aws_dynamodb_table_item.config.item).json.S).accounts == { self = "111111111111", staging = "222222222222" }
    error_message = "This account is always scanned, as account_name."
  }

  assert {
    condition     = jsondecode(jsondecode(aws_dynamodb_table_item.config.item).json.S).scan == { profile = "top1000", extra_ports = [], rate = 100, concurrency = 256, timeout = 1 }
    error_message = "The scan defaults are top1000 at 100 attempts per second with a one-second timeout."
  }

  assert {
    condition     = jsondecode(jsondecode(aws_dynamodb_table_item.config.item).json.S).mode == "baseline"
    error_message = "A new deployment starts in baseline mode."
  }
}

run "one_run_plans_scans_then_judges" {
  command = apply

  assert {
    condition = (
      jsondecode(aws_sfn_state_machine.this.definition).States.Scan.ItemsPath == "$.batches" &&
      jsondecode(aws_sfn_state_machine.this.definition).States.Scan.ItemProcessor.ProcessorConfig.Mode == "INLINE" &&
      jsondecode(aws_sfn_state_machine.this.definition).States.Plan.Parameters.Payload["execution.$"] == "$$.Execution.Name" &&
      jsondecode(aws_sfn_state_machine.this.definition).States.Wait.SecondsPath == "$.delay"
    )
    error_message = "Plan, an inline Map over the batches, then judge; a tripwire run waits first."
  }

  assert {
    condition = (
      jsondecode(aws_sfn_state_machine.this.definition).States.Scan.ItemProcessor.StartAt == "Verify batch" &&
      jsondecode(aws_sfn_state_machine.this.definition).States.Scan.ItemProcessor.States["Verify batch"].Parameters.Payload["verify.$"] == "$" &&
      jsondecode(aws_sfn_state_machine.this.definition).States.Scan.ItemProcessor.States["Verify batch"].Next == "Scan batch"
    )
    error_message = "Each batch re-verifies its addresses' ownership right before it scans."
  }

  assert {
    condition     = aws_cloudwatch_event_target.schedule["full"].input == jsonencode({ mode = "full" }) && aws_cloudwatch_event_rule.schedule["full"].schedule_expression == "cron(0 2 * * ? *)" && aws_cloudwatch_event_rule.schedule["inventory"].schedule_expression == "rate(1 hour)"
    error_message = "A daily full run and an hourly inventory run."
  }
}

run "slack_channel_for_notifications_only" {
  command = apply

  assert {
    condition     = jsondecode(aws_cloudformation_stack.chat[0].template_body).Resources.Channel.Properties.ConfigurationName == "perimeter-4a2aa4"
    error_message = "The channel configuration is named after the module and a hash of its workspace and channel."
  }

  assert {
    condition     = keys(jsondecode(aws_cloudformation_stack.chat[0].template_body).Resources) == ["Channel"]
    error_message = "No custom actions: v1 is notifications only."
  }

  assert {
    condition     = [for s in jsondecode(aws_iam_policy.chat_guardrail[0].policy).Statement : s.Action] == [["cloudwatch:DescribeAlarms", "cloudwatch:GetMetricData", "cloudwatch:GetMetricWidgetImage"]]
    error_message = "The channel may read only what Amazon Q needs to render notifications."
  }

  assert {
    condition     = aws_cloudwatch_log_group.chat[0].region == "us-east-1" && aws_cloudwatch_log_group.chat[0].name == "/aws/chatbot/perimeter-4a2aa4"
    error_message = "Amazon Q's audit log group is created in us-east-1 under the configuration's name."
  }
}

run "rate_is_capped" {
  command = plan

  variables {
    scan = { rate = 501 }
  }

  expect_failures = [var.scan]
}

run "mode_is_baseline_or_enforce" {
  command = plan

  variables {
    mode = "alert"
  }

  expect_failures = [var.mode]
}

run "account_ids_are_twelve_digits" {
  command = plan

  variables {
    accounts = { staging = "2222" }
  }

  expect_failures = [var.accounts]
}

run "regions_are_required" {
  command = plan

  variables {
    regions = []
  }

  expect_failures = [var.regions]
}

run "account_name_isnt_also_a_listed_account" {
  command = plan

  variables {
    accounts = { self = "222222222222" }
  }

  expect_failures = [var.account_name]
}

run "account_ids_are_listed_once" {
  command = plan

  variables {
    accounts = { staging = "222222222222", stage = "222222222222" }
  }

  expect_failures = [var.accounts]
}

run "this_account_isnt_listed_under_another_name" {
  command = plan

  variables {
    accounts = { staging = "222222222222", me = "111111111111" }
  }

  expect_failures = [aws_dynamodb_table_item.config]
}

run "silent_alarm_waits_three_hourly_runs" {
  command = plan

  assert {
    condition     = aws_cloudwatch_metric_alarm.runs_silent.period == 10800 && aws_cloudwatch_metric_alarm.runs_silent.evaluation_periods == 1 && strcontains(aws_cloudwatch_metric_alarm.runs_silent.alarm_description, "in 3 hours")
    error_message = "With the hourly default, three missed runs raise the silent alarm."
  }
}

run "silent_alarm_follows_a_faster_inventory_rate" {
  command = plan

  variables {
    scan = { inventory_schedule = "rate(15 minutes)" }
  }

  assert {
    condition     = aws_cloudwatch_metric_alarm.runs_silent.period == 2700 && strcontains(aws_cloudwatch_metric_alarm.runs_silent.alarm_description, "in 45 minutes")
    error_message = "Three missed runs of a 15-minute schedule are 45 minutes."
  }
}

run "silent_alarm_spans_days_for_a_daily_inventory" {
  command = plan

  variables {
    scan = { inventory_schedule = "rate(1 day)" }
  }

  assert {
    condition     = aws_cloudwatch_metric_alarm.runs_silent.period == 86400 && aws_cloudwatch_metric_alarm.runs_silent.evaluation_periods == 3 && aws_cloudwatch_metric_alarm.runs_silent.datapoints_to_alarm == 3
    error_message = "A daily schedule is watched over three one-day periods, within CloudWatch's limits."
  }
}

run "silent_alarm_keeps_three_hours_for_a_cron_inventory" {
  command = plan

  variables {
    scan = { inventory_schedule = "cron(0 * * * ? *)" }
  }

  assert {
    condition     = aws_cloudwatch_metric_alarm.runs_silent.period == 10800
    error_message = "A cron schedule has no interval to read: three hours."
  }
}
