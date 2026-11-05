# Tripwires: every account's rules (module.self here, the member module elsewhere) forward
# CloudTrail events to this bus, which only the listed accounts may write to.

locals {
  tripwire_sources = sort(keys(jsondecode(file("${path.module}/modules/member/events.json"))))
}

resource "aws_cloudwatch_event_bus" "this" {
  name = var.name
  tags = var.tags
}

resource "aws_cloudwatch_event_bus_policy" "this" {
  event_bus_name = aws_cloudwatch_event_bus.this.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "ListedAccountsForwardTripwireEvents"
      Effect    = "Allow"
      Action    = "events:PutEvents"
      Principal = { AWS = [for id in sort(distinct(values(local.accounts))) : "arn:${local.partition}:iam::${id}:root"] }
      Resource  = aws_cloudwatch_event_bus.this.arn
      Condition = { StringEquals = { "events:source" = local.tripwire_sources } }
    }]
  })
}

resource "aws_cloudwatch_event_rule" "tripwire" {
  name           = "${var.name}-tripwire"
  description    = "Forwarded CloudTrail calls that can expose something to the internet"
  event_bus_name = aws_cloudwatch_event_bus.this.name
  event_pattern = jsonencode({
    source        = local.tripwire_sources
    "detail-type" = ["AWS API Call via CloudTrail"]
  })
  tags = var.tags
}

resource "aws_cloudwatch_event_target" "tripwire" {
  rule           = aws_cloudwatch_event_rule.tripwire.name
  event_bus_name = aws_cloudwatch_event_bus.this.name
  arn            = aws_lambda_function.this["tripwire"].arn
}

resource "aws_lambda_permission" "tripwire" {
  statement_id  = "AllowTripwireBus"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.this["tripwire"].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.tripwire.arn
}

# --- schedules ----------------------------------------------------------------------------------

locals {
  schedules = {
    full      = { expression = var.scan.schedule, input = { mode = "full" }, description = "Inventory and scan everything" }
    inventory = { expression = var.scan.inventory_schedule, input = { mode = "inventory" }, description = "Inventory everything; scan what is new or changed" }
  }
}

resource "aws_cloudwatch_event_rule" "schedule" {
  for_each = local.schedules

  name                = "${var.name}-${each.key}"
  description         = each.value.description
  schedule_expression = each.value.expression
  tags                = var.tags
}

resource "aws_cloudwatch_event_target" "schedule" {
  for_each = local.schedules

  rule     = aws_cloudwatch_event_rule.schedule[each.key].name
  arn      = aws_sfn_state_machine.this.arn
  role_arn = aws_iam_role.schedule.arn
  input    = jsonencode(each.value.input)
}
