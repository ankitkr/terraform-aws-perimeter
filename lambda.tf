# The functions need only boto3, which the Lambda runtime provides.
data "archive_file" "package" {
  type        = "zip"
  output_path = "${path.module}/.build/${var.name}.zip"

  dynamic "source" {
    for_each = toset(["app.py", "aws.py", "classify.py", "diff.py", "internet.py", "inventory.py", "model.py", "paths.py", "plan.py", "ports.py", "scanner.py", "tripwire.py"])
    content {
      filename = source.value
      content  = file("${path.module}/lambda/perimeter/${source.value}")
    }
  }
}

locals {
  functions = {
    planner = {
      description = "Lists public endpoints in every account and region, explains their paths, and plans the scan"
      memory      = 512
      timeout     = 900
    }
    scanner = {
      description = "Scans one batch of ownership-proven addresses; invoked only by the state machine"
      memory      = 256
      timeout     = 900
    }
    judge = {
      description = "Classifies scan results, diffs them against the last run, alerts and writes the inventory"
      memory      = 512
      timeout     = 300
    }
    tripwire = {
      description = "Judges CloudTrail events that can expose something to the internet, alerts, and starts a rescan"
      memory      = 256
      timeout     = 60
    }
  }
}

resource "aws_cloudwatch_log_group" "function" {
  for_each = local.functions

  name              = "/aws/lambda/${var.name}-${each.key}"
  retention_in_days = var.log_retention_days
  tags              = var.tags
}

resource "aws_lambda_function" "this" {
  for_each = local.functions

  function_name    = "${var.name}-${each.key}"
  description      = each.value.description
  role             = aws_iam_role.function[each.key].arn
  filename         = data.archive_file.package.output_path
  source_code_hash = data.archive_file.package.output_base64sha256
  handler          = "app.${each.key}"
  runtime          = "python3.14"
  architectures    = ["arm64"]
  memory_size      = each.value.memory
  timeout          = each.value.timeout

  # The scanner needs no configuration: everything it may touch arrives in the batch.
  dynamic "environment" {
    for_each = each.key == "scanner" ? [] : [1]
    content {
      variables = { TABLE_NAME = aws_dynamodb_table.this.name }
    }
  }

  tags       = var.tags
  depends_on = [aws_cloudwatch_log_group.function, aws_iam_role_policy.function]
}

# The only resource-policy grant on the scanner.
resource "aws_lambda_permission" "scanner" {
  statement_id  = "StateMachineOnly"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.this["scanner"].function_name
  principal     = aws_iam_role.states.arn
}

resource "aws_lambda_function_event_invoke_config" "tripwire" {
  function_name          = aws_lambda_function.this["tripwire"].function_name
  maximum_retry_attempts = 2
}
