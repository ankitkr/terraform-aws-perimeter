locals {
  lambda_trust = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })

  member_roles = [for id in distinct(values(local.accounts)) : "arn:${local.partition}:iam::${id}:role/${local.member_role_name}"]

  state_read  = { Sid = "State", Effect = "Allow", Action = ["dynamodb:GetItem", "dynamodb:Scan"], Resource = aws_dynamodb_table.this.arn }
  state_write = { Sid = "State", Effect = "Allow", Action = ["dynamodb:GetItem", "dynamodb:Scan", "dynamodb:PutItem", "dynamodb:DeleteItem"], Resource = aws_dynamodb_table.this.arn }
  notify      = { Sid = "Notify", Effect = "Allow", Action = ["sns:Publish"], Resource = local.topic_arn }
  assume      = { Sid = "AssumeMemberRoles", Effect = "Allow", Action = ["sts:AssumeRole"], Resource = local.member_roles }

  function_statements = {
    planner = [
      local.assume,
      local.state_read,
      { Sid = "RunDocuments", Effect = "Allow", Action = ["s3:PutObject"], Resource = "${aws_s3_bucket.this.arn}/runs/*" },
    ]
    # Logs only: the scanner touches nothing in AWS.
    scanner = []
    judge = [
      local.state_write,
      local.notify,
      { Sid = "ReadRuns", Effect = "Allow", Action = ["s3:GetObject"], Resource = "${aws_s3_bucket.this.arn}/runs/*" },
      { Sid = "WriteDocuments", Effect = "Allow", Action = ["s3:PutObject"], Resource = ["${aws_s3_bucket.this.arn}/inventory/*", "${aws_s3_bucket.this.arn}/suggested-expected.tf"] },
    ]
    tripwire = [
      local.assume,
      { Sid = "State", Effect = "Allow", Action = ["dynamodb:GetItem", "dynamodb:PutItem"], Resource = aws_dynamodb_table.this.arn },
      local.notify,
      { Sid = "Rescan", Effect = "Allow", Action = ["states:StartExecution"], Resource = local.state_machine_arn },
    ]
  }
}

resource "aws_iam_role" "function" {
  for_each = local.functions

  name               = "${var.name}-${each.key}"
  assume_role_policy = local.lambda_trust
  tags               = var.tags
}

resource "aws_iam_role_policy" "function" {
  for_each = local.functions

  name = each.key
  role = aws_iam_role.function[each.key].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat([
      {
        Sid      = "Logs"
        Effect   = "Allow"
        Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "${aws_cloudwatch_log_group.function[each.key].arn}:*"
      },
    ], local.function_statements[each.key])
  })
}

# --- the state machine --------------------------------------------------------------------------

resource "aws_iam_role" "states" {
  name = "${var.name}-states"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "states.amazonaws.com" }
      Condition = { StringEquals = { "aws:SourceAccount" = local.account_id } }
    }]
  })
  tags = var.tags
}

resource "aws_iam_role_policy" "states" {
  name = "invoke"
  role = aws_iam_role.states.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["lambda:InvokeFunction"]
      Resource = flatten([for f in ["planner", "scanner", "judge"] : [aws_lambda_function.this[f].arn, "${aws_lambda_function.this[f].arn}:*"]])
    }]
  })
}

# --- schedules ----------------------------------------------------------------------------------

resource "aws_iam_role" "schedule" {
  name = "${var.name}-schedule"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "events.amazonaws.com" }
      Condition = { StringEquals = { "aws:SourceAccount" = local.account_id } }
    }]
  })
  tags = var.tags
}

resource "aws_iam_role_policy" "schedule" {
  name = "start-runs"
  role = aws_iam_role.schedule.id
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["states:StartExecution"], Resource = local.state_machine_arn }]
  })
}
