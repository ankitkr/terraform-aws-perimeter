# One run: plan, scan the batches (at most four at a time), judge. A tripwire's run waits first,
# so the change it reacts to has settled. Each batch re-verifies its addresses' ownership right
# before it scans, so a batch that waits for a free slot never scans on a stale proof.

locals {
  lambda_retry = [{
    ErrorEquals     = ["Lambda.ServiceException", "Lambda.AWSLambdaException", "Lambda.SdkClientException", "Lambda.TooManyRequestsException"]
    IntervalSeconds = 5
    MaxAttempts     = 3
    BackoffRate     = 2
  }]

  definition = {
    Comment        = "${var.name}: inventory, scan and judge the perimeter"
    StartAt        = "Delayed?"
    TimeoutSeconds = 3600
    States = {
      "Delayed?" = {
        Type    = "Choice"
        Choices = [{ Variable = "$.delay", IsPresent = true, Next = "Wait" }]
        Default = "Plan"
      }
      Wait = { Type = "Wait", SecondsPath = "$.delay", Next = "Plan" }
      Plan = {
        Type     = "Task"
        Resource = "arn:${local.partition}:states:::lambda:invoke"
        Parameters = {
          FunctionName = aws_lambda_function.this["planner"].arn
          Payload      = { "input.$" = "$", "execution.$" = "$$.Execution.Name" }
        }
        ResultSelector = { "run.$" = "$.Payload.run", "batches.$" = "$.Payload.batches" }
        Retry          = local.lambda_retry
        TimeoutSeconds = 900
        Next           = "Scan"
      }
      Scan = {
        Type           = "Map"
        ItemsPath      = "$.batches"
        MaxConcurrency = 4
        ItemProcessor = {
          ProcessorConfig = { Mode = "INLINE" }
          StartAt         = "Verify batch"
          States = {
            "Verify batch" = {
              Type           = "Task"
              Resource       = "arn:${local.partition}:states:::lambda:invoke"
              Parameters     = { FunctionName = aws_lambda_function.this["planner"].arn, Payload = { "verify.$" = "$" } }
              OutputPath     = "$.Payload"
              Retry          = local.lambda_retry
              TimeoutSeconds = 300
              Next           = "Scan batch"
            }
            "Scan batch" = {
              Type           = "Task"
              Resource       = "arn:${local.partition}:states:::lambda:invoke"
              Parameters     = { FunctionName = aws_lambda_function.this["scanner"].arn, "Payload.$" = "$" }
              OutputPath     = "$.Payload"
              Retry          = local.lambda_retry
              TimeoutSeconds = 900
              End            = true
            }
          }
        }
        ResultPath = "$.results"
        Next       = "Judge"
      }
      Judge = {
        Type     = "Task"
        Resource = "arn:${local.partition}:states:::lambda:invoke"
        Parameters = {
          FunctionName = aws_lambda_function.this["judge"].arn
          Payload      = { "run.$" = "$.run", "results.$" = "$.results" }
        }
        OutputPath     = "$.Payload"
        Retry          = local.lambda_retry
        TimeoutSeconds = 300
        End            = true
      }
    }
  }
}

resource "aws_sfn_state_machine" "this" {
  name       = var.name
  type       = "STANDARD"
  role_arn   = aws_iam_role.states.arn
  definition = jsonencode(local.definition)
  tags       = var.tags

  depends_on = [aws_iam_role_policy.states]
}
