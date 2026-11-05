output "topic_arn" {
  description = "SNS topic receiving alerts and the module's alarms."
  value       = local.topic_arn
}

output "bucket_name" {
  description = "Bucket holding inventory/latest.json, the dated inventories and suggested-expected.tf."
  value       = aws_s3_bucket.this.bucket
}

output "inventory_url" {
  description = "The current inventory document."
  value       = "s3://${aws_s3_bucket.this.bucket}/inventory/latest.json"
}

output "state_machine_arn" {
  description = "Start a run by hand: aws stepfunctions start-execution --state-machine-arn <this> --input '{\"full\": true}' (or {\"endpoints\": [\"self/alb/api\"]})."
  value       = aws_sfn_state_machine.this.arn
}

output "table_name" {
  description = "DynamoDB table holding the configuration and the last verdicts per endpoint."
  value       = aws_dynamodb_table.this.name
}

output "event_bus_arn" {
  description = "Event bus that receives tripwire events from every listed account."
  value       = aws_cloudwatch_event_bus.this.arn
}

output "planner_role_name" {
  description = "The role member accounts trust (with <name>-tripwire)."
  value       = aws_iam_role.function["planner"].name
}

output "member" {
  description = "Inputs for the member submodule in each other account."
  value = {
    scanner_account_id = local.account_id
    scanner_region     = local.region
    name               = var.name
    regions            = var.regions
  }
}
