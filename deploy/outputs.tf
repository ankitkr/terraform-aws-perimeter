output "inventory_url" {
  description = "The current inventory document."
  value       = module.perimeter.inventory_url
}

output "state_machine_arn" {
  description = "Start a run by hand with aws stepfunctions start-execution."
  value       = module.perimeter.state_machine_arn
}

output "topic_arn" {
  description = "SNS topic receiving alerts and alarms."
  value       = module.perimeter.topic_arn
}

output "member" {
  description = "Values for deploy/member in each other account."
  value       = module.perimeter.member
}
