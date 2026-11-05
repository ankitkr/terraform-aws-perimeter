output "role_arn" {
  description = "The read-only role the scanner assumes in this account."
  value       = aws_iam_role.member.arn
}

output "forward_role_arn" {
  description = "The role EventBridge uses to forward tripwire events to the scanner's bus."
  value       = aws_iam_role.forward.arn
}

output "rule_regions" {
  description = "Regions with tripwire rules."
  value       = sort(distinct([for r in local.rules : r.region]))
}
