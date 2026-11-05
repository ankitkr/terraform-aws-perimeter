variable "region" {
  description = "Region to deploy the scanner in."
  type        = string
}

variable "aws_profile" {
  description = "Named profile from ~/.aws/config. Leave null to use the default credential chain."
  type        = string
  default     = null
}

variable "assume_role_arn" {
  description = "Role to assume in the scanner account, if your credentials are for another one."
  type        = string
  default     = null
}

variable "regions" {
  description = "Regions to inventory and watch in every account."
  type        = list(string)
}

variable "accounts" {
  description = "Other accounts to scan, as { name = \"123456789012\" }; apply deploy/member in each."
  type        = map(string)
  default     = {}
}

variable "account_name" {
  description = "Name of this account in endpoint ids."
  type        = string
  default     = "self"
}

variable "mode" {
  description = "baseline first, then enforce."
  type        = string
  default     = "baseline"
}

variable "expected" {
  description = "See the module's expected variable."
  type = map(object({
    ports  = list(number)
    reason = string
  }))
  default = {}
}

variable "undeclared" {
  description = "alert or report."
  type        = string
  default     = "alert"
}

variable "min_severity" {
  description = "info, low, medium, high or critical."
  type        = string
  default     = "low"
}

variable "alert_on_closed" {
  description = "Alert when an expected port stops answering."
  type        = bool
  default     = false
}

variable "scan" {
  description = "See the module's scan variable."
  type = object({
    schedule           = optional(string, "cron(0 2 * * ? *)")
    inventory_schedule = optional(string, "rate(1 hour)")
    ports              = optional(string, "top1000")
    extra_ports        = optional(list(number), [])
    rate               = optional(number, 100)
    concurrency        = optional(number, 256)
    timeout_ms         = optional(number, 1000)
  })
  default = {}
}

variable "tag_prefix" {
  description = "Prefix of the expectation tags."
  type        = string
  default     = "perimeter"
}

variable "external_id" {
  description = "Optional external ID for the member roles."
  type        = string
  default     = null
  sensitive   = true
}

variable "slack" {
  description = "{ workspace_id, channel_id }, after authorizing the workspace in the Amazon Q Developer console. Null: alerts by SNS and email only."
  type = object({
    workspace_id = string
    channel_id   = string
  })
  default = null
}

variable "chat_region" {
  description = "Region of the Amazon Q Developer channel's CloudFormation stack. Null: the module's region."
  type        = string
  default     = null
}

variable "sns_topic_arn" {
  description = "An existing topic to publish to instead of one the module creates."
  type        = string
  default     = null
}

variable "alert_emails" {
  description = "Addresses subscribed to the alert topic (each must confirm by email)."
  type        = list(string)
  default     = []
}

variable "name" {
  description = "Prefix for every resource; the member stacks take the same value."
  type        = string
  default     = "perimeter"
}

variable "force_destroy" {
  description = "Let `terraform destroy` delete the inventory bucket while it still holds inventory documents."
  type        = bool
  default     = false
}

variable "log_retention_days" {
  description = "Retention of the module's Lambda logs."
  type        = number
  default     = 30
}

variable "inventory_retention_days" {
  description = "Days to keep dated inventory documents."
  type        = number
  default     = 90
}

variable "tags" {
  description = "Tags on every resource."
  type        = map(string)
  default     = {}
}
