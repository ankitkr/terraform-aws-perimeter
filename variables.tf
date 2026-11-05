variable "regions" {
  description = "Regions to inventory and watch in every account. CloudFront and S3 websites are listed once per account wherever they are."
  type        = list(string)

  validation {
    condition     = length(var.regions) > 0 && alltrue([for r in var.regions : can(regex("^[a-z]{2}(-[a-z]+)+-[0-9]$", r))])
    error_message = "regions must list at least one AWS region name, e.g. [\"us-east-1\"]."
  }
}

variable "accounts" {
  description = "Other accounts to scan, as { name = \"123456789012\" }. Each needs the member submodule applied in it. This account is always scanned, as account_name."
  type        = map(string)
  default     = {}
  nullable    = false

  validation {
    condition     = alltrue([for id in values(var.accounts) : can(regex("^[0-9]{12}$", id))])
    error_message = "Every value in accounts is a 12-digit AWS account ID."
  }

  validation {
    condition     = alltrue([for n in keys(var.accounts) : can(regex("^[a-z0-9][a-z0-9-]{0,31}$", n))])
    error_message = "Account names are 1-32 lower-case letters, digits or hyphens: they start every endpoint id."
  }

  validation {
    condition     = length(distinct(values(var.accounts))) == length(var.accounts)
    error_message = "Each account ID appears once in accounts: two names for one account would list its endpoints twice."
  }
}

variable "account_name" {
  description = "Name of this (the scanner's) account in endpoint ids, e.g. self/alb/api."
  type        = string
  default     = "self"

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{0,31}$", var.account_name))
    error_message = "account_name is 1-32 lower-case letters, digits or hyphens."
  }

  validation {
    condition     = !contains(keys(var.accounts), var.account_name)
    error_message = "account_name names this account; it can't also be a key in accounts."
  }
}

variable "mode" {
  description = "baseline: inventory, scan and write a suggested `expected` block, with one summary per daily run and no per-port alerts. enforce: alert on every difference from `expected`."
  type        = string
  default     = "baseline"

  validation {
    condition     = contains(["baseline", "enforce"], var.mode)
    error_message = "mode is \"baseline\" or \"enforce\"."
  }
}

variable "expected" {
  description = <<-EOT
    What should answer, keyed by glob. A key matches endpoint ids ("self/alb/api-prod",
    "staging/eni/i-*") or, when no key matches the id, the endpoint's security groups as
    "<account>/sg/<sg-id>" ("self/sg/sg-0abc*"). The first match in key order wins.

      ports  - TCP ports expected open; [] means nothing should answer
      reason - why, shown in alerts and the inventory document
  EOT
  type = map(object({
    ports  = list(number)
    reason = string
  }))
  default  = {}
  nullable = false

  validation {
    condition     = alltrue(flatten([for k, v in var.expected : [for p in v.ports : p >= 1 && p <= 65535 && floor(p) == p]]))
    error_message = "expected ports are whole numbers from 1 to 65535."
  }

  validation {
    condition     = alltrue([for k in keys(var.expected) : can(regex("^[a-z0-9*?\\[\\]-]+/[a-z0-9*?\\[\\]-]+/.+$", k))])
    error_message = "expected keys look like <account>/<kind>/<id>, with * and ? globs, e.g. \"self/alb/api-*\" or \"self/sg/sg-0abc*\"."
  }

  validation {
    condition     = alltrue([for v in values(var.expected) : trimspace(v.reason) != ""])
    error_message = "Every expected entry needs a reason."
  }
}

variable "undeclared" {
  description = "alert: an endpoint nothing in `expected` (or its tags) declares alerts per open port. report: it is noticed as a new endpoint, and its ports appear in the inventory document without alerts."
  type        = string
  default     = "alert"

  validation {
    condition     = contains(["alert", "report"], var.undeclared)
    error_message = "undeclared is \"alert\" or \"report\"."
  }
}

variable "min_severity" {
  description = "The lowest severity of a new or changed verdict that alerts: info, low, medium, high or critical. New and removed endpoints always alert."
  type        = string
  default     = "low"

  validation {
    condition     = contains(["info", "low", "medium", "high", "critical"], var.min_severity)
    error_message = "min_severity is info, low, medium, high or critical."
  }
}

variable "alert_on_closed" {
  description = "Raise an expected port that stopped answering from info to medium, so it alerts at the default min_severity."
  type        = bool
  default     = false
}

variable "scan" {
  description = <<-EOT
    How the scan runs.

      schedule           - full inventory and scan (EventBridge schedule expression, UTC)
      inventory_schedule - inventory only; new or changed endpoints are scanned. The silent-run
                           alarm allows three rate() intervals (3 hours for a cron())
      ports              - top100 | top1000 | all (Nmap's most frequently open TCP ports)
      extra_ports        - added to the profile; the critical ports are always scanned
      rate               - connection attempts per second, per address (1-500)
      concurrency        - connections in flight per scanner invocation (1-1024)
      timeout_ms         - per connection attempt (50-5000)
  EOT
  type = object({
    schedule           = optional(string, "cron(0 2 * * ? *)")
    inventory_schedule = optional(string, "rate(1 hour)")
    ports              = optional(string, "top1000")
    extra_ports        = optional(list(number), [])
    rate               = optional(number, 100)
    concurrency        = optional(number, 256)
    timeout_ms         = optional(number, 1000)
  })
  default  = {}
  nullable = false

  validation {
    condition     = contains(["top100", "top1000", "all"], var.scan.ports)
    error_message = "scan.ports is \"top100\", \"top1000\" or \"all\"."
  }

  validation {
    condition     = var.scan.rate >= 1 && var.scan.rate <= 500 && floor(var.scan.rate) == var.scan.rate
    error_message = "scan.rate is a whole number of attempts per second from 1 to 500."
  }

  validation {
    condition     = var.scan.concurrency >= 1 && var.scan.concurrency <= 1024 && var.scan.timeout_ms >= 50 && var.scan.timeout_ms <= 5000
    error_message = "scan.concurrency is 1-1024 and scan.timeout_ms is 50-5000."
  }

  validation {
    condition     = alltrue([for p in var.scan.extra_ports : p >= 1 && p <= 65535 && floor(p) == p])
    error_message = "scan.extra_ports are whole numbers from 1 to 65535."
  }

  validation {
    condition     = can(regex("^(cron|rate)\\(.+\\)$", var.scan.schedule)) && can(regex("^(cron|rate)\\(.+\\)$", var.scan.inventory_schedule))
    error_message = "scan.schedule and scan.inventory_schedule are EventBridge schedule expressions: cron(...) or rate(...)."
  }
}

variable "tag_prefix" {
  description = "Prefix of the tags that declare an expectation on a resource: <prefix>:expected = \"443,80\" and <prefix>:reason."
  type        = string
  default     = "perimeter"

  validation {
    condition     = can(regex("^[A-Za-z0-9_.-]{1,32}$", var.tag_prefix)) && !startswith(lower(var.tag_prefix), "aws")
    error_message = "tag_prefix is 1-32 letters, digits, '.', '_' or '-', and can't start with \"aws\"."
  }
}

variable "external_id" {
  description = "Optional external ID for assuming the member roles. Pass the same value to every member module."
  type        = string
  default     = null
  sensitive   = true
}

variable "slack" {
  description = <<-EOT
    The Slack channel for alerts, through Amazon Q Developer in chat applications. The workspace
    must be authorized once in the Amazon Q Developer console first. Null: alerts go to the SNS
    topic (and alert_emails) only.

      workspace_id - Slack workspace (team) ID, e.g. T0123ABCD
      channel_id   - Slack channel ID, e.g. C0123ABCD
  EOT
  type = object({
    workspace_id = string
    channel_id   = string
  })
  default = null

  validation {
    condition     = var.slack == null ? true : can(regex("^[0-9A-Z]{1,255}$", var.slack.workspace_id))
    error_message = "slack.workspace_id is the workspace ID shown in the Amazon Q Developer console, e.g. T0123ABCD."
  }

  validation {
    condition     = var.slack == null ? true : can(regex("^[A-Za-z0-9]{1,256}$", var.slack.channel_id))
    error_message = "slack.channel_id is the channel ID from the channel's link, e.g. C0123ABCD."
  }
}

variable "chat_region" {
  description = "Region of the CloudFormation stack that holds the Amazon Q Developer channel configuration. Null: the module's region."
  type        = string
  default     = null
}

variable "sns_topic_arn" {
  description = "An existing SNS topic to publish alerts and alarms to, instead of one the module creates."
  type        = string
  default     = null

  validation {
    condition     = var.sns_topic_arn == null ? true : can(regex("^arn:aws[a-z-]*:sns:[a-z0-9-]+:[0-9]{12}:.+$", var.sns_topic_arn))
    error_message = "sns_topic_arn is an SNS topic ARN."
  }
}

variable "alert_emails" {
  description = "Email addresses subscribed to the alert topic (each must confirm by email). They get every alert as plain text."
  type        = list(string)
  default     = []
  nullable    = false
}

variable "name" {
  description = "Prefix for every resource name. The member modules take the same value."
  type        = string
  default     = "perimeter"

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{0,31}$", var.name))
    error_message = "name is 1-32 lower-case letters, digits or hyphens (role names like <name>-planner and the bucket prefix derive from it)."
  }
}

variable "force_destroy" {
  description = "Let `terraform destroy` delete the inventory bucket while it still holds inventory documents (every version)."
  type        = bool
  default     = false
}

variable "log_retention_days" {
  description = "Retention of the module's Lambda logs, in days: one of CloudWatch Logs' allowed values (0 keeps them forever)."
  type        = number
  default     = 30

  validation {
    condition     = contains([0, 1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653], var.log_retention_days)
    error_message = "log_retention_days must be one of CloudWatch Logs' values: 0 (forever), 1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288 or 3653."
  }
}

variable "inventory_retention_days" {
  description = "Days to keep the dated inventory documents (inventory/<date>.json) and old versions of the others."
  type        = number
  default     = 90

  validation {
    condition     = var.inventory_retention_days >= 1 && floor(var.inventory_retention_days) == var.inventory_retention_days
    error_message = "inventory_retention_days is a whole number of days, at least 1."
  }
}

variable "tags" {
  description = "Tags for every resource the module creates."
  type        = map(string)
  default     = {}
}
