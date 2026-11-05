variable "scanner_account_id" {
  description = "Account where the main perimeter module runs."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.scanner_account_id))
    error_message = "scanner_account_id is a 12-digit AWS account ID."
  }
}

variable "scanner_region" {
  description = "Region of the main module: its event bus receives this account's tripwire events."
  type        = string

  validation {
    condition     = can(regex("^[a-z]{2}(-[a-z]+)+-[0-9]$", var.scanner_region))
    error_message = "scanner_region is an AWS region name, e.g. us-east-1."
  }
}

variable "name" {
  description = "The main module's `name`. This account's roles are <name>-member and <name>-forward, and they trust the <name>-planner and <name>-tripwire roles in the scanner account."
  type        = string
  default     = "perimeter"

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{0,31}$", var.name))
    error_message = "name must be 1-32 lower-case letters, digits or hyphens, and match the main module's name."
  }
}

variable "regions" {
  description = "Regions to watch for tripwire events: the main module's regions. CloudFront's events are watched in us-east-1 as well."
  type        = list(string)

  validation {
    condition     = length(var.regions) > 0 && alltrue([for r in var.regions : can(regex("^[a-z]{2}(-[a-z]+)+-[0-9]$", r))])
    error_message = "regions must list at least one AWS region name, e.g. [\"us-east-1\"]."
  }
}

variable "external_id" {
  description = "Optional external ID the scanner must present when it assumes the member role. Set the same value as the main module's external_id."
  type        = string
  default     = null
}

variable "tags" {
  description = "Tags for every resource this module creates."
  type        = map(string)
  default     = {}
}
