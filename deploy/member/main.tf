# Ready-to-run stack for each scanned account other than the scanner's: copy
# terraform.tfvars.example to terraform.tfvars, fill it in from the scanner stack's `member`
# output, then `terraform init && terraform apply` with credentials for that account.

terraform {
  required_version = ">= 1.10.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.41, < 7.0"
    }
  }
}

provider "aws" {
  region  = var.scanner_region
  profile = var.aws_profile

  dynamic "assume_role" {
    for_each = var.assume_role_arn != null ? [1] : []
    content {
      role_arn = var.assume_role_arn
    }
  }

  default_tags {
    tags = var.tags
  }
}

module "member" {
  source = "../../modules/member"

  scanner_account_id = var.scanner_account_id
  scanner_region     = var.scanner_region
  name               = var.name
  regions            = var.regions
  external_id        = var.external_id
}

variable "scanner_account_id" {
  description = "The scanner stack's member.scanner_account_id."
  type        = string
}

variable "scanner_region" {
  description = "The scanner stack's member.scanner_region."
  type        = string
}

variable "regions" {
  description = "The scanner stack's member.regions."
  type        = list(string)
}

variable "name" {
  description = "The scanner stack's member.name."
  type        = string
  default     = "perimeter"
}

variable "external_id" {
  description = "The scanner stack's external_id, if set."
  type        = string
  default     = null
  sensitive   = true
}

variable "aws_profile" {
  description = "Named profile for this account. Null: the default credential chain."
  type        = string
  default     = null
}

variable "assume_role_arn" {
  description = "Role to assume in this account, if your credentials are for another one."
  type        = string
  default     = null
}

variable "tags" {
  description = "Tags on every resource."
  type        = map(string)
  default     = {}
}

output "role_arn" {
  description = "The read-only role the scanner assumes here."
  value       = module.member.role_arn
}
