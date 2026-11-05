# Ready-to-run stack for the scanner account: copy terraform.tfvars.example to terraform.tfvars,
# fill it in, then `terraform init && terraform apply` from this directory. For every other
# account, apply deploy/member there.

terraform {
  required_version = ">= 1.10.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.41, < 7.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = ">= 2.4"
    }
  }

  # State is local (terraform.tfstate here) unless you add a backend; see backend.tf.example.
}

provider "aws" {
  region  = var.region
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

module "perimeter" {
  source = "../"

  regions                  = var.regions
  accounts                 = var.accounts
  account_name             = var.account_name
  mode                     = var.mode
  expected                 = var.expected
  undeclared               = var.undeclared
  min_severity             = var.min_severity
  alert_on_closed          = var.alert_on_closed
  scan                     = var.scan
  tag_prefix               = var.tag_prefix
  external_id              = var.external_id
  slack                    = var.slack
  chat_region              = var.chat_region
  sns_topic_arn            = var.sns_topic_arn
  alert_emails             = var.alert_emails
  name                     = var.name
  log_retention_days       = var.log_retention_days
  force_destroy            = var.force_destroy
  inventory_retention_days = var.inventory_retention_days
}
