# The scanner in a security account, and the member submodule in a workload account, from one
# root with two providers. Usually each account has its own stack; see deploy/ and deploy/member.

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.41, < 7.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

provider "aws" {
  alias  = "staging"
  region = "us-east-1"
  assume_role {
    role_arn = "arn:aws:iam::222222222222:role/OrganizationAccountAccessRole"
  }
}

module "perimeter" {
  source = "github.com/ankitkr/terraform-aws-perimeter?ref=v1.0.0"

  regions  = ["us-east-1", "ap-south-1"]
  accounts = { staging = "222222222222" }
  mode     = "enforce"

  expected = {
    "self/alb/api-prod"   = { ports = [80, 443], reason = "public API" }
    "staging/alb/api-stg" = { ports = [443], reason = "staging API, office only" }
    "staging/eni/i-*"     = { ports = [], reason = "nothing in staging answers directly" }
  }
  undeclared = "alert"

  scan = {
    ports       = "top1000"
    extra_ports = [2375, 5601, 9090, 11211]
    rate        = 100
  }

  alert_emails = ["security@example.com"]
}

module "perimeter_member" {
  source    = "github.com/ankitkr/terraform-aws-perimeter//modules/member?ref=v1.0.0"
  providers = { aws = aws.staging }

  scanner_account_id = module.perimeter.member.scanner_account_id
  scanner_region     = module.perimeter.member.scanner_region
  regions            = module.perimeter.member.regions
}
