# One account, starting in baseline mode. After the first daily run, read
# s3://<bucket>/suggested-expected.tf, move its entries into `expected` with a reason each, and
# set mode = "enforce".

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.41, < 7.0"
    }
  }
}

provider "aws" {
  region = "eu-west-1"
}

module "perimeter" {
  source = "github.com/ankitkr/terraform-aws-perimeter?ref=v1.0.0"

  regions = ["eu-west-1"]
  mode    = "baseline"

  expected = {
    "self/alb/api-prod"         = { ports = [80, 443], reason = "public API" }
    "self/sg/sg-0123456789abcd" = { ports = [443], reason = "web tier" }
    "self/cloudfront/*"         = { ports = [443], reason = "the website" }
  }

  slack = {
    workspace_id = "T0123ABCD"
    channel_id   = "C0123ABCD"
  }
  alert_emails = ["security@example.com"]
}

output "inventory_url" {
  value = module.perimeter.inventory_url
}

# A resource can declare its own expectation with tags (the variable wins when both do):
#
#   perimeter:expected = "443,80"
#   perimeter:reason   = "public website"
