# The member submodule, planned against a mocked AWS provider.

mock_provider "aws" {
  mock_data "aws_caller_identity" {
    defaults = { account_id = "222222222222" }
  }
  mock_data "aws_partition" {
    defaults = { partition = "aws" }
  }
  mock_resource "aws_iam_role" {
    defaults = { arn = "arn:aws:iam::222222222222:role/perimeter-forward" }
  }
}

variables {
  scanner_account_id = "111111111111"
  scanner_region     = "eu-west-1"
  regions            = ["eu-west-1", "ap-south-1"]
}

run "trust_pins_the_scanner_roles_by_arn" {
  command = apply

  module {
    source = "./modules/member"
  }

  assert {
    condition     = jsondecode(aws_iam_role.member.assume_role_policy).Statement[0].Principal.AWS == "arn:aws:iam::111111111111:root"
    error_message = "The member role trusts the scanner account."
  }

  assert {
    condition = jsondecode(aws_iam_role.member.assume_role_policy).Statement[0].Condition == {
      ArnEquals = { "aws:PrincipalArn" = ["arn:aws:iam::111111111111:role/perimeter-planner", "arn:aws:iam::111111111111:role/perimeter-tripwire"] }
    }
    error_message = "Only the planner and tripwire roles may assume it, pinned with ArnEquals on aws:PrincipalArn."
  }

  assert {
    condition = alltrue([
      for s in jsondecode(aws_iam_role_policy.member.policy).Statement : alltrue([
        for a in s.Action : !endswith(a, "*") && !contains(["ec2:DescribeInstanceAttribute", "lightsail:GetInstanceAccessDetails", "apigateway:GET"], a) || (a == "apigateway:GET" && s.Sid == "ApiGatewayApis")
      ])
    ])
    error_message = "The member role reads with named actions only: no user data, no Lightsail access details, API Gateway limited to APIs."
  }
}

run "external_id_when_set" {
  command = apply

  module {
    source = "./modules/member"
  }

  variables {
    external_id = "perimeter-ext"
  }

  assert {
    condition     = jsondecode(aws_iam_role.member.assume_role_policy).Statement[0].Condition.StringEquals["sts:ExternalId"] == "perimeter-ext"
    error_message = "An external ID, when given, is required."
  }
}

run "tripwire_rules_per_region_and_cloudfront_in_us_east_1" {
  command = apply

  module {
    source = "./modules/member"
  }

  assert {
    condition     = aws_cloudwatch_event_rule.tripwire["us-east-1/aws.cloudfront"].region == "us-east-1"
    error_message = "CloudFront's events arrive in us-east-1, so its rule is there."
  }

  assert {
    condition     = length([for k, r in aws_cloudwatch_event_rule.tripwire : k if endswith(k, "/aws.cloudfront")]) == 1
    error_message = "CloudFront is watched in us-east-1 only."
  }

  assert {
    condition     = toset([for k, r in aws_cloudwatch_event_rule.tripwire : r.region]) == toset(["ap-south-1", "eu-west-1", "us-east-1"])
    error_message = "Rules live in every listed region, plus us-east-1."
  }

  assert {
    condition     = alltrue([for k, t in aws_cloudwatch_event_target.tripwire : t.arn == "arn:aws:events:eu-west-1:111111111111:event-bus/perimeter" && t.region == aws_cloudwatch_event_rule.tripwire[k].region])
    error_message = "Every rule forwards to the scanner's bus from its own region."
  }

  assert {
    condition     = contains(jsondecode(aws_cloudwatch_event_rule.tripwire["eu-west-1/aws.ec2"].event_pattern).detail.eventName, { prefix = "AuthorizeSecurityGroupIngress" })
    error_message = "Rules match event names by prefix."
  }

  assert {
    condition     = jsondecode(aws_iam_role_policy.forward.policy).Statement[0].Resource == "arn:aws:events:eu-west-1:111111111111:event-bus/perimeter"
    error_message = "The forwarding role may put events on the scanner's bus only."
  }
}
