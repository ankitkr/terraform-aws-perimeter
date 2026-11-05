"""Tripwire judgments over CloudTrail events as EventBridge delivers them."""

import copy
import json
import os

import pytest

from model import AlertKind, Severity
from tripwire import EVENTS, alert, event_name, judge, prefix_list_ids

HERE = os.path.dirname(__file__)
EVENTS_JSON = os.path.join(HERE, "..", "modules", "member", "events.json")
SAMPLES = json.load(open(os.path.join(HERE, "fixtures", "cloudtrail.json")))

C, H, M, I = Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.INFO

# case -> (severity, text, resource, touched) or None when the event opens nothing.
CASES = {
    "sg_ingress_ssh_world": (C, "opened tcp/22 to 0.0.0.0/0", "sg-0abc1234 (sgr-0f00d)", ("sg-0abc1234",)),
    "sg_ingress_https_ipv6": (H, "opened tcp/443 to ::/0", "sg-0web (sgr-06)", ("sg-0web",)),
    "sg_ingress_private": None,
    "sg_ingress_group_ref": None,
    "sg_ingress_all_traffic": (C, "opened all traffic to 0.0.0.0/0", "sg-0debug (sgr-0a)", ("sg-0debug",)),
    "modify_sg_rule_rdp_world": (C, "opened tcp/3389 to 0.0.0.0/0", "sg-0win (sgr-0rdp)", ("sg-0win",)),
    "modify_sg_rule_to_office": None,
    "nacl_entry_ingress_world": (H, "allowed tcp/22 in from 0.0.0.0/0 (rule #90)", "acl-0123", ("acl-0123",)),
    "nacl_entry_egress_world": None,
    "replace_nacl_entry_deny": None,
    "replace_nacl_association": (I, "moved a subnet onto acl-0open", "acl-0open", ("acl-0open",)),
    "create_route_igw": (H, "routed 0.0.0.0/0 to igw-0abc", "rtb-0priv", ("rtb-0priv", "igw-0abc")),
    "create_route_nat": None,
    "replace_route_igw_ipv6": (H, "routed ::/0 to igw-0abc", "rtb-0priv", ("rtb-0priv", "igw-0abc")),
    "associate_route_table": (I, "associated subnet-0db with rtb-0pub", "rtb-0pub", ("rtb-0pub", "subnet-0db")),
    "replace_route_table_association": (I, "associated rtbassoc-0cc with rtb-0pub", "rtb-0pub", ("rtb-0pub",)),
    "attach_igw": (I, "attached igw-0new to vpc-0data", "vpc-0data", ("vpc-0data",)),
    "modify_instance_groupset": (I, "set the security groups of i-0abc to sg-0abc1234, sg-0debug", "i-0abc", ("i-0abc", "sg-0abc1234", "sg-0debug")),
    "modify_instance_type": None,
    "modify_eni_groups": (I, "set the security groups of eni-0abc to sg-0debug", "eni-0abc", ("eni-0abc", "sg-0debug")),
    "modify_subnet_public_ip": (I, "turned on public IPs at launch in subnet-0app", "subnet-0app", ("subnet-0app",)),
    "modify_subnet_public_ip_off": None,
    "run_instances_public": (M, "launched with a public IP", "i-0new", ("i-0new",)),
    "run_instances_private": None,
    "associate_address": (M, "attached eipalloc-0abc to i-0abc", "i-0abc", ("i-0abc",)),
    "create_alb_internet": (M, "created internet-facing load balancer api-prod", "api-prod", ("api-prod",)),
    "create_alb_internal": None,
    "create_clb_default_scheme": (M, "created internet-facing load balancer legacy-web", "legacy-web", ("legacy-web",)),
    "create_listener": (I, "added a listener on port 6379 on edge", "edge", ("edge",)),
    "set_security_groups": (I, "changed the security groups (sg-0debug) on api-prod", "api-prod", ("api-prod", "sg-0debug")),
    "apply_sgs_clb": (I, "changed the security groups (sg-0debug) on legacy-web", "legacy-web", ("legacy-web", "sg-0debug")),
    "create_function_url_none": (M, "gave function webhook a URL with AuthType NONE (public if its policy lets anyone invoke it)", "webhook", ("webhook",)),
    "update_function_url_iam": None,
    "add_permission_public_url": (H, "let anyone invoke function webhook's URL (FunctionURLAllowPublicAccess)", "webhook", ("webhook",)),
    "add_permission_s3": None,
    "create_db_public": (H, "made database reports publicly accessible", "reports", ("reports",)),
    "create_db_default_public": (H, "made database scratch publicly accessible", "scratch", ("scratch",)),
    "create_db_private": None,
    "modify_db_public": (H, "made database app publicly accessible", "app", ("app",)),
    "modify_db_class_only": None,
    "restore_db_snapshot_public": (H, "made database app-restore publicly accessible", "app-restore", ("app-restore",)),
    "opensearch_create_public": (M, "created OpenSearch domain logs with a public endpoint", "logs", ("logs",)),
    "opensearch_create_vpc": None,
    "opensearch_update_public": (I, "changed public OpenSearch domain logs", "logs", ("logs",)),
    "eks_create_default": (H, "opened the Kubernetes API of main to 0.0.0.0/0", "main", ("main",)),
    "eks_update_private": None,
    "eks_update_logging": None,
    "eks_update_office_cidr": (H, "opened the Kubernetes API of main to 198.51.100.0/24", "main", ("main",)),
    "eks_update_public_existing_cidrs": (H, "turned on the public Kubernetes API of main with its existing CIDRs", "main", ("main",)),
    "s3_put_website": (M, "turned on website hosting for bucket acme-site", "acme-site", ("acme-site",)),
    "s3_policy_public_read": (H, "gave bucket acme-site a policy that lets anyone read its objects", "acme-site", ("acme-site",)),
    "s3_policy_cloudfront_only": None,
    "s3_delete_pab": (M, "removed the public access block of bucket acme-site", "acme-site", ("acme-site",)),
    "s3_put_pab_off": (M, "turned off BlockPublicPolicy and RestrictPublicBuckets for bucket acme-site", "acme-site", ("acme-site",)),
    "s3_put_pab_on": None,
    "s3_put_account_pab_off": (M, "turned off BlockPublicPolicy and RestrictPublicBuckets for the account", "the account", ()),
    "s3_delete_account_pab": (M, "removed the account's S3 public access block", "the account", ()),
    "es_create_public": (M, "created OpenSearch domain legacy-logs with a public endpoint", "legacy-logs", ("legacy-logs",)),
    "es_update_public": (I, "changed public OpenSearch domain legacy-logs", "legacy-logs", ("legacy-logs",)),
    "cloudfront_create_with_tags": (I, "created CloudFront distribution d222222abcdef8.cloudfront.net (E3DOCSEXAMPLE)", "d222222abcdef8.cloudfront.net (E3DOCSEXAMPLE)", ("E3DOCSEXAMPLE",)),
    "create_db_replica_public": (H, "made database reports-replica publicly accessible", "reports-replica", ("reports-replica",)),
    "restore_db_pitr_default": (H, "made database app-pitr publicly accessible", "app-pitr", ("app-pitr",)),
    "restore_db_s3_private": None,
    "cloudfront_create": (I, "created CloudFront distribution d111111abcdef8.cloudfront.net (E2QWRUHEXAMPLE)", "d111111abcdef8.cloudfront.net (E2QWRUHEXAMPLE)", ("E2QWRUHEXAMPLE",)),
    "apigw_create_rest": (I, "created REST API orders (a1b2c3d4e5)", "orders (a1b2c3d4e5)", ("a1b2c3d4e5",)),
    "apigw_create_http": (I, "created API hooks (f6g7h8i9j0)", "hooks (f6g7h8i9j0)", ("f6g7h8i9j0",)),
    "apigw_create_stage": (I, "created API stage prod (a1b2c3d4e5)", "prod (a1b2c3d4e5)", ("a1b2c3d4e5",)),
    "lightsail_open_ports": (I, "opened tcp/3306-3306 to 0.0.0.0/0 on Lightsail blog", "blog", ("blog",)),
    "lightsail_put_ports": (I, "opened tcp/443-443 to 0.0.0.0/0; tcp/22-22 to 198.51.100.7/32 on Lightsail blog", "blog", ("blog",)),
    "failed_call": None,
}


def test_every_sample_has_an_expected_outcome():
    assert set(CASES) == set(SAMPLES) - {"sg_ingress_prefix_list"}


@pytest.mark.parametrize("case", sorted(CASES))
def test_judgment(case):
    finding = judge(SAMPLES[case])
    want = CASES[case]
    if want is None:
        assert finding is None
        return
    severity, text, resource, touched = want
    assert (finding.change.severity, finding.change.text, finding.change.resource, finding.change.touched) == (severity, text, resource, touched)


def test_every_listed_event_has_a_sample():
    sampled = {event_name(e["detail"]["eventName"]) for e in SAMPLES.values()}
    assert set(EVENTS) - sampled == set()


def test_terraform_rules_match_the_event_table():
    rules = json.load(open(EVENTS_JSON))
    from_table = {}
    for name, (source, _) in EVENTS.items():
        from_table.setdefault(source, set()).add(name)
    assert {s: set(names) for s, names in rules.items()} == from_table


def test_versioned_event_names_are_normalized():
    assert event_name("AddPermission20150331v2") == "AddPermission"
    assert event_name("CreateFunctionUrlConfig20211031") == "CreateFunctionUrlConfig"
    assert event_name("CreateDistribution2020_05_31") == "CreateDistribution"
    assert event_name("CreateRoute") == "CreateRoute"


def test_prefix_lists_are_resolved_before_judging():
    event = SAMPLES["sg_ingress_prefix_list"]
    assert prefix_list_ids(event) == ["pl-0office"]
    assert judge(event, {"pl-0office": ["10.0.0.0/8"]}) is None
    found = judge(event, {"pl-0office": ["10.0.0.0/8", "198.51.100.0/24"]})
    assert found.change.text == "opened tcp/8443 to pl-0office (prefix list with internet ranges)"
    unresolved = judge(event, None)
    assert unresolved.change.text == "opened tcp/8443 to pl-0office (prefix list, not resolved)"


@pytest.mark.parametrize(
    "case,caller",
    [
        ("sg_ingress_ssh_world", "alice@acme.com (AWSReservedSSO_AdministratorAccess_0123456789abcdef)"),
        ("sg_ingress_https_ipv6", "deploy-bot"),
        ("sg_ingress_all_traffic", "root"),
    ],
)
def test_the_caller_is_named(case, caller):
    assert judge(SAMPLES[case]).caller == caller


def test_the_alert_names_who_what_where_and_from():
    finding = judge(SAMPLES["sg_ingress_ssh_world"])
    a = alert(finding, "staging")
    assert a.kind is AlertKind.TRIPWIRE and a.severity is Severity.CRITICAL and a.account == "staging"
    assert a.title == ":rotating_light: AuthorizeSecurityGroupIngress in staging/ap-south-1"
    assert a.description == (
        "*alice@acme.com (AWSReservedSSO_AdministratorAccess_0123456789abcdef)* opened tcp/22 to 0.0.0.0/0 on sg-0abc1234 (sgr-0f00d), "
        "from 203.0.113.9. Rescanning in 2 min."
    )
    assert a.context["eventId"] == finding.event_id and finding.event_id


def test_a_resource_already_named_in_the_text_isnt_repeated():
    a = alert(judge(SAMPLES["create_alb_internet"]), "prod")
    assert a.description.count("api-prod") == 1


def test_calls_by_aws_service_linked_roles_are_info():
    # Live: ELB and RDS attach their own Elastic IPs; the human call that created them already alerted.
    event = copy.deepcopy(SAMPLES["associate_address"])
    human = judge(event)
    assert human.change.severity > Severity.INFO
    event["detail"]["userIdentity"]["sessionContext"]["sessionIssuer"]["arn"] = "arn:aws:iam::222222222222:role/aws-service-role/elasticloadbalancing.amazonaws.com/AWSServiceRoleForElasticLoadBalancing"
    assert judge(event).change.severity is Severity.INFO
    event["detail"]["userIdentity"] = {"type": "AWSService", "invokedBy": "rds.amazonaws.com"}
    assert judge(event).change.severity is Severity.INFO
