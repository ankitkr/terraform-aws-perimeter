"""Inventory: the EC2 network against moto, every other kind against fakes with the APIs'
response shapes, and the ownership re-check."""

import json
import os

import boto3
import pytest
from helpers import Fake, client_error
from moto import mock_aws

import inventory
from inventory import Account, Throttle, disambiguate, discover_global, discover_region, verify_ownership
from model import Flag, Kind, OwnedIPv4

REGION = "us-east-1"
ACCOUNT_ID = "123456789012"


@pytest.fixture
def aws():
    os.environ.setdefault("AWS_DEFAULT_REGION", REGION)
    with mock_aws():
        yield


def account(clients):
    return Account("prod", ACCOUNT_ID, lambda service, region: clients.get(service) or EMPTY[service])


EMPTY = {
    "elbv2": Fake(describe_load_balancers={"LoadBalancers": []}),
    "elb": Fake(describe_load_balancers={"LoadBalancerDescriptions": []}),
    "rds": Fake(describe_db_instances={"DBInstances": []}),
    "opensearch": Fake(list_domain_names={"DomainNames": []}),
    "lambda": Fake(list_functions={"Functions": []}),
    "apigateway": Fake(get_rest_apis={"items": []}),
    "apigatewayv2": Fake(get_apis={"Items": []}),
    "eks": Fake(list_clusters={"clusters": []}),
    "lightsail": Fake(get_instances={"instances": []}, get_static_ips={"staticIps": []}),
    "cloudfront": Fake(list_distributions={"DistributionList": {"Items": []}}),
    "s3": Fake(list_buckets={"Buckets": []}),
}


def public_vpc(ec2, port=22):
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    subnet = ec2.create_subnet(VpcId=vpc, CidrBlock="10.0.1.0/24")["Subnet"]["SubnetId"]
    igw = ec2.create_internet_gateway()["InternetGateway"]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=igw, VpcId=vpc)
    rtb = ec2.describe_route_tables(Filters=[{"Name": "vpc-id", "Values": [vpc]}])["RouteTables"][0]["RouteTableId"]
    ec2.create_route(RouteTableId=rtb, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw)
    sg = ec2.create_security_group(GroupName="bastion", Description="ssh", VpcId=vpc)["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=sg, IpPermissions=[{"IpProtocol": "tcp", "FromPort": port, "ToPort": port, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    instance = ec2.run_instances(
        ImageId="ami-12c6146b",
        MinCount=1,
        MaxCount=1,
        NetworkInterfaces=[{"DeviceIndex": 0, "SubnetId": subnet, "Groups": [sg]}],
        TagSpecifications=[{"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": "bastion"}, {"Key": "perimeter:expected", "Value": "22"}]}],
    )["Instances"][0]["InstanceId"]
    eip = ec2.allocate_address(Domain="vpc")
    ec2.associate_address(AllocationId=eip["AllocationId"], InstanceId=instance)
    return dict(vpc=vpc, subnet=subnet, igw=igw, rtb=rtb, sg=sg, instance=instance, ip=eip["PublicIp"])


def test_an_instance_with_a_world_open_port_is_found_and_explained(aws):
    ec2 = boto3.client("ec2", region_name=REGION)
    v = public_vpc(ec2)
    ec2.allocate_address(Domain="vpc")  # unattached
    inv = discover_region(account({"ec2": ec2}), REGION)
    assert inv.problems == []
    eni_ep = next(e for e in inv.endpoints if e.kind is Kind.ENI)
    assert eni_ep.id == f"prod/eni/{v['instance']}"
    assert eni_ep.display == "bastion" and eni_ep.tags["perimeter:expected"] == "22"
    assert eni_ep.security_groups == (v["sg"],)
    [address] = eni_ep.addresses
    assert address.ip == v["ip"] and address.proof.startswith("eni-") and address.proof.endswith(f" in {ACCOUNT_ID}/{REGION}")
    [path] = eni_ep.paths
    assert path.ports == (22, 22) and path.cidr == "0.0.0.0/0" and path.verified
    assert path.refs[0].startswith(f"{v['sg']} rule sgr-") and path.refs[-1] == f"{v['rtb']} 0.0.0.0/0 → {v['igw']}"
    assert {v["vpc"], v["subnet"], v["rtb"], v["sg"]} <= set(eni_ep.network)
    assert [e.kind for e in inv.endpoints if e.kind is Kind.EIP] == [Kind.EIP]


def test_a_failing_step_marks_the_scope_incomplete_but_the_rest_continues(aws):
    ec2 = boto3.client("ec2", region_name=REGION)
    public_vpc(ec2)
    broken = Fake(describe_load_balancers=client_error("AccessDenied"))
    inv = discover_region(account({"ec2": ec2, "elbv2": broken}), REGION)
    assert inv.problems == ["prod/us-east-1 load balancers: AccessDenied"]
    assert any(e.kind is Kind.ENI for e in inv.endpoints)


# --- load balancers -----------------------------------------------------------------------------

LB_ARN = f"arn:aws:elasticloadbalancing:{REGION}:{ACCOUNT_ID}:loadbalancer/net/edge/7a3f"
TG_ARN = f"arn:aws:elasticloadbalancing:{REGION}:{ACCOUNT_ID}:targetgroup/web/1"


def nlb_world(ec2, preserve):
    v = public_vpc(ec2, port=443)
    eni = ec2.create_network_interface(SubnetId=v["subnet"], Description="ELB net/edge/7a3f", Groups=[])["NetworkInterface"]["NetworkInterfaceId"]
    eip = ec2.allocate_address(Domain="vpc")
    ec2.associate_address(AllocationId=eip["AllocationId"], NetworkInterfaceId=eni)
    elbv2 = Fake(
        describe_load_balancers={"LoadBalancers": [{"LoadBalancerArn": LB_ARN, "LoadBalancerName": "edge", "Scheme": "internet-facing", "Type": "network", "VpcId": v["vpc"], "AvailabilityZones": [{"ZoneName": "us-east-1a", "SubnetId": v["subnet"]}]}]},
        describe_tags={"TagDescriptions": [{"ResourceArn": LB_ARN, "Tags": [{"Key": "perimeter:expected", "Value": "443"}]}]},
        describe_target_groups={"TargetGroups": [{"TargetGroupArn": TG_ARN, "TargetGroupName": "web", "Protocol": "TCP", "Port": 443, "TargetType": "instance"}]},
        describe_target_health={"TargetHealthDescriptions": [{"Target": {"Id": v["instance"], "Port": 443}, "TargetHealth": {"State": "healthy"}}]},
        describe_target_group_attributes={"Attributes": [{"Key": "preserve_client_ip.enabled", "Value": preserve}]},
        describe_listeners={"Listeners": [{"ListenerArn": "l", "Port": 443, "Protocol": "TCP", "DefaultActions": [{"Type": "forward", "TargetGroupArn": TG_ARN, "ForwardConfig": {"TargetGroups": [{"TargetGroupArn": TG_ARN, "Weight": 1}]}}]}]},
    )
    return v, elbv2, eip["PublicIp"]


def test_nlb_addresses_come_from_its_enis_and_paths_reach_the_target(aws):
    ec2 = boto3.client("ec2", region_name=REGION)
    v, elbv2, ip = nlb_world(ec2, "true")
    inv = discover_region(account({"ec2": ec2, "elbv2": elbv2}), REGION)
    nlb = next(e for e in inv.endpoints if e.kind is Kind.NLB)
    assert nlb.id == "prod/nlb/edge" and nlb.tags == {"perimeter:expected": "443"}
    assert [a.ip for a in nlb.addresses] == [ip]
    assert [p.ports for p in nlb.paths] == [(443, 443)]
    assert any(f"web preserves client IP → {v['instance']}:443" == r for r in nlb.paths[0].refs)
    # The load balancer's own ENI isn't listed again as an instance-less ENI endpoint.
    assert [e.id for e in inv.endpoints if e.kind is Kind.ENI] == [f"prod/eni/{v['instance']}"]


def test_alb_and_clb_from_fakes():
    snap = inventory.paths.Snapshot()
    raw_enis = [{"NetworkInterfaceId": "eni-lb", "Description": "ELB legacy", "Association": {"PublicIp": "198.51.100.4"}}]
    elb = Fake(
        describe_load_balancers={"LoadBalancerDescriptions": [{"LoadBalancerName": "legacy", "Scheme": "internet-facing", "VPCId": "vpc-1", "Subnets": ["subnet-1"], "SecurityGroups": ["sg-1"], "ListenerDescriptions": [{"Listener": {"Protocol": "HTTP", "LoadBalancerPort": 80}}]}, {"LoadBalancerName": "inner", "Scheme": "internal"}]},
        describe_tags={"TagDescriptions": [{"LoadBalancerName": "legacy", "Tags": [{"Key": "Name", "Value": "legacy"}]}]},
    )
    [clb] = inventory.clb_endpoints(Account("prod", ACCOUNT_ID, None), REGION, elb, snap, raw_enis)
    assert clb.id == "prod/clb/legacy" and [a.ip for a in clb.addresses] == ["198.51.100.4"] and clb.addresses[0].proof == f"eni-lb in {ACCOUNT_ID}/{REGION}"


# --- databases, search, fronts ------------------------------------------------------------------


def test_public_rds_is_scanned_on_its_engine_port_only_when_an_eni_holds_the_address():
    raw_enis = [{"NetworkInterfaceId": "eni-db", "Description": "RDSNetworkInterface", "Association": {"PublicIp": "198.51.100.7"}}]
    dbs = {
        "DBInstances": [
            {"DBInstanceIdentifier": "reports", "PubliclyAccessible": True, "Endpoint": {"Address": "reports.abc.us-east-1.rds.amazonaws.com", "Port": 5432}, "VpcSecurityGroups": [{"VpcSecurityGroupId": "sg-db"}], "TagList": [{"Key": "team", "Value": "data"}]},
            {"DBInstanceIdentifier": "elsewhere", "PubliclyAccessible": True, "Endpoint": {"Address": "elsewhere.abc.us-east-1.rds.amazonaws.com", "Port": 3306}},
            {"DBInstanceIdentifier": "private", "PubliclyAccessible": False, "Endpoint": {"Address": "p", "Port": 5432}},
        ]
    }
    resolve = {"reports.abc.us-east-1.rds.amazonaws.com": ("x", [], ["198.51.100.7"]), "elsewhere.abc.us-east-1.rds.amazonaws.com": ("x", [], ["203.0.113.99"])}.__getitem__
    reports, elsewhere = inventory.rds_endpoints(Account("prod", ACCOUNT_ID, None), REGION, Fake(describe_db_instances=dbs), inventory.paths.Snapshot(), raw_enis, resolve)
    assert reports.probe.ports == (5432,) and reports.addresses == (OwnedIPv4("198.51.100.7", f"eni-db in {ACCOUNT_ID}/{REGION}"),)
    assert reports.tags == {"team": "data"} and reports.security_groups == ("sg-db",)
    assert elsewhere.probe is None and "no RDS network interface in this account holds" in elsewhere.notes[-1]


def test_an_rds_address_held_by_another_kind_of_interface_isnt_the_databases():
    # A stale DNS answer can name an address that is now an instance's Elastic IP.
    raw_enis = [{"NetworkInterfaceId": "eni-web", "Description": "", "Association": {"PublicIp": "198.51.100.7"}}]
    dbs = {"DBInstances": [{"DBInstanceIdentifier": "reports", "PubliclyAccessible": True, "Endpoint": {"Address": "reports.abc.us-east-1.rds.amazonaws.com", "Port": 5432}}]}
    [reports] = inventory.rds_endpoints(Account("prod", ACCOUNT_ID, None), REGION, Fake(describe_db_instances=dbs), inventory.paths.Snapshot(), raw_enis, lambda host: ("x", [], ["198.51.100.7"]))
    assert reports.probe is None and "no RDS network interface in this account holds" in reports.notes[-1]


def test_lambda_url_is_flagged_only_with_auth_none_and_a_public_policy():
    public = json.dumps({"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "lambda:InvokeFunctionUrl", "Resource": "x", "Condition": {"StringEquals": {"lambda:FunctionUrlAuthType": "NONE"}}}]})
    urls = {
        "hook": {"FunctionUrlConfigs": [{"FunctionUrl": "https://aaa.lambda-url.us-east-1.on.aws/", "FunctionArn": "arn:hook", "AuthType": "NONE"}]},
        "nopolicy": {"FunctionUrlConfigs": [{"FunctionUrl": "https://bbb.lambda-url.us-east-1.on.aws/", "AuthType": "NONE"}]},
        "iam": {"FunctionUrlConfigs": [{"FunctionUrl": "https://ccc.lambda-url.us-east-1.on.aws/", "AuthType": "AWS_IAM"}]},
        "none": {"FunctionUrlConfigs": []},
    }

    def policy(FunctionName):
        if FunctionName == "hook":
            return {"Policy": public}
        return client_error("ResourceNotFoundException")

    lam = Fake(list_functions={"Functions": [{"FunctionName": n} for n in urls]}, list_function_url_configs=lambda FunctionName: urls[FunctionName], get_policy=policy)
    found = inventory.lambda_url_endpoints(Account("prod", ACCOUNT_ID, None), REGION, lam, throttle=lambda: None)
    assert {e.id: e.flags for e in found} == {"prod/lambda-url/hook": frozenset({Flag.UNAUTHENTICATED_URL}), "prod/lambda-url/nopolicy": frozenset(), "prod/lambda-url/iam": frozenset()}
    assert found[0].probe.host == "aaa.lambda-url.us-east-1.on.aws"
    assert [c for c in lam.calls if c[0] == "get_policy"] == [("get_policy", {"FunctionName": "hook"}), ("get_policy", {"FunctionName": "nopolicy"})]


def test_api_gateway_rest_http_and_websocket():
    apigw = Fake(
        get_rest_apis={"items": [{"id": "a1", "name": "orders", "endpointConfiguration": {"types": ["REGIONAL"]}, "tags": {"perimeter:expected": "443"}}, {"id": "p1", "endpointConfiguration": {"types": ["PRIVATE"]}}, {"id": "u1", "endpointConfiguration": {"types": ["EDGE"]}}]},
        get_stages=lambda restApiId: {"item": [{"stageName": "prod"}]} if restApiId == "a1" else {"item": []},
    )
    v2 = Fake(get_apis={"Items": [{"ApiId": "h1", "Name": "hooks", "ProtocolType": "HTTP", "ApiEndpoint": "https://h1.execute-api.us-east-1.amazonaws.com"}, {"ApiId": "w1", "Name": "chat", "ProtocolType": "WEBSOCKET", "ApiEndpoint": "wss://w1.execute-api.us-east-1.amazonaws.com"}, {"ApiId": "d1", "ProtocolType": "HTTP", "ApiEndpoint": "https://d1", "DisableExecuteApiEndpoint": True}]})
    found = inventory.apigw_endpoints(Account("prod", ACCOUNT_ID, None), REGION, apigw, v2)
    assert [(e.id, e.probe.url) for e in found] == [
        ("prod/apigw-rest/a1", "https://a1.execute-api.us-east-1.amazonaws.com/prod/"),
        ("prod/apigw-http/h1", "https://h1.execute-api.us-east-1.amazonaws.com/"),
        ("prod/apigw-ws/w1", "https://w1.execute-api.us-east-1.amazonaws.com/"),
    ]
    assert found[0].tags == {"perimeter:expected": "443"}


@pytest.mark.parametrize("cidrs,flagged", [(None, True), (["0.0.0.0/0"], True), (["10.0.0.0/8"], False), (["198.51.100.0/24"], True)])
def test_eks_public_endpoint_is_flagged_for_internet_cidrs(cidrs, flagged):
    config = {"endpointPublicAccess": True, "vpcId": "vpc-1"}
    if cidrs is not None:
        config["publicAccessCidrs"] = cidrs
    eks = Fake(list_clusters={"clusters": ["main", "quiet"]}, describe_cluster=lambda name: {"cluster": {"name": name, "endpoint": "https://ABC.gr7.us-east-1.eks.amazonaws.com", "arn": "arn:eks", "resourcesVpcConfig": config if name == "main" else {"endpointPublicAccess": False}}})
    found = inventory.eks_endpoints(Account("prod", ACCOUNT_ID, None), REGION, eks)
    assert [e.id for e in found] == ["prod/eks/main"]
    assert (Flag.PUBLIC_API in found[0].flags) is flagged


def test_lightsail_instance_paths_and_unattached_static_ips():
    ls = Fake(
        get_instances={"instances": [{"name": "blog", "arn": "arn:ls", "publicIpAddress": "198.51.100.30", "tags": [{"key": "perimeter:expected", "value": "80,443"}]}]},
        get_instance_port_states={"portStates": [{"fromPort": 22, "toPort": 22, "protocol": "tcp", "state": "open", "cidrs": ["0.0.0.0/0"]}]},
        get_static_ips={"staticIps": [{"name": "spare", "ipAddress": "198.51.100.31", "isAttached": False}, {"name": "used", "isAttached": True}]},
    )
    blog, spare = inventory.lightsail_endpoints(Account("prod", ACCOUNT_ID, None), REGION, ls)
    assert blog.addresses == (OwnedIPv4("198.51.100.30", f"lightsail:blog in {ACCOUNT_ID}/{REGION}"),)
    assert blog.tags == {"perimeter:expected": "80,443"} and [p.ports for p in blog.paths] == [(22, 22)]
    assert spare.id == "prod/eip/lightsail-spare" and spare.probe is None


def test_global_cloudfront_and_s3_websites():
    cf = Fake(
        list_distributions={"DistributionList": {"Items": [{"Id": "E1", "ARN": "arn:cf:E1", "DomainName": "d111.cloudfront.net", "Enabled": True, "Aliases": {"Quantity": 1, "Items": ["www.acme.com"]}}, {"Id": "E2", "ARN": "arn:cf:E2", "DomainName": "d222.cloudfront.net", "Enabled": False}]}},
        list_tags_for_resource={"Tags": {"Items": [{"Key": "perimeter:expected", "Value": "443"}]}},
    )

    def website(Bucket):
        return {} if Bucket in ("site", "eu-site") else client_error("NoSuchWebsiteConfiguration")

    s3 = Fake(
        list_buckets={"Buckets": [{"Name": "site", "BucketRegion": "us-east-1"}, {"Name": "eu-site", "BucketRegion": "eu-central-1"}, {"Name": "logs", "BucketRegion": "us-east-1"}]},
        get_bucket_website=website,
        get_bucket_policy_status=lambda Bucket: {"PolicyStatus": {"IsPublic": Bucket == "site"}},
    )
    inv = discover_global(Account("prod", ACCOUNT_ID, lambda svc, region: {"cloudfront": cf, "s3": s3}[svc]))
    assert inv.problems == []
    assert [(e.id, e.display, e.region, e.probe.url) for e in inv.endpoints] == [
        ("prod/cloudfront/E1", "www.acme.com", "global", "https://d111.cloudfront.net/"),
        ("prod/s3-website/site", "site", "us-east-1", "http://site.s3-website-us-east-1.amazonaws.com/"),
        ("prod/s3-website/eu-site", "eu-site", "eu-central-1", "http://eu-site.s3-website.eu-central-1.amazonaws.com/"),
    ]
    assert inv.endpoints[0].tags == {"perimeter:expected": "443"}
    assert all(e.scope == ("prod", "global") for e in inv.endpoints)


def test_nat_gateways_are_listed_without_a_probe(aws):
    raw = [{"NetworkInterfaceId": "eni-n", "InterfaceType": "nat_gateway", "Description": "Interface for NAT Gateway nat-0abc", "Association": {"PublicIp": "198.51.100.40"}}]
    ec2 = boto3.client("ec2", region_name=REGION)
    [nat] = inventory.eni_endpoints(Account("prod", ACCOUNT_ID, None), REGION, ec2, inventory.paths.Snapshot(), raw)
    assert nat.id == "prod/nat/nat-0abc" and nat.probe is None


def test_same_named_regional_endpoints_get_their_region():
    a = inventory.Endpoint("prod/alb/api", "api", "prod", "us-east-1", Kind.ALB)
    b = inventory.Endpoint("prod/alb/api", "api", "prod", "eu-west-1", Kind.ALB)
    c = inventory.Endpoint("prod/alb/web", "web", "prod", "eu-west-1", Kind.ALB)
    assert [e.id for e in disambiguate([a, b, c])] == ["prod/alb/api@us-east-1", "prod/alb/api@eu-west-1", "prod/alb/web"]


# --- ownership ----------------------------------------------------------------------------------


def test_only_addresses_still_held_by_the_named_eni_or_instance_pass():
    def describe(Filters):
        assert Filters[0]["Name"] == "association.public-ip"
        return {"NetworkInterfaces": [{"NetworkInterfaceId": "eni-a", "Association": {"PublicIp": "198.51.100.1"}}, {"NetworkInterfaceId": "eni-other", "Association": {"PublicIp": "198.51.100.2"}}]}

    ec2 = Fake(describe_network_interfaces=describe)
    ls = Fake(get_instance=lambda instanceName: {"instance": {"publicIpAddress": "198.51.100.9" if instanceName == "blog" else "198.51.100.99"}})
    acct = Account("prod", ACCOUNT_ID, lambda svc, region: {"ec2": ec2, "lightsail": ls}[svc])
    proof = f" in {ACCOUNT_ID}/{REGION}"
    addresses = [
        OwnedIPv4("198.51.100.1", "eni-a" + proof),  # still there
        OwnedIPv4("198.51.100.2", "eni-b" + proof),  # moved to another interface
        OwnedIPv4("198.51.100.3", "eni-c" + proof),  # released
        OwnedIPv4("198.51.100.9", "lightsail:blog" + proof),
        OwnedIPv4("198.51.100.10", "lightsail:shop" + proof),
    ]
    assert [a.ip for a in verify_ownership(acct, REGION, addresses)] == ["198.51.100.1", "198.51.100.9"]


def test_throttle_spaces_calls():
    now, slept = [0.0], []

    def sleep(seconds):
        slept.append(round(seconds, 3))
        now[0] += seconds

    t = Throttle(15, clock=lambda: now[0], sleep=sleep)
    for _ in range(4):
        t()
    assert slept == [0.067, 0.067, 0.067]


def test_a_bucket_listed_without_its_region_is_located():
    s3 = Fake(
        list_buckets={"Buckets": [{"Name": "old-eu"}, {"Name": "old-us"}, {"Name": "legacy-eu"}]},
        get_bucket_website={},
        get_bucket_location=lambda Bucket: {"LocationConstraint": {"old-eu": "eu-central-1", "old-us": None, "legacy-eu": "EU"}[Bucket]},
        get_bucket_policy_status={"PolicyStatus": {"IsPublic": True}},
    )
    inv = discover_global(Account("prod", ACCOUNT_ID, lambda svc, region: {"cloudfront": Fake(list_distributions={}), "s3": s3}[svc]))
    assert [(e.region, e.probe.host) for e in inv.endpoints] == [
        ("eu-central-1", "old-eu.s3-website.eu-central-1.amazonaws.com"),
        ("us-east-1", "old-us.s3-website-us-east-1.amazonaws.com"),
        ("eu-west-1", "legacy-eu.s3-website-eu-west-1.amazonaws.com"),
    ]
