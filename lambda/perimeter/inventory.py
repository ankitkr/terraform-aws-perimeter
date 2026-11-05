"""Inventory: every public endpoint in one account and region, with its paths, from the AWS
APIs. The boto3 clients come in through `client(service, region)`, already in the account.

discover_region() lists a region; discover_global() lists CloudFront and S3 websites once per
account. verify_ownership() re-checks a batch's addresses right before it scans."""

import json
import logging
import re
import socket
import time
from dataclasses import dataclass, field, replace

from botocore.exceptions import BotoCoreError, ClientError

import internet
import paths
from model import Endpoint, Flag, Http, Kind, OwnedIPv4, Tcp

log = logging.getLogger(__name__)

# ENIs that belong to an endpoint of another kind, or to AWS plumbing with no listener of yours.
OTHER_OWNERS = frozenset({"nat_gateway", "network_load_balancer", "gateway_load_balancer", "gateway_load_balancer_endpoint", "vpc_endpoint", "global_accelerator_managed", "transit_gateway", "load_balancer"})
NAT_DESCRIPTION = re.compile(r"NAT Gateway (nat-[0-9a-f]+)")
PROOF_SCOPE = re.compile(r"^\S+ in (\d{12})/([a-z0-9-]+)$")
# Regions whose S3 website endpoints use a dash (s3-website-us-east-1); newer ones use a dot.
S3_WEBSITE_DASH = frozenset({"us-east-1", "us-west-1", "us-west-2", "ap-southeast-1", "ap-southeast-2", "ap-northeast-1", "eu-west-1", "sa-east-1"})


@dataclass
class Account:
    name: str
    id: str
    client: object  # (service, region) -> boto3 client in this account


@dataclass
class RegionInventory:
    endpoints: list = field(default_factory=list)
    problems: list = field(default_factory=list)  # a non-empty list means the scope is incomplete


class Throttle:
    """At most `rate` calls per second: Lambda's control plane allows 15 for these APIs."""

    def __init__(self, rate, clock=time.monotonic, sleep=time.sleep):
        self.interval, self.clock, self.sleep, self.next = 1.0 / rate, clock, sleep, 0.0

    def __call__(self):
        now = self.clock()
        if now < self.next:
            self.sleep(self.next - now)
            now = self.next
        self.next = now + self.interval


# --- helpers ------------------------------------------------------------------------------------


def _pages(client, method, key, **kwargs):
    if client.can_paginate(method):
        for page in client.get_paginator(method).paginate(**kwargs):
            yield from page.get(key) or ()
    else:
        yield from getattr(client, method)(**kwargs).get(key) or ()


def _tags(raw):
    if isinstance(raw, dict):
        return dict(raw)
    return {t["Key"]: t["Value"] for t in raw or ()}


def _code(exc):
    return exc.response.get("Error", {}).get("Code", "") if isinstance(exc, ClientError) else type(exc).__name__


def _proof(eni_id, account, region):
    return f"{eni_id} in {account.id}/{region}"


def proof_scope(proof):
    """(account id, region) a proof names, or (None, None)."""
    m = PROOF_SCOPE.match(proof)
    return m.groups() if m else (None, None)


def _guard(inv, what, fn, *args):
    """Run one discovery step; a failure is a problem that marks the scope incomplete."""
    try:
        return fn(*args)
    except (ClientError, BotoCoreError) as exc:
        inv.problems.append(f"{what}: {_code(exc)}")
        log.warning("%s failed: %s", what, exc)
        return None


# --- the region snapshot ------------------------------------------------------------------------


def _route_target(r):
    for key in ("GatewayId", "NatGatewayId", "TransitGatewayId", "VpcPeeringConnectionId", "NetworkInterfaceId", "InstanceId", "LocalGatewayId", "CarrierGatewayId", "EgressOnlyInternetGatewayId", "CoreNetworkArn"):
        if r.get(key):
            return r[key]
    return "unknown"


def snapshot(ec2):
    """The region's network as paths.Snapshot."""
    vpcs = {}
    for v in _pages(ec2, "describe_vpcs", "Vpcs"):
        cidrs = [a["CidrBlock"] for a in v.get("CidrBlockAssociationSet") or () if a.get("CidrBlockState", {}).get("State", "associated") == "associated"]
        cidrs += [a["Ipv6CidrBlock"] for a in v.get("Ipv6CidrBlockAssociationSet") or () if a.get("Ipv6CidrBlockState", {}).get("State", "associated") == "associated"]
        vpcs[v["VpcId"]] = tuple(cidrs or [v.get("CidrBlock")])

    prefix_lists = {}
    for pl in _pages(ec2, "describe_managed_prefix_lists", "PrefixLists"):
        managed = pl.get("OwnerId") == "AWS"
        cidrs = () if managed else tuple(e["Cidr"] for e in _pages(ec2, "get_managed_prefix_list_entries", "Entries", PrefixListId=pl["PrefixListId"]))
        prefix_lists[pl["PrefixListId"]] = paths.PrefixList(pl["PrefixListId"], pl.get("PrefixListName", ""), managed, cidrs)

    rules = {}
    for r in _pages(ec2, "describe_security_group_rules", "SecurityGroupRules"):
        if r.get("IsEgress"):
            continue
        rules.setdefault(r["GroupId"], []).append(
            paths.SgRule(
                r["SecurityGroupRuleId"],
                str(r.get("IpProtocol", "-1")),
                r.get("FromPort"),
                r.get("ToPort"),
                r.get("CidrIpv4") or r.get("CidrIpv6"),
                r.get("PrefixListId"),
                (r.get("ReferencedGroupInfo") or {}).get("GroupId"),
            )
        )
    groups = {
        g["GroupId"]: paths.SecurityGroup(g["GroupId"], g.get("VpcId", ""), g.get("GroupName", ""), tuple(rules.get(g["GroupId"], ())))
        for g in _pages(ec2, "describe_security_groups", "SecurityGroups")
    }

    acls = []
    for a in _pages(ec2, "describe_network_acls", "NetworkAcls"):
        entries = tuple(
            paths.AclEntry(
                e["RuleNumber"],
                bool(e["Egress"]),
                str(e["Protocol"]),
                e["RuleAction"] == "allow",
                e.get("CidrBlock") or e.get("Ipv6CidrBlock"),
                (e["PortRange"]["From"], e["PortRange"]["To"]) if e.get("PortRange") else None,
            )
            for e in a.get("Entries") or ()
        )
        acls.append(paths.NetworkAcl(a["NetworkAclId"], a["VpcId"], entries, frozenset(x["SubnetId"] for x in a.get("Associations") or ())))

    tables, appliances = [], set()
    for t in _pages(ec2, "describe_route_tables", "RouteTables"):
        routes = []
        for r in t.get("Routes") or ():
            target = _route_target(r)
            if target.startswith("vpce-"):
                appliances.add(target)
            active = r.get("State", "active") == "active"
            if r.get("DestinationCidrBlock") or r.get("DestinationIpv6CidrBlock"):
                routes.append(paths.Route(r.get("DestinationCidrBlock") or r["DestinationIpv6CidrBlock"], target, active))
            elif r.get("DestinationPrefixListId") in prefix_lists:
                routes += [paths.Route(c, target, active) for c in prefix_lists[r["DestinationPrefixListId"]].cidrs]
        assoc = t.get("Associations") or ()
        tables.append(
            paths.RouteTable(
                t["RouteTableId"],
                t["VpcId"],
                tuple(routes),
                frozenset(a["SubnetId"] for a in assoc if a.get("SubnetId")),
                any(a.get("Main") for a in assoc),
                frozenset(a["GatewayId"] for a in assoc if a.get("GatewayId")),
            )
        )

    igws = {g["InternetGatewayId"]: frozenset(a["VpcId"] for a in g.get("Attachments") or () if a.get("State") in ("available", "attached")) for g in _pages(ec2, "describe_internet_gateways", "InternetGateways")}

    raw_enis = list(_pages(ec2, "describe_network_interfaces", "NetworkInterfaces"))
    enis = {
        e["NetworkInterfaceId"]: paths.Eni(
            e["NetworkInterfaceId"],
            e.get("SubnetId", ""),
            e.get("VpcId", ""),
            tuple(g["GroupId"] for g in e.get("Groups") or ()),
            e.get("PrivateIpAddress", ""),
            (e.get("Association") or {}).get("PublicIp"),
            (e.get("Attachment") or {}).get("InstanceId"),
        )
        for e in raw_enis
    }
    snap = paths.Snapshot(vpcs, groups, tuple(acls), tuple(tables), igws, prefix_lists, enis, {}, frozenset(appliances))
    return snap, raw_enis


def _network(snap, eni_ids):
    """Ids a tripwire event might name for these ENIs: VPC, subnets, NACLs, route tables."""
    ids = []
    for eni_id in eni_ids:
        eni = snap.enis.get(eni_id)
        if eni is None:
            continue
        ids += [eni.id, eni.vpc_id, eni.subnet_id]
        acl = snap.acl_for(eni.subnet_id)
        table = snap.route_table_for(eni.subnet_id, eni.vpc_id)
        ids += [x.id for x in (acl, table) if x]
    return tuple(dict.fromkeys(i for i in ids if i))


# --- EC2: instances, task ENIs, EIPs, NAT -------------------------------------------------------


def _instance_tags(ec2, instance_ids):
    tags = {}
    ids = sorted(instance_ids)
    for i in range(0, len(ids), 200):
        for reservation in _pages(ec2, "describe_instances", "Reservations", InstanceIds=ids[i : i + 200]):
            for inst in reservation["Instances"]:
                tags[inst["InstanceId"]] = _tags(inst.get("Tags"))
    return tags


def eni_endpoints(account, region, ec2, snap, raw_enis):
    """Instances and other ENIs with a public IPv4 (Fargate tasks, services' own ENIs), and NAT
    gateways (listed only). Load balancer and database ENIs belong to those endpoints."""
    grouped, nats = {}, []
    for e in raw_enis:
        public = (e.get("Association") or {}).get("PublicIp")
        if not public:
            continue
        description, kind = e.get("Description") or "", e.get("InterfaceType") or "interface"
        if kind == "nat_gateway":
            m = NAT_DESCRIPTION.search(description)
            nats.append((m.group(1) if m else e["NetworkInterfaceId"], public))
            continue
        if kind in OTHER_OWNERS or description.startswith("ELB ") or description == "RDSNetworkInterface":
            continue
        owner = (e.get("Attachment") or {}).get("InstanceId") or e["NetworkInterfaceId"]
        grouped.setdefault(owner, []).append(e)

    instance_tags = _instance_tags(ec2, [o for o in grouped if o.startswith("i-")])
    out = []
    for owner, enis in sorted(grouped.items()):
        eni_ids = [e["NetworkInterfaceId"] for e in enis]
        tags = instance_tags.get(owner) or _tags(enis[0].get("TagSet"))
        found, notes = paths.eni_paths(snap, eni_ids)
        sgs = tuple(dict.fromkeys(g["GroupId"] for e in enis for g in e.get("Groups") or ()))
        display = tags.get("Name") or (enis[0].get("Description") or owner)[:80]
        arn = f"arn:aws:ec2:{region}:{account.id}:{'instance' if owner.startswith('i-') else 'network-interface'}/{owner}"
        out.append(
            Endpoint(
                f"{account.name}/eni/{owner}",
                display,
                account.name,
                region,
                Kind.ENI,
                arn,
                tags,
                sgs,
                Tcp(tuple(OwnedIPv4(e["Association"]["PublicIp"], _proof(e["NetworkInterfaceId"], account, region)) for e in enis)),
                found,
                notes=notes,
                network=_network(snap, eni_ids) + sgs,
            )
        )
    for nat_id, ip in sorted(nats):
        out.append(Endpoint(f"{account.name}/nat/{nat_id}", nat_id, account.name, region, Kind.NAT, f"arn:aws:ec2:{region}:{account.id}:natgateway/{nat_id}", notes=(f"public address {ip}; a NAT gateway accepts no inbound connections",)))
    return out


def eip_endpoints(account, region, ec2):
    """Elastic IPs attached to nothing: listed so they can be released."""
    out = []
    for a in ec2.describe_addresses().get("Addresses") or ():
        if a.get("AssociationId") or a.get("NetworkInterfaceId"):
            continue
        alloc = a.get("AllocationId") or a["PublicIp"]
        tags = _tags(a.get("Tags"))
        out.append(Endpoint(f"{account.name}/eip/{alloc}", tags.get("Name") or a["PublicIp"], account.name, region, Kind.EIP, f"arn:aws:ec2:{region}:{account.id}:elastic-ip/{alloc}", tags, notes=(f"{a['PublicIp']} is attached to nothing",)))
    return out


# --- load balancers -----------------------------------------------------------------------------


def _target_eni(snap, target_type, target_id):
    if target_type == "instance":
        candidates = [e for e in snap.enis.values() if e.instance_id == target_id]
        return candidates[0].id if candidates else None
    if target_type == "ip":
        return next((e.id for e in snap.enis.values() if e.private_ip == target_id), None)
    return None


def _target_groups(elbv2, snap, lb_arn):
    groups = {}
    for tg in _pages(elbv2, "describe_target_groups", "TargetGroups", LoadBalancerArn=lb_arn):
        health = elbv2.describe_target_health(TargetGroupArn=tg["TargetGroupArn"]).get("TargetHealthDescriptions") or ()
        attrs = {a["Key"]: a["Value"] for a in elbv2.describe_target_group_attributes(TargetGroupArn=tg["TargetGroupArn"]).get("Attributes") or ()}
        preserve = attrs.get("preserve_client_ip.enabled")
        targets = tuple(
            paths.Target(
                h["Target"]["Id"],
                h["Target"].get("Port") or tg.get("Port") or 0,
                _target_eni(snap, tg.get("TargetType", "instance"), h["Target"]["Id"]),
                (h.get("TargetHealth") or {}).get("State") == "healthy",
            )
            for h in health
        )
        groups[tg["TargetGroupArn"]] = paths.TargetGroup(tg["TargetGroupArn"], tg["TargetGroupName"], tg.get("TargetType", "instance"), tg.get("Protocol", "TCP"), targets, None if preserve is None else preserve == "true")
    return groups


def _lb_addresses(raw_enis, description, account, region):
    return tuple(
        OwnedIPv4(e["Association"]["PublicIp"], _proof(e["NetworkInterfaceId"], account, region))
        for e in raw_enis
        if (e.get("Description") or "") == description and (e.get("Association") or {}).get("PublicIp")
    ), [e["NetworkInterfaceId"] for e in raw_enis if (e.get("Description") or "") == description]


def _elbv2_tags(elbv2, arns):
    tags = {}
    for i in range(0, len(arns), 20):
        for d in elbv2.describe_tags(ResourceArns=arns[i : i + 20]).get("TagDescriptions") or ():
            tags[d["ResourceArn"]] = _tags(d.get("Tags"))
    return tags


def elbv2_endpoints(account, region, elbv2, snap, raw_enis):
    lbs = [lb for lb in _pages(elbv2, "describe_load_balancers", "LoadBalancers") if lb.get("Scheme") == "internet-facing" and lb.get("Type") in ("application", "network")]
    tags = _elbv2_tags(elbv2, [lb["LoadBalancerArn"] for lb in lbs]) if lbs else {}
    out = []
    for lb in lbs:
        arn = lb["LoadBalancerArn"]
        suffix = arn.split(":loadbalancer/", 1)[1]  # app/<name>/<id>
        groups = _target_groups(elbv2, snap, arn)
        listeners = tuple(
            paths.Listener(
                ls["Port"],
                ls["Protocol"],
                tuple(dict.fromkeys(tg["TargetGroupArn"] for a in ls.get("DefaultActions") or () for tg in ((a.get("ForwardConfig") or {}).get("TargetGroups") or ([{"TargetGroupArn": a["TargetGroupArn"]}] if a.get("TargetGroupArn") else [])))),
            )
            for ls in _pages(elbv2, "describe_listeners", "Listeners", LoadBalancerArn=arn)
        )
        model = paths.LoadBalancer(lb["LoadBalancerName"], lb["Type"], lb.get("VpcId", ""), tuple(z["SubnetId"] for z in lb.get("AvailabilityZones") or ()), tuple(lb.get("SecurityGroups") or ()), listeners)
        found, notes = paths.lb_paths(replace(snap, target_groups=groups), model)
        addresses, eni_ids = _lb_addresses(raw_enis, f"ELB {suffix}", account, region)
        kind = Kind.ALB if lb["Type"] == "application" else Kind.NLB
        target_enis = [t.eni_id for g in groups.values() for t in g.targets if t.eni_id]
        out.append(
            Endpoint(
                f"{account.name}/{kind.value}/{lb['LoadBalancerName']}",
                lb["LoadBalancerName"],
                account.name,
                region,
                kind,
                arn,
                tags.get(arn, {}),
                model.security_groups,
                Tcp(addresses),
                found,
                notes=notes + (() if addresses else ("no public addresses found on its network interfaces",)),
                network=_network(snap, eni_ids + target_enis) + model.security_groups + tuple(model.subnets),
            )
        )
    return out


def clb_endpoints(account, region, elb, snap, raw_enis):
    lbs = [lb for lb in _pages(elb, "describe_load_balancers", "LoadBalancerDescriptions") if lb.get("Scheme") == "internet-facing"]
    tags = {}
    names = [lb["LoadBalancerName"] for lb in lbs]
    for i in range(0, len(names), 20):
        for d in elb.describe_tags(LoadBalancerNames=names[i : i + 20]).get("TagDescriptions") or ():
            tags[d["LoadBalancerName"]] = _tags(d.get("Tags"))
    out = []
    for lb in lbs:
        name = lb["LoadBalancerName"]
        listeners = tuple(paths.Listener(d["Listener"]["LoadBalancerPort"], d["Listener"]["Protocol"]) for d in lb.get("ListenerDescriptions") or ())
        model = paths.LoadBalancer(name, "classic", lb.get("VPCId", ""), tuple(lb.get("Subnets") or ()), tuple(lb.get("SecurityGroups") or ()), listeners)
        found, notes = paths.lb_paths(snap, model)
        addresses, eni_ids = _lb_addresses(raw_enis, f"ELB {name}", account, region)
        out.append(
            Endpoint(
                f"{account.name}/clb/{name}",
                name,
                account.name,
                region,
                Kind.CLB,
                f"arn:aws:elasticloadbalancing:{region}:{account.id}:loadbalancer/{name}",
                tags.get(name, {}),
                model.security_groups,
                Tcp(addresses),
                found,
                notes=notes,
                network=_network(snap, eni_ids) + model.security_groups + model.subnets,
            )
        )
    return out


# --- databases and search -----------------------------------------------------------------------


def rds_endpoints(account, region, rds, snap, raw_enis, resolve=socket.gethostbyname_ex):
    """Publicly accessible DB instances. Addresses come from DNS and count only when an RDS
    network interface in this account holds them."""
    by_ip = {(e.get("Association") or {}).get("PublicIp"): e["NetworkInterfaceId"] for e in raw_enis if e.get("Description") == "RDSNetworkInterface" and (e.get("Association") or {}).get("PublicIp")}
    out = []
    for db in _pages(rds, "describe_db_instances", "DBInstances"):
        if not db.get("PubliclyAccessible") or not db.get("Endpoint"):
            continue
        host, port = db["Endpoint"]["Address"], db["Endpoint"]["Port"]
        try:
            ips = resolve(host)[2]
        except OSError:
            ips = []
        owned = [(ip, by_ip[ip]) for ip in ips if ip in by_ip]
        eni_ids = [e for _, e in owned]
        found, notes = paths.eni_paths(snap, eni_ids, (port, port))
        if not owned:
            notes += (f"{host} resolves to {', '.join(ips) or 'nothing'}, which no RDS network interface in this account holds; not scanned",)
        out.append(
            Endpoint(
                f"{account.name}/rds/{db['DBInstanceIdentifier']}",
                db["DBInstanceIdentifier"],
                account.name,
                region,
                Kind.RDS,
                db.get("DBInstanceArn", ""),
                _tags(db.get("TagList")),
                tuple(g["VpcSecurityGroupId"] for g in db.get("VpcSecurityGroups") or ()),
                Tcp(tuple(OwnedIPv4(ip, _proof(eni, account, region)) for ip, eni in owned), (port,)) if owned else None,
                found,
                notes=notes,
                network=_network(snap, eni_ids) + tuple(g["VpcSecurityGroupId"] for g in db.get("VpcSecurityGroups") or ()),
            )
        )
    return out


def opensearch_endpoints(account, region, opensearch):
    """Domains outside a VPC. Their addresses are AWS's, not the account's, so they get one
    HTTPS request rather than a scan."""
    names = [d["DomainName"] for d in opensearch.list_domain_names().get("DomainNames") or ()]
    out = []
    for i in range(0, len(names), 5):
        for d in opensearch.describe_domains(DomainNames=names[i : i + 5]).get("DomainStatusList") or ():
            if d.get("VPCOptions") or not d.get("Endpoint"):
                continue
            host = d["Endpoint"]
            out.append(Endpoint(f"{account.name}/opensearch/{d['DomainName']}", d["DomainName"], account.name, region, Kind.OPENSEARCH, d.get("ARN", ""), probe=Http(f"https://{host}/", host), notes=("public endpoint; its access policy decides who may call it",)))
    return out


# --- managed fronts -----------------------------------------------------------------------------


def _anyone_invokes_url(policy_text):
    try:
        statements = json.loads(policy_text).get("Statement") or []
    except ValueError:
        return False
    for s in statements if isinstance(statements, list) else [statements]:
        principal = s.get("Principal")
        anyone = principal == "*" or (isinstance(principal, dict) and principal.get("AWS") in ("*", ["*"]))
        actions = s.get("Action")
        actions = [actions] if isinstance(actions, str) else actions or []
        if s.get("Effect") == "Allow" and anyone and any(a in ("lambda:InvokeFunctionUrl", "lambda:*", "*") for a in actions):
            return True
    return False


def lambda_url_endpoints(account, region, lam, throttle=None):
    throttle = throttle or Throttle(15)
    out = []
    throttle()
    for fn in _pages(lam, "list_functions", "Functions"):
        throttle()
        for url in _pages(lam, "list_function_url_configs", "FunctionUrlConfigs", FunctionName=fn["FunctionName"]):
            flags = frozenset()
            if url.get("AuthType") == "NONE":
                throttle()
                try:
                    policy = lam.get_policy(FunctionName=fn["FunctionName"]).get("Policy", "{}")
                except ClientError as exc:
                    if _code(exc) != "ResourceNotFoundException":
                        raise
                    policy = "{}"
                if _anyone_invokes_url(policy):
                    flags = frozenset({Flag.UNAUTHENTICATED_URL})
            host = url["FunctionUrl"].split("/")[2]
            out.append(
                Endpoint(
                    f"{account.name}/lambda-url/{fn['FunctionName']}",
                    fn["FunctionName"],
                    account.name,
                    region,
                    Kind.LAMBDA_URL,
                    url.get("FunctionArn", fn.get("FunctionArn", "")),
                    probe=Http(url["FunctionUrl"], host),
                    flags=flags,
                    notes=(f"AuthType {url.get('AuthType')}",),
                )
            )
    return out


def apigw_endpoints(account, region, apigw, apigwv2):
    out = []
    for api in _pages(apigw, "get_rest_apis", "items"):
        types = (api.get("endpointConfiguration") or {}).get("types") or ["EDGE"]
        if "PRIVATE" in types or api.get("disableExecuteApiEndpoint"):
            continue
        stages = apigw.get_stages(restApiId=api["id"]).get("item") or []
        if not stages:
            continue
        host = f"{api['id']}.execute-api.{region}.amazonaws.com"
        out.append(
            Endpoint(
                f"{account.name}/apigw-rest/{api['id']}",
                api.get("name", api["id"]),
                account.name,
                region,
                Kind.APIGW_REST,
                f"arn:aws:apigateway:{region}::/restapis/{api['id']}",
                _tags(api.get("tags")),
                probe=Http(f"https://{host}/{stages[0]['stageName']}/", host),
                notes=(f"stages: {', '.join(s['stageName'] for s in stages)}",),
            )
        )
    for api in _pages(apigwv2, "get_apis", "Items"):
        if api.get("DisableExecuteApiEndpoint") or not api.get("ApiEndpoint"):
            continue
        kind = Kind.APIGW_WS if api.get("ProtocolType") == "WEBSOCKET" else Kind.APIGW_HTTP
        url = re.sub(r"^wss://", "https://", api["ApiEndpoint"]) + "/"
        out.append(Endpoint(f"{account.name}/{kind.value}/{api['ApiId']}", api.get("Name", api["ApiId"]), account.name, region, kind, f"arn:aws:apigateway:{region}::/apis/{api['ApiId']}", _tags(api.get("Tags")), probe=Http(url, url.split("/")[2])))
    return out


def eks_endpoints(account, region, eks):
    out = []
    for name in _pages(eks, "list_clusters", "clusters"):
        c = eks.describe_cluster(name=name)["cluster"]
        vpc = c.get("resourcesVpcConfig") or {}
        if not vpc.get("endpointPublicAccess") or not c.get("endpoint"):
            continue
        cidrs = vpc.get("publicAccessCidrs") or ["0.0.0.0/0"]
        open_to = [x for x in cidrs if internet.is_internet(x)]
        host = c["endpoint"].split("/")[2]
        out.append(
            Endpoint(
                f"{account.name}/eks/{name}",
                name,
                account.name,
                region,
                Kind.EKS,
                c.get("arn", ""),
                _tags(c.get("tags")),
                tuple(vpc.get("securityGroupIds") or ()) + ((vpc["clusterSecurityGroupId"],) if vpc.get("clusterSecurityGroupId") else ()),
                Http(c["endpoint"] + "/", host),
                flags=frozenset({Flag.PUBLIC_API}) if open_to else frozenset(),
                notes=(f"public API endpoint allowed from {', '.join(cidrs)}",),
                network=(vpc.get("vpcId", ""),),
            )
        )
    return out


def lightsail_endpoints(account, region, lightsail):
    out = []
    for inst in _pages(lightsail, "get_instances", "instances"):
        ip = inst.get("publicIpAddress")
        if not ip:
            continue
        states = lightsail.get_instance_port_states(instanceName=inst["name"]).get("portStates") or []
        out.append(
            Endpoint(
                f"{account.name}/lightsail/{inst['name']}",
                inst["name"],
                account.name,
                region,
                Kind.LIGHTSAIL,
                inst.get("arn", ""),
                _tags([{"Key": t["key"], "Value": t.get("value", "")} for t in inst.get("tags") or ()]),
                probe=Tcp((OwnedIPv4(ip, f"lightsail:{inst['name']} in {account.id}/{region}"),)),
                paths=paths.lightsail_paths(states, inst["name"]),
            )
        )
    for s in _pages(lightsail, "get_static_ips", "staticIps"):
        if not s.get("isAttached"):
            out.append(Endpoint(f"{account.name}/eip/lightsail-{s['name']}", s["name"], account.name, region, Kind.EIP, s.get("arn", ""), notes=(f"Lightsail static IP {s.get('ipAddress')} is attached to nothing",)))
    return out


def cloudfront_endpoints(account, cloudfront):
    out = []
    for d in _distributions(cloudfront):
        if not d.get("Enabled"):
            continue
        aliases = (d.get("Aliases") or {}).get("Items") or []
        tags = _tags((cloudfront.list_tags_for_resource(Resource=d["ARN"]).get("Tags") or {}).get("Items"))
        out.append(
            Endpoint(
                f"{account.name}/cloudfront/{d['Id']}",
                aliases[0] if aliases else d["DomainName"],
                account.name,
                "global",
                Kind.CLOUDFRONT,
                d["ARN"],
                tags,
                probe=Http(f"https://{d['DomainName']}/", d["DomainName"]),
                notes=(f"aliases: {', '.join(aliases)}",) if aliases else (),
            )
        )
    return out


def _distributions(cloudfront):
    pages = cloudfront.get_paginator("list_distributions").paginate() if cloudfront.can_paginate("list_distributions") else [cloudfront.list_distributions()]
    for page in pages:
        yield from (page.get("DistributionList") or {}).get("Items") or ()


def _bucket_region(s3, name):
    # GetBucketLocation answers null for us-east-1 and "EU" for buckets made as eu-west-1 long ago.
    location = s3.get_bucket_location(Bucket=name).get("LocationConstraint")
    return {None: "us-east-1", "": "us-east-1", "EU": "eu-west-1"}.get(location, location)


def s3_website_endpoints(account, s3):
    out = []
    for b in _pages(s3, "list_buckets", "Buckets"):
        name = b["Name"]
        try:
            s3.get_bucket_website(Bucket=name)
        except ClientError as exc:
            if _code(exc) in ("NoSuchWebsiteConfiguration", "NoSuchBucket"):
                continue
            raise
        region = b.get("BucketRegion") or _bucket_region(s3, name)
        try:
            public = s3.get_bucket_policy_status(Bucket=name)["PolicyStatus"]["IsPublic"]
        except ClientError:
            public = False
        sep = "-" if region in S3_WEBSITE_DASH else "."
        host = f"{name}.s3-website{sep}{region}.amazonaws.com"
        out.append(
            Endpoint(
                f"{account.name}/s3-website/{name}",
                name,
                account.name,
                region,
                Kind.S3_WEBSITE,
                f"arn:aws:s3:::{name}",
                probe=Http(f"http://{host}/", host),
                notes=("bucket policy is public" if public else "bucket policy isn't public: the website answers 403",),
            )
        )
    return out


# --- the scopes ---------------------------------------------------------------------------------


def discover_region(account, region, resolve=socket.gethostbyname_ex):
    """Every endpoint of one account in one region."""
    inv = RegionInventory()
    ec2 = account.client("ec2", region)
    base = _guard(inv, f"{account.name}/{region} network", snapshot, ec2)
    if base is None:
        return inv
    snap, raw_enis = base
    steps = [
        ("instances and network interfaces", eni_endpoints, (account, region, ec2, snap, raw_enis)),
        ("Elastic IPs", eip_endpoints, (account, region, ec2)),
        ("load balancers", elbv2_endpoints, (account, region, account.client("elbv2", region), snap, raw_enis)),
        ("classic load balancers", clb_endpoints, (account, region, account.client("elb", region), snap, raw_enis)),
        ("RDS", rds_endpoints, (account, region, account.client("rds", region), snap, raw_enis, resolve)),
        ("OpenSearch", opensearch_endpoints, (account, region, account.client("opensearch", region))),
        ("Lambda URLs", lambda_url_endpoints, (account, region, account.client("lambda", region))),
        ("API Gateway", apigw_endpoints, (account, region, account.client("apigateway", region), account.client("apigatewayv2", region))),
        ("EKS", eks_endpoints, (account, region, account.client("eks", region))),
        ("Lightsail", lightsail_endpoints, (account, region, account.client("lightsail", region))),
    ]
    for what, fn, args in steps:
        found = _guard(inv, f"{account.name}/{region} {what}", fn, *args)
        inv.endpoints += found or []
    return inv


def discover_global(account):
    """CloudFront and S3 websites, listed once per account."""
    inv = RegionInventory()
    for what, fn, args in (
        ("CloudFront", cloudfront_endpoints, (account, account.client("cloudfront", "us-east-1"))),
        ("S3 websites", s3_website_endpoints, (account, account.client("s3", "us-east-1"))),
    ):
        inv.endpoints += _guard(inv, f"{account.name} {what}", fn, *args) or []
    return inv


REGIONAL_NAMES = frozenset({Kind.ALB, Kind.NLB, Kind.CLB, Kind.RDS, Kind.OPENSEARCH, Kind.LAMBDA_URL, Kind.EKS, Kind.LIGHTSAIL})


def disambiguate(endpoints):
    """Names are unique per region, not per account: a load balancer called api in two regions
    gets "@<region>" on both ids."""
    counts = {}
    for e in endpoints:
        counts[e.id] = counts.get(e.id, 0) + 1
    out = []
    for e in endpoints:
        if counts[e.id] > 1 and e.kind in REGIONAL_NAMES:
            e = replace(e, id=f"{e.id}@{e.region}")
        out.append(e)
    return out


# --- ownership ----------------------------------------------------------------------------------


def verify_ownership(account, region, addresses):
    """The subset of addresses (OwnedIPv4) that the named ENI or Lightsail instance in this
    account still holds. Called right before a batch scans: an address released since the
    inventory may belong to someone else by now."""
    held = set()
    eni_owned = [a for a in addresses if a.proof.startswith("eni-")]
    if eni_owned:
        ec2 = account.client("ec2", region)
        ips = sorted({a.ip for a in eni_owned})
        for i in range(0, len(ips), 200):
            for e in _pages(ec2, "describe_network_interfaces", "NetworkInterfaces", Filters=[{"Name": "association.public-ip", "Values": ips[i : i + 200]}]):
                ip = (e.get("Association") or {}).get("PublicIp")
                held.add((ip, _proof(e["NetworkInterfaceId"], account, region)))
    lightsail = [a for a in addresses if a.proof.startswith("lightsail:")]
    if lightsail:
        client = account.client("lightsail", region)
        for a in lightsail:
            name = a.proof.split(":", 1)[1].split(" ", 1)[0]
            try:
                if client.get_instance(instanceName=name)["instance"].get("publicIpAddress") == a.ip:
                    held.add((a.ip, a.proof))
            except ClientError:
                continue
    return [a for a in addresses if (a.ip, a.proof) in held]
