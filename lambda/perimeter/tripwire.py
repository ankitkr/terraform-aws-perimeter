"""Tripwires: judge one CloudTrail management event (as EventBridge delivers it) and say whether
it opened something to the internet, who did it, and what to rescan. Pure: the tripwire handler
resolves prefix lists and sends the alert."""

import json
import re
from dataclasses import dataclass, replace

import internet
from classify import CRITICAL_PORTS
from model import Alert, AlertKind, Severity

RESCAN_DELAY = 120

# CloudTrail appends an API version to some event names: AddPermission20150331v2,
# CreateDistribution2020_05_31.
VERSION_SUFFIX = re.compile(r"(\d{8}(v\d+)?|\d{4}_\d{2}_\d{2})$")


@dataclass(frozen=True)
class Change:
    severity: Severity
    text: str  # "opened tcp/22 to 0.0.0.0/0"
    resource: str
    touched: tuple[str, ...] = ()  # resource ids the targeted run looks for
    rescan: bool = True


@dataclass(frozen=True)
class TripwireFinding:
    event_id: str
    event_name: str
    account_id: str
    region: str
    caller: str
    source_ip: str
    change: Change


# --- CloudTrail shapes --------------------------------------------------------------------------


def _items(value):
    """CloudTrail wraps EC2 lists as {"items": [...]}; other services use plain lists."""
    if isinstance(value, dict):
        return list(value.get("items") or ())
    if isinstance(value, list):
        return value
    return []


def caller(detail):
    """Who made the call: the session name and the role it assumed, the IAM user, or root."""
    who = detail.get("userIdentity") or {}
    kind = who.get("type")
    if kind == "Root":
        return "root"
    if kind == "IAMUser":
        return who.get("userName") or who.get("arn", "an IAM user")
    if kind == "AssumedRole":
        role = ((who.get("sessionContext") or {}).get("sessionIssuer") or {}).get("userName")
        session = (who.get("arn") or "").rsplit("/", 1)[-1]
        return f"{session} ({role})" if role and session and session != role else role or who.get("arn", "an assumed role")
    if kind == "AWSService":
        return who.get("invokedBy", "an AWS service")
    return who.get("arn") or who.get("principalId") or "unknown caller"


def by_aws_service(detail):
    """A call AWS made on its own: a service principal, or a service-linked role (ELB or RDS
    attaching their own Elastic IPs). The human call that started it alerts on its own."""
    who = detail.get("userIdentity") or {}
    issuer = ((who.get("sessionContext") or {}).get("sessionIssuer") or {}).get("arn", "")
    return who.get("type") == "AWSService" or ":role/aws-service-role/" in issuer


def _short(name_or_arn):
    return (name_or_arn or "").rsplit(":", 1)[-1].rsplit("/", 1)[-1]


def _ports(protocol, lo, hi):
    protocol = str(protocol).lower()
    if protocol in ("-1", "all"):
        return "all traffic", True
    name = {"6": "tcp", "17": "udp", "1": "icmp"}.get(protocol, protocol)
    if lo in (None, -1) or name == "icmp":
        return f"{name}/all", name == "tcp"
    lo, hi = int(lo), int(hi if hi is not None else lo)
    label = f"{name}/{lo}" if lo == hi else f"{name}/{lo}-{hi}"
    return label, name == "tcp" and any(lo <= p <= hi for p in CRITICAL_PORTS)


def _opened(protocol, lo, hi, sources, where, touched):
    """A Change for an ingress rule admitting internet sources, or None."""
    public = [s for s in sources if s]
    if not public:
        return None
    label, critical = _ports(protocol, lo, hi)
    return Change(Severity.CRITICAL if critical else Severity.HIGH, f"opened {label} to {', '.join(public)}", where, touched)


def _internet_sources(cidrs, prefix_lists, resolved):
    """The internet sources among a rule's CIDRs and prefix lists, described."""
    out = [c for c in cidrs if c and internet.is_internet(c)]
    for pl in prefix_lists:
        entries = (resolved or {}).get(pl)
        if entries is None:
            out.append(f"{pl} (prefix list, not resolved)")
        elif any(internet.is_internet(c) for c in entries):
            out.append(f"{pl} (prefix list with internet ranges)")
    return out


# --- EC2 ----------------------------------------------------------------------------------------


def _authorize_ingress(req, resp, resolved):
    group = req.get("groupId") or req.get("groupName") or "a security group"
    rule_ids = [r.get("securityGroupRuleId") for r in _items((resp or {}).get("securityGroupRuleSet")) if r.get("securityGroupRuleId")]
    where = group + (f" ({', '.join(rule_ids)})" if rule_ids else "")
    permissions = _items(req.get("ipPermissions"))
    if not permissions and req.get("ipProtocol"):  # the older flat form
        permissions = [{"ipProtocol": req["ipProtocol"], "fromPort": req.get("fromPort"), "toPort": req.get("toPort"), "ipRanges": {"items": [{"cidrIp": req.get("cidrIp")}]}}]
    changes = []
    for p in permissions:
        cidrs = [r.get("cidrIp") for r in _items(p.get("ipRanges"))] + [r.get("cidrIpv6") for r in _items(p.get("ipv6Ranges"))]
        lists = [r.get("prefixListId") for r in _items(p.get("prefixListIds"))]
        c = _opened(p.get("ipProtocol"), p.get("fromPort"), p.get("toPort"), _internet_sources(cidrs, lists, resolved), where, (req.get("groupId") or group,))
        if c:
            changes.append(c)
    return _merge(changes)


def _modify_sg_rules(req, resp, resolved):
    body = req.get("ModifySecurityGroupRulesRequest") or req
    group = body.get("GroupId", "a security group")
    rules = body.get("SecurityGroupRule")
    rules = rules if isinstance(rules, list) else [rules] if rules else []
    changes = []
    for r in rules:
        spec = r.get("SecurityGroupRule") or {}
        sources = _internet_sources([spec.get("CidrIpv4"), spec.get("CidrIpv6")], [spec.get("PrefixListId")] if spec.get("PrefixListId") else [], resolved)
        where = f"{group} ({r.get('SecurityGroupRuleId', 'a rule')})"
        c = _opened(spec.get("IpProtocol", "-1"), spec.get("FromPort"), spec.get("ToPort"), sources, where, (group,))
        if c:
            changes.append(c)
    return _merge(changes)


def _nacl_entry(req, resp, resolved):
    if str(req.get("egress")).lower() == "true" or req.get("ruleAction") != "allow":
        return None
    cidr = req.get("cidrBlock") or req.get("ipv6CidrBlock")
    if not cidr or not internet.is_internet(cidr):
        return None
    ports = req.get("portRange") or {}
    label, _ = _ports(req.get("aclProtocol", "-1"), ports.get("from"), ports.get("to"))
    acl = req.get("networkAclId", "a network ACL")
    return Change(Severity.HIGH, f"allowed {label} in from {cidr} (rule #{req.get('ruleNumber')})", acl, (acl,))


def _nacl_association(req, resp, resolved):
    acl = req.get("networkAclId", "a network ACL")
    return Change(Severity.INFO, f"moved a subnet onto {acl}", acl, (acl,))


def _route(req, resp, resolved):
    gateway = req.get("gatewayId") or ""
    destination = req.get("destinationCidrBlock") or req.get("destinationIpv6CidrBlock")
    if not gateway.startswith("igw-") or not destination or not internet.is_internet(destination):
        return None
    table = req.get("routeTableId", "a route table")
    return Change(Severity.HIGH, f"routed {destination} to {gateway}", table, (table, gateway))


def _route_association(req, resp, resolved):
    table = req.get("routeTableId", "a route table")
    subnet = req.get("subnetId") or req.get("gatewayId") or req.get("associationId", "")
    return Change(Severity.INFO, f"associated {subnet} with {table}".replace("  ", " "), table, tuple(x for x in (table, req.get("subnetId")) if x))


def _attach_igw(req, resp, resolved):
    vpc = req.get("vpcId", "a VPC")
    return Change(Severity.INFO, f"attached {req.get('internetGatewayId', 'an internet gateway')} to {vpc}", vpc, (vpc,))


def _instance_groups(req, resp, resolved):
    groups = [g.get("groupId") for g in _items(req.get("groupSet"))]
    if not groups:
        return None
    instance = req.get("instanceId", "an instance")
    return Change(Severity.INFO, f"set the security groups of {instance} to {', '.join(groups)}", instance, (instance, *groups))


def _eni_groups(req, resp, resolved):
    groups = [g.get("groupId") for g in _items(req.get("groupSet"))]
    if not groups:
        return None
    eni = req.get("networkInterfaceId", "a network interface")
    return Change(Severity.INFO, f"set the security groups of {eni} to {', '.join(groups)}", eni, (eni, *groups))


def _subnet_attribute(req, resp, resolved):
    value = (req.get("mapPublicIpOnLaunch") or {}).get("value")
    if value is not True and str(value).lower() != "true":
        return None
    subnet = req.get("subnetId", "a subnet")
    return Change(Severity.INFO, f"turned on public IPs at launch in {subnet}", subnet, (subnet,))


def _run_instances(req, resp, resolved):
    public = {}
    for i in _items((resp or {}).get("instancesSet")):
        for eni in _items(i.get("networkInterfaceSet")):
            ip = (eni.get("association") or {}).get("publicIp")
            if ip:
                public[i.get("instanceId")] = ip
        if i.get("publicIpAddress"):
            public[i.get("instanceId")] = i["publicIpAddress"]
    asked = any(str(n.get("associatePublicIpAddress")).lower() == "true" for n in _items(req.get("networkInterfaceSet")))
    instances = [i.get("instanceId") for i in _items((resp or {}).get("instancesSet")) if i.get("instanceId")]
    if not public and not asked:
        return None
    where = ", ".join(instances) or "new instances"
    detail = ", ".join(f"{i} at {ip}" for i, ip in public.items()) if public else "with a public IP"
    return Change(Severity.MEDIUM, f"launched {detail}", where, tuple(instances))


def _associate_address(req, resp, resolved):
    target = req.get("instanceId") or req.get("networkInterfaceId") or "a resource"
    address = req.get("publicIp") or req.get("allocationId") or "an Elastic IP"
    return Change(Severity.MEDIUM, f"attached {address} to {target}", target, (target,))


# --- load balancers -----------------------------------------------------------------------------


def _lb_name(req):
    return req.get("name") or req.get("loadBalancerName") or _lb_from_arn(req.get("loadBalancerArn"))


def _lb_from_arn(arn):
    # arn:aws:elasticloadbalancing:region:acct:loadbalancer/app/<name>/<id>
    parts = (arn or "").split("/")
    return parts[2] if len(parts) >= 4 else _short(arn) or "a load balancer"


def _create_lb(req, resp, resolved):
    if req.get("scheme") == "internal":
        return None
    name = _lb_name(req)
    return Change(Severity.MEDIUM, f"created internet-facing load balancer {name}", name, (name,))


def _lb_change(verb):
    def judge(req, resp, resolved):
        name = _lb_name(req)
        port = f" on port {req['port']}" if req.get("port") else ""
        groups = ", ".join(req.get("securityGroups") or ())
        return Change(Severity.INFO, f"{verb}{port}{f' ({groups})' if groups else ''} on {name}", name, (name, *(req.get("securityGroups") or ())))

    return judge


# --- managed fronts and data services -----------------------------------------------------------


def _function_url(req, resp, resolved):
    auth = req.get("authType") or (resp or {}).get("authType")
    if auth != "NONE":
        return None
    fn = _short(req.get("functionName"))
    return Change(Severity.MEDIUM, f"gave function {fn} a URL with AuthType NONE (public if its policy lets anyone invoke it)", fn, (fn,))


def _add_permission(req, resp, resolved):
    action, principal = req.get("action", ""), str(req.get("principal", ""))
    if principal != "*" or action not in ("lambda:InvokeFunctionUrl", "lambda:*"):
        return None
    if req.get("functionUrlAuthType") not in (None, "NONE"):
        return None
    fn = _short(req.get("functionName"))
    return Change(Severity.HIGH, f"let anyone invoke function {fn}'s URL ({req.get('statementId', 'a statement')})", fn, (fn,))


def _rds_public(req, value):
    if value is not True:
        return None
    db = req.get("dBInstanceIdentifier") or req.get("targetDBInstanceIdentifier") or "a database"
    return Change(Severity.HIGH, f"made database {db} publicly accessible", db, (db,))


def _rds_create(req, resp, resolved):
    """The response says whether a new database ended up public, also when the request left it
    to the default."""
    value = req.get("publiclyAccessible")
    return _rds_public(req, value if value is not None else (resp or {}).get("publiclyAccessible"))


def _rds_modify(req, resp, resolved):
    # The response carries the current value: any change to an already public database shows it.
    return _rds_public(req, req.get("publiclyAccessible"))


def _vpc_options(raw):
    options = raw.get("vPCOptions") or raw.get("vpcOptions") or raw.get("VPCOptions") or {}
    options = options.get("options", options) if isinstance(options, dict) else {}
    return bool(options.get("subnetIds") or options.get("SubnetIds"))


def _opensearch_create(req, resp, resolved):
    if _vpc_options(req):
        return None
    domain = req.get("domainName", "a domain")
    return Change(Severity.MEDIUM, f"created OpenSearch domain {domain} with a public endpoint", domain, (domain,))


def _opensearch_update(req, resp, resolved):
    config = (resp or {}).get("domainConfig") or {}
    if _vpc_options(config) or _vpc_options(req):
        return None
    domain = req.get("domainName", "a domain")
    return Change(Severity.INFO, f"changed public OpenSearch domain {domain}", domain, (domain,))


def _eks(req, update):
    config = req.get("resourcesVpcConfig")
    if config is None:
        return None
    public = config.get("endpointPublicAccess")
    cidrs = config.get("publicAccessCidrs")
    if update and public is None and cidrs is None:
        return None
    if public is False:
        return None
    cluster = req.get("name", "a cluster")
    if update and cidrs is None:
        # The cluster keeps the CIDRs it had, which the event doesn't show; the rescan reads them.
        return Change(Severity.HIGH, f"turned on the public Kubernetes API of {cluster} with its existing CIDRs", cluster, (cluster,))
    cidrs = cidrs if cidrs is not None else ["0.0.0.0/0"]  # CreateCluster's default
    open_to = [c for c in cidrs if internet.is_internet(c)]
    if not open_to:
        return None
    return Change(Severity.HIGH, f"opened the Kubernetes API of {cluster} to {', '.join(open_to)}", cluster, (cluster,))


def _eks_create(req, resp, resolved):
    return _eks(req, update=False)


def _eks_update(req, resp, resolved):
    return _eks(req, update=True)


def _bucket(req):
    return req.get("bucketName", "a bucket")


def _website(req, resp, resolved):
    b = _bucket(req)
    return Change(Severity.MEDIUM, f"turned on website hosting for bucket {b}", b, (b,))


def _public_statement(s):
    principal = s.get("Principal")
    anyone = principal == "*" or (isinstance(principal, dict) and principal.get("AWS") in ("*", ["*"]))
    actions = s.get("Action")
    actions = [actions] if isinstance(actions, str) else actions or []
    reads = any(a in ("*", "s3:*", "s3:GetObject", "s3:Get*") for a in actions)
    return s.get("Effect") == "Allow" and anyone and reads and not s.get("Condition")


def _bucket_policy(req, resp, resolved):
    policy = req.get("bucketPolicy") or {}
    if isinstance(policy, str):
        try:
            policy = json.loads(policy)
        except ValueError:
            return None
    statements = policy.get("Statement") or []
    statements = [statements] if isinstance(statements, dict) else statements
    if not any(_public_statement(s) for s in statements):
        return None
    b = _bucket(req)
    return Change(Severity.HIGH, f"gave bucket {b} a policy that lets anyone read its objects", b, (b,))


def _delete_pab(req, resp, resolved):
    b = req.get("bucketName")
    if b:
        return Change(Severity.MEDIUM, f"removed the public access block of bucket {b}", b, (b,))
    return Change(Severity.MEDIUM, "removed the account's S3 public access block", "the account", ())


def _put_pab(req, resp, resolved):
    config = req.get("PublicAccessBlockConfiguration") or {}
    weakened = [k for k in ("BlockPublicPolicy", "RestrictPublicBuckets") if config.get(k) is False or str(config.get(k)).lower() == "false"]
    if not weakened:
        return None
    b = req.get("bucketName")
    where = f"bucket {b}" if b else "the account"
    return Change(Severity.MEDIUM, f"turned off {' and '.join(weakened)} for {where}", b or "the account", (b,) if b else ())


def _dig(raw, path):
    for key in path.split("."):
        raw = raw.get(key) if isinstance(raw, dict) else None
    return raw


def _always(text, names, ids):
    """A creation that is exposure by itself: name it, and rescan whatever it created."""

    def judge(req, resp, resolved):
        def found(paths):
            return next((v for p in paths for v in (_dig(req, p), _dig(resp, p)) if v), None)

        name, ident = found(names), found(ids)
        label = name or ident or "a resource"
        if name and ident and name != ident:
            label = f"{name} ({ident})"
        return Change(Severity.INFO, text.format(name=label), label, (ident,) if ident else ())

    return judge


def _lightsail(req, resp, resolved):
    instance = req.get("instanceName", "an instance")
    infos = req.get("portInfos") or ([req["portInfo"]] if req.get("portInfo") else [])
    opened = []
    for p in infos:
        cidrs = p.get("cidrs") or ["0.0.0.0/0"]
        public = [c for c in cidrs if internet.is_internet(c)]
        if public:
            opened.append(f"{p.get('protocol', 'tcp')}/{p.get('fromPort')}-{p.get('toPort')} to {', '.join(public)}")
    text = f"opened {'; '.join(opened)} on Lightsail {instance}" if opened else f"changed the firewall of Lightsail {instance}"
    return Change(Severity.INFO, text, instance, (instance,))


def _merge(changes):
    if not changes:
        return None
    if len(changes) == 1:
        return changes[0]
    worst = max(c.severity for c in changes)
    return Change(worst, "; ".join(c.text for c in changes), changes[0].resource, tuple(dict.fromkeys(t for c in changes for t in c.touched)))


# The event table: name -> (EventBridge source, judge). modules/member/events.json lists the same
# names per source for the rules; a test keeps the two in step.
EVENTS = {
    "AuthorizeSecurityGroupIngress": ("aws.ec2", _authorize_ingress),
    "ModifySecurityGroupRules": ("aws.ec2", _modify_sg_rules),
    "CreateNetworkAclEntry": ("aws.ec2", _nacl_entry),
    "ReplaceNetworkAclEntry": ("aws.ec2", _nacl_entry),
    "ReplaceNetworkAclAssociation": ("aws.ec2", _nacl_association),
    "CreateRoute": ("aws.ec2", _route),
    "ReplaceRoute": ("aws.ec2", _route),
    "AssociateRouteTable": ("aws.ec2", _route_association),
    "ReplaceRouteTableAssociation": ("aws.ec2", _route_association),
    "AttachInternetGateway": ("aws.ec2", _attach_igw),
    "ModifyInstanceAttribute": ("aws.ec2", _instance_groups),
    "ModifyNetworkInterfaceAttribute": ("aws.ec2", _eni_groups),
    "ModifySubnetAttribute": ("aws.ec2", _subnet_attribute),
    "RunInstances": ("aws.ec2", _run_instances),
    "AssociateAddress": ("aws.ec2", _associate_address),
    "CreateLoadBalancer": ("aws.elasticloadbalancing", _create_lb),
    "CreateListener": ("aws.elasticloadbalancing", _lb_change("added a listener")),
    "SetSecurityGroups": ("aws.elasticloadbalancing", _lb_change("changed the security groups")),
    "ApplySecurityGroupsToLoadBalancer": ("aws.elasticloadbalancing", _lb_change("changed the security groups")),
    "CreateFunctionUrlConfig": ("aws.lambda", _function_url),
    "UpdateFunctionUrlConfig": ("aws.lambda", _function_url),
    "AddPermission": ("aws.lambda", _add_permission),
    "CreateDBInstance": ("aws.rds", _rds_create),
    "CreateDBInstanceReadReplica": ("aws.rds", _rds_create),
    "ModifyDBInstance": ("aws.rds", _rds_modify),
    "RestoreDBInstanceFromDBSnapshot": ("aws.rds", _rds_create),
    "RestoreDBInstanceToPointInTime": ("aws.rds", _rds_create),
    "RestoreDBInstanceFromS3": ("aws.rds", _rds_create),
    "CreateDomain": ("aws.es", _opensearch_create),
    "CreateElasticsearchDomain": ("aws.es", _opensearch_create),
    "UpdateDomainConfig": ("aws.es", _opensearch_update),
    "UpdateElasticsearchDomainConfig": ("aws.es", _opensearch_update),
    "CreateCluster": ("aws.eks", _eks_create),
    "UpdateClusterConfig": ("aws.eks", _eks_update),
    "PutBucketWebsite": ("aws.s3", _website),
    "PutBucketPolicy": ("aws.s3", _bucket_policy),
    "DeleteBucketPublicAccessBlock": ("aws.s3", _delete_pab),
    "DeleteAccountPublicAccessBlock": ("aws.s3", _delete_pab),
    "PutBucketPublicAccessBlock": ("aws.s3", _put_pab),
    "PutAccountPublicAccessBlock": ("aws.s3", _put_pab),
    "CreateDistribution": ("aws.cloudfront", _always("created CloudFront distribution {name}", ["distribution.domainName"], ["distribution.id"])),
    "CreateDistributionWithTags": ("aws.cloudfront", _always("created CloudFront distribution {name}", ["distribution.domainName"], ["distribution.id"])),
    "CreateRestApi": ("aws.apigateway", _always("created REST API {name}", ["name"], ["id"])),
    "CreateApi": ("aws.apigateway", _always("created API {name}", ["name"], ["apiId"])),
    "CreateStage": ("aws.apigateway", _always("created API stage {name}", ["stageName"], ["restApiId", "apiId"])),
    "OpenInstancePublicPorts": ("aws.lightsail", _lightsail),
    "PutInstancePublicPorts": ("aws.lightsail", _lightsail),
}


def event_name(raw):
    return VERSION_SUFFIX.sub("", raw or "")


def prefix_list_ids(event):
    """Prefix lists an event's security group rules name: the handler resolves them first."""
    req = (event.get("detail") or {}).get("requestParameters") or {}
    ids = [r.get("prefixListId") for p in _items(req.get("ipPermissions")) for r in _items(p.get("prefixListIds"))]
    body = req.get("ModifySecurityGroupRulesRequest") or {}
    rules = body.get("SecurityGroupRule")
    for r in rules if isinstance(rules, list) else [rules] if rules else []:
        ids.append((r.get("SecurityGroupRule") or {}).get("PrefixListId"))
    return sorted({i for i in ids if i})


def judge(event, prefix_lists=None):
    """TripwireFinding, or None when the call failed or opened nothing. prefix_lists: id -> CIDRs
    for the lists the event names, resolved in the event's account."""
    detail = event.get("detail") or {}
    if detail.get("errorCode"):
        return None
    name = event_name(detail.get("eventName"))
    entry = EVENTS.get(name)
    if entry is None:
        return None
    change = entry[1](detail.get("requestParameters") or {}, detail.get("responseElements") or {}, prefix_lists)
    if change is None:
        return None
    if by_aws_service(detail):
        change = replace(change, severity=Severity.INFO)
    return TripwireFinding(
        event_id=detail.get("eventID") or event.get("id", ""),
        event_name=name,
        account_id=event.get("account") or detail.get("recipientAccountId", ""),
        region=event.get("region") or detail.get("awsRegion", ""),
        caller=caller(detail),
        source_ip=detail.get("sourceIPAddress", "an unknown address"),
        change=change,
    )


def alert(finding, account_name):
    c = finding.change
    icon = {Severity.CRITICAL: ":rotating_light:", Severity.HIGH: ":red_circle:", Severity.MEDIUM: ":large_orange_circle:"}.get(c.severity, ":information_source:")
    rescan = f" Rescanning in {RESCAN_DELAY // 60} min." if c.rescan else ""
    on = "" if c.resource in c.text else f" on {c.resource}"
    return Alert(
        AlertKind.TRIPWIRE,
        c.severity,
        account_name,
        f"{icon} {finding.event_name} in {account_name}/{finding.region}",
        f"*{finding.caller}* {c.text}{on}, from {finding.source_ip}.{rescan}",
        None,
        {"event": finding.event_name, "eventId": finding.event_id, "region": finding.region, "resource": c.resource},
    )
