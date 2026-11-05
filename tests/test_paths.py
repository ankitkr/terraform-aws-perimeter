"""Why-reachable analysis over fixture VPCs."""

from dataclasses import replace

from paths import (
    AclEntry,
    Eni,
    Listener,
    LoadBalancer,
    NetworkAcl,
    PrefixList,
    Route,
    RouteTable,
    SecurityGroup,
    SgRule,
    Snapshot,
    Target,
    TargetGroup,
    by_port,
    eni_paths,
    lb_paths,
    lightsail_paths,
)

VPC = "vpc-1"
OPEN_ACL = (
    AclEntry(100, False, "-1", True, "0.0.0.0/0"),
    AclEntry(32767, False, "-1", False, "0.0.0.0/0"),
    AclEntry(100, True, "-1", True, "0.0.0.0/0"),
    AclEntry(32767, True, "-1", False, "0.0.0.0/0"),
)
PUBLIC_RT = RouteTable("rtb-main", VPC, (Route("10.0.0.0/16", "local"), Route("0.0.0.0/0", "igw-1")), main=True)


def sg(id, *rules):
    return SecurityGroup(id, VPC, id, tuple(rules))


def rule(port, cidr=None, rule_id="sgr-1", to=None, protocol="tcp", **kw):
    return SgRule(rule_id, protocol, port, to if to is not None else port, cidr, **kw)


def snapshot(groups=(), acl_entries=OPEN_ACL, tables=(PUBLIC_RT,), enis=None, **kw):
    enis = enis or {"eni-1": Eni("eni-1", "subnet-1", VPC, tuple(g.id for g in groups), "10.0.1.5", "203.0.113.10", "i-1")}
    return Snapshot(
        vpcs={VPC: ("10.0.0.0/16",)},
        security_groups={g.id: g for g in groups},
        acls=(NetworkAcl("acl-1", VPC, tuple(acl_entries), frozenset({"subnet-1", "subnet-2"})),),
        route_tables=tuple(tables),
        igws={"igw-1": frozenset({VPC})},
        enis=enis,
        **kw,
    )


def ports_of(paths):
    return sorted({p.ports for p in paths})


# --- security groups ----------------------------------------------------------------------------


def test_world_open_ssh_is_explained_by_rule_nacl_and_route():
    snap = snapshot([sg("sg-web", rule(22, "0.0.0.0/0", "sgr-9"))])
    paths, _ = eni_paths(snap, ["eni-1"])
    assert len(paths) == 1
    p = paths[0]
    assert p.ports == (22, 22) and p.cidr == "0.0.0.0/0" and p.verified and not p.partial
    assert p.refs == (
        "sg-web rule sgr-9 tcp/22 from 0.0.0.0/0",
        "acl-1 #100 allow",
        "acl-1 egress #100 allow 1024-65535",
        "rtb-main 0.0.0.0/0 → igw-1",
    )


def test_private_sources_and_sg_references_are_not_internet_paths():
    snap = snapshot([sg("sg-app", rule(5432, "10.0.0.0/8"), rule(5432, group="sg-web", rule_id="sgr-2"), rule(8080, "100.64.0.0/10", rule_id="sgr-3"))])
    assert eni_paths(snap, ["eni-1"])[0] == ()


def test_a_public_cidr_inside_the_vpc_is_not_internet():
    snap = replace(snapshot([sg("sg-1", rule(80, "198.51.100.0/24"))]), vpcs={VPC: ("10.0.0.0/16", "198.51.100.0/24")})
    assert eni_paths(snap, ["eni-1"])[0] == ()


def test_all_traffic_rule_covers_every_port_and_udp_doesnt():
    snap = snapshot([sg("sg-1", rule(None, "0.0.0.0/0", protocol="-1"), rule(53, "0.0.0.0/0", "sgr-u", protocol="udp"))])
    paths, _ = eni_paths(snap, ["eni-1"])
    assert ports_of(paths) == [(0, 65535)]
    assert "all from 0.0.0.0/0" in paths[0].refs[0]


def test_ipv6_world_rule_is_a_path_through_an_ipv6_route():
    table = replace(PUBLIC_RT, routes=PUBLIC_RT.routes + (Route("::/0", "igw-1"),))
    acl = OPEN_ACL + (AclEntry(101, False, "-1", True, "::/0"), AclEntry(101, True, "-1", True, "::/0"))
    paths, _ = eni_paths(snapshot([sg("sg-1", rule(443, "::/0"))], acl, (table,)), ["eni-1"])
    assert [p.cidr for p in paths] == ["::/0"] and paths[0].refs[-1] == "rtb-main ::/0 → igw-1"


def test_customer_prefix_list_is_expanded_and_aws_managed_is_named():
    office = PrefixList("pl-office", "office", False, ("203.0.113.0/24", "10.9.0.0/16"))
    cloudfront = PrefixList("pl-cf", "com.amazonaws.global.cloudfront.origin-facing", True)
    snap = snapshot(
        [sg("sg-1", rule(22, prefix_list="pl-office"), rule(443, prefix_list="pl-cf", rule_id="sgr-2"))],
        prefix_lists={"pl-office": office, "pl-cf": cloudfront},
    )
    paths, notes = eni_paths(snap, ["eni-1"])
    assert [(p.ports, p.cidr) for p in paths] == [((22, 22), "pl-office (office): 203.0.113.0/24")]
    assert notes == ("tcp/443-443 reachable only from com.amazonaws.global.cloudfront.origin-facing (pl-cf), via sg-1 rule sgr-2",)


# --- NACLs --------------------------------------------------------------------------------------


def test_nacl_rules_apply_in_rule_order_not_list_order():
    deny_first = (
        AclEntry(200, False, "6", True, "0.0.0.0/0", (22, 22)),
        AclEntry(100, False, "6", False, "0.0.0.0/0", (22, 22)),
    ) + OPEN_ACL[2:]
    assert eni_paths(snapshot([sg("sg-1", rule(22, "0.0.0.0/0"))], deny_first), ["eni-1"])[0] == ()

    allow_first = (
        AclEntry(100, False, "6", True, "0.0.0.0/0", (22, 22)),
        AclEntry(200, False, "6", False, "0.0.0.0/0", (22, 22)),
    ) + OPEN_ACL[2:]
    paths, _ = eni_paths(snapshot([sg("sg-1", rule(22, "0.0.0.0/0"))], allow_first), ["eni-1"])
    assert paths[0].refs[1] == "acl-1 #100 allow"


def test_a_narrower_deny_carves_only_its_sources():
    entries = (
        AclEntry(90, False, "-1", False, "0.0.0.0/1"),
        AclEntry(100, False, "-1", True, "0.0.0.0/0"),
    ) + OPEN_ACL[2:]
    paths, _ = eni_paths(snapshot([sg("sg-1", rule(22, "0.0.0.0/0"))], entries), ["eni-1"])
    assert len(paths) == 1  # 128.0.0.0/1 still gets in

    only_denied = snapshot([sg("sg-1", rule(22, "8.8.8.0/24"))], entries)
    assert eni_paths(only_denied, ["eni-1"])[0] == ()


def test_nacl_splits_an_sg_range_by_its_port_rules():
    entries = (
        AclEntry(100, False, "6", True, "0.0.0.0/0", (80, 80)),
        AclEntry(110, False, "6", True, "0.0.0.0/0", (443, 443)),
    ) + OPEN_ACL[2:]
    paths, _ = eni_paths(snapshot([sg("sg-1", rule(0, "0.0.0.0/0", to=1000))], entries), ["eni-1"])
    assert ports_of(paths) == [(80, 80), (443, 443)]
    assert by_port(paths, [22, 80, 443]).keys() == {80, 443}


def test_outbound_must_allow_the_ephemeral_range():
    no_egress = OPEN_ACL[:2] + (AclEntry(100, True, "6", True, "0.0.0.0/0", (443, 443)),)
    assert eni_paths(snapshot([sg("sg-1", rule(22, "0.0.0.0/0"))], no_egress), ["eni-1"])[0] == ()


def test_outbound_on_part_of_the_ephemeral_range_is_a_partial_path():
    narrow = OPEN_ACL[:2] + (AclEntry(100, True, "6", True, "0.0.0.0/0", (32768, 65535)),)
    paths, _ = eni_paths(snapshot([sg("sg-1", rule(22, "0.0.0.0/0"))], narrow), ["eni-1"])
    assert len(paths) == 1 and paths[0].partial
    assert "partial" in paths[0].refs[2]


# --- routes -------------------------------------------------------------------------------------


def test_explicit_association_beats_the_main_table():
    private = RouteTable("rtb-private", VPC, (Route("10.0.0.0/16", "local"), Route("0.0.0.0/0", "nat-1")), subnets=frozenset({"subnet-1"}))
    snap = snapshot([sg("sg-1", rule(22, "0.0.0.0/0"))], tables=(PUBLIC_RT, private))
    assert eni_paths(snap, ["eni-1"])[0] == ()  # explicit NAT table wins: no inbound path

    snap = snapshot([sg("sg-1", rule(22, "0.0.0.0/0"))], tables=(replace(PUBLIC_RT, main=False, subnets=frozenset({"subnet-1"})), replace(private, subnets=frozenset(), main=True)))
    assert len(eni_paths(snap, ["eni-1"])[0]) == 1


def test_a_more_specific_route_decides_for_its_addresses():
    # The office /24 returns through the NAT; the rest of the world through the IGW.
    table = replace(PUBLIC_RT, routes=PUBLIC_RT.routes + (Route("203.0.113.0/24", "nat-1"),))
    office_only = snapshot([sg("sg-1", rule(22, "203.0.113.0/24"))], tables=(table,))
    assert eni_paths(office_only, ["eni-1"])[0] == ()

    world = snapshot([sg("sg-1", rule(22, "0.0.0.0/0"))], tables=(table,))
    paths, _ = eni_paths(world, ["eni-1"])
    assert [(p.cidr, p.refs[-1]) for p in paths] == [("0.0.0.0/0", "rtb-main 0.0.0.0/0 → igw-1")]


def test_a_more_specific_igw_route_narrows_the_path_to_its_addresses():
    # Only the /24 returns through the IGW; the rest of the world's replies go to the NAT.
    table = replace(PUBLIC_RT, routes=(Route("10.0.0.0/16", "local"), Route("0.0.0.0/0", "nat-1"), Route("203.0.113.0/24", "igw-1"), Route("198.51.100.0/24", "igw-1")))
    paths, _ = eni_paths(snapshot([sg("sg-1", rule(22, "0.0.0.0/0"))], tables=(table,)), ["eni-1"])
    assert [(p.cidr, p.refs[-1]) for p in paths] == [("203.0.113.0/24", "rtb-main 203.0.113.0/24 → igw-1"), ("198.51.100.0/24", "rtb-main 198.51.100.0/24 → igw-1")]


def test_an_igw_attached_to_another_vpc_is_no_path():
    snap = replace(snapshot([sg("sg-1", rule(22, "0.0.0.0/0"))]), igws={"igw-1": frozenset({"vpc-other"})})
    assert eni_paths(snap, ["eni-1"])[0] == ()


def test_firewall_endpoint_route_is_unverified():
    table = replace(PUBLIC_RT, routes=(Route("10.0.0.0/16", "local"), Route("0.0.0.0/0", "vpce-fw")))
    snap = snapshot([sg("sg-1", rule(22, "0.0.0.0/0"))], tables=(table,), gateway_endpoints=frozenset({"vpce-fw"}))
    paths, _ = eni_paths(snap, ["eni-1"])
    assert len(paths) == 1 and not paths[0].verified


def test_ingress_routing_on_the_igw_makes_the_path_unverified():
    edge = RouteTable("rtb-edge", VPC, (Route("10.0.1.0/24", "vpce-gwlb"),), gateways=frozenset({"igw-1"}))
    snap = snapshot([sg("sg-1", rule(22, "0.0.0.0/0"))], tables=(PUBLIC_RT, edge))
    assert not eni_paths(snap, ["eni-1"])[0][0].verified


def test_port_limit_for_a_database():
    snap = snapshot([sg("sg-db", rule(0, "0.0.0.0/0", to=65535))])
    paths, _ = eni_paths(snap, ["eni-1"], ports=(5432, 5432))
    assert ports_of(paths) == [(5432, 5432)]


# --- load balancers -----------------------------------------------------------------------------

LB_SG = sg("sg-lb", rule(443, "0.0.0.0/0", "sgr-lb"))


def test_alb_is_reachable_on_listener_ports_only():
    alb = LoadBalancer("api-prod", "application", VPC, ("subnet-1", "subnet-2"), ("sg-lb",), (Listener(443, "HTTPS"), Listener(8443, "HTTPS")))
    paths, _ = lb_paths(snapshot([LB_SG]), alb)
    assert ports_of(paths) == [(443, 443)]
    assert paths[0].refs[0] == "api-prod listener https/443"


def _nlb(sgs=(), preserve=None, target_type="instance", protocol="TCP", healthy=True, target_rules=(rule(443, "0.0.0.0/0", "sgr-t"),)):
    target_sg = sg("sg-target", *target_rules)
    enis = {
        "eni-t": Eni("eni-t", "subnet-2", VPC, ("sg-target",), "10.0.2.9", None, "i-target"),
    }
    tg = TargetGroup("arn:tg", "web-tg", target_type, protocol, (Target("i-target", 443, "eni-t", healthy),), preserve)
    snap = snapshot([LB_SG, target_sg], enis=enis, target_groups={"arn:tg": tg})
    lb = LoadBalancer("edge", "network", VPC, ("subnet-1",), tuple(sgs), (Listener(443, "TCP", ("arn:tg",)),))
    return snap, lb


def test_nlb_without_sg_and_with_client_ip_preservation_needs_the_target_sg():
    snap, lb = _nlb()
    paths, _ = lb_paths(snap, lb)
    assert ports_of(paths) == [(443, 443)]
    assert any("preserves client IP" in r for r in paths[0].refs)
    assert "sg-target rule sgr-t tcp/443 from 0.0.0.0/0" in paths[0].refs

    closed_target, lb = _nlb(target_rules=(rule(443, "10.0.0.0/16"),))
    assert lb_paths(closed_target, lb)[0] == ()


def test_nlb_ip_targets_on_tcp_dont_preserve_the_client_ip_by_default():
    snap, lb = _nlb(target_type="ip", target_rules=(rule(443, "10.0.0.0/16"),))
    paths, _ = lb_paths(snap, lb)
    assert ports_of(paths) == [(443, 443)]
    assert "targets see the load balancer" in paths[0].refs[-1]


def test_nlb_attribute_overrides_the_default():
    snap, lb = _nlb(preserve=True, target_type="ip", target_rules=(rule(443, "10.0.0.0/16"),))
    assert lb_paths(snap, lb)[0] == ()


def test_nlb_with_an_sg_needs_it_to_admit_the_listener_port():
    snap, lb = _nlb(sgs=("sg-lb",))
    assert len(lb_paths(snap, lb)[0]) == 1
    closed = replace(lb, listeners=(Listener(8443, "TCP", ("arn:tg",)),))
    assert lb_paths(snap, closed)[0] == ()


def test_nlb_notes_unhealthy_targets():
    snap, lb = _nlb(healthy=False)
    paths, notes = lb_paths(snap, lb)
    assert paths and notes == ("edge tcp/443: no healthy targets in web-tg",)


# --- lightsail ----------------------------------------------------------------------------------


def test_lightsail_open_port_states_with_internet_cidrs():
    states = [
        {"fromPort": 22, "toPort": 22, "protocol": "tcp", "state": "open", "cidrs": ["0.0.0.0/0"]},
        {"fromPort": 80, "toPort": 80, "protocol": "tcp", "state": "open", "cidrs": ["10.0.0.0/8"]},
        {"fromPort": 53, "toPort": 53, "protocol": "udp", "state": "open", "cidrs": ["0.0.0.0/0"]},
    ]
    paths = lightsail_paths(states, "blog")
    assert [(p.ports, p.cidr) for p in paths] == [((22, 22), "0.0.0.0/0")]


def test_nlb_with_an_sg_reaches_targets_that_admit_the_nlb_sg():
    # Live in staging: the target admits only the NLB's group; preservation is on (instance targets).
    snap, lb = _nlb(sgs=("sg-lb",), target_rules=(rule(443, group="sg-lb", rule_id="sgr-from-lb"),))
    paths, _ = lb_paths(snap, lb)
    assert ports_of(paths) == [(443, 443)]
    assert "sg-target rule sgr-from-lb tcp/443 from sg-lb (the load balancer)" in paths[0].refs

    other_group, lb = _nlb(sgs=("sg-lb",), target_rules=(rule(443, group="sg-other"),))
    assert lb_paths(other_group, lb)[0] == ()
    no_lb_sg, lb = _nlb(target_rules=(rule(443, group="sg-lb"),))
    assert lb_paths(no_lb_sg, lb)[0] == ()


def test_nlb_targets_in_private_subnets_need_no_internet_route():
    # Live in staging: the NLB sits in a public subnet, its targets in a private one routed via NAT.
    private = RouteTable("rtb-private", VPC, (Route("10.0.0.0/16", "local"), Route("0.0.0.0/0", "nat-1")), subnets=frozenset({"subnet-2"}))
    snap, lb = _nlb(sgs=("sg-lb",), target_rules=(rule(443, group="sg-lb", rule_id="sgr-from-lb"),))
    snap = replace(snap, route_tables=(replace(PUBLIC_RT, main=False, subnets=frozenset({"subnet-1"})), private))
    paths, _ = lb_paths(snap, lb)
    assert ports_of(paths) == [(443, 443)]
    assert not any("rtb-private" in r for r in paths[0].refs)


def test_nlb_targets_see_only_the_sources_a_narrowed_front_path_admits():
    snap, lb = _nlb()
    half = replace(PUBLIC_RT, routes=(Route("10.0.0.0/16", "local"), Route("0.0.0.0/0", "nat-1"), Route("0.0.0.0/1", "igw-1")))
    paths, _ = lb_paths(replace(snap, route_tables=(half,)), lb)
    assert len(paths) == 1 and paths[0].cidr.startswith("1.0.0.0/8, 2.0.0.0/7") and "10.0.0.0" not in paths[0].cidr


def test_nlb_notes_a_target_outside_the_vpc():
    snap, lb = _nlb(target_type="ip", preserve=True)
    tg = snap.target_groups["arn:tg"]
    snap = replace(snap, target_groups={"arn:tg": replace(tg, targets=(Target("172.31.9.9", 443, None, True),))})
    paths, notes = lb_paths(snap, lb)
    assert paths == () and notes == ("edge tcp/443: target 172.31.9.9 in web-tg has no network interface in this account and region (a peered or on-premises address?); its path isn't analysed",)
