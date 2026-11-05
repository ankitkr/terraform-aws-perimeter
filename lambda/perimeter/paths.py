"""Why an endpoint is reachable from the internet: security group, NACL and route, worked out
over a normalized snapshot of one region. Pure: inventory.py builds the snapshot.

Every result is a tuple of Path, each for a range of TCP ports with the references that let a
client in ("sg-1 rule sgr-9 tcp/22 from 0.0.0.0/0", "acl-2 #100 allow", "rtb-3 0.0.0.0/0 → igw-4").
"""

from dataclasses import dataclass, field

import internet
from model import Path

TCP = ("6", "tcp", "-1")
EPHEMERAL = (1024, 65535)
ALL_PORTS = (0, 65535)


# --- the snapshot -------------------------------------------------------------------------------


@dataclass(frozen=True)
class SgRule:
    rule_id: str
    protocol: str  # "tcp", "6", "-1", "udp", …
    from_port: int | None
    to_port: int | None
    cidr: str | None = None
    prefix_list: str | None = None
    group: str | None = None  # another security group: never an internet path

    @property
    def ports(self):
        if self.protocol == "-1" or self.from_port is None or self.from_port == -1:
            return ALL_PORTS
        return (self.from_port, self.to_port)


@dataclass(frozen=True)
class SecurityGroup:
    id: str
    vpc_id: str
    name: str = ""
    ingress: tuple[SgRule, ...] = ()


@dataclass(frozen=True)
class AclEntry:
    number: int
    egress: bool
    protocol: str  # "6", "-1", …
    allow: bool
    cidr: str
    ports: tuple[int, int] | None = None  # None: all ports


@dataclass(frozen=True)
class NetworkAcl:
    id: str
    vpc_id: str
    entries: tuple[AclEntry, ...]
    subnets: frozenset[str] = frozenset()


@dataclass(frozen=True)
class Route:
    destination: str  # IPv4 or IPv6 CIDR; prefix-list routes are expanded by inventory
    target: str  # igw-…, nat-…, vpce-…, tgw-…, local, eni-…, pcx-…, vgw-…, eigw-…
    active: bool = True


@dataclass(frozen=True)
class RouteTable:
    id: str
    vpc_id: str
    routes: tuple[Route, ...]
    subnets: frozenset[str] = frozenset()
    main: bool = False
    gateways: frozenset[str] = frozenset()  # edge associations (ingress routing)


@dataclass(frozen=True)
class PrefixList:
    id: str
    name: str
    aws_managed: bool
    cidrs: tuple[str, ...] = ()


@dataclass(frozen=True)
class Eni:
    id: str
    subnet_id: str
    vpc_id: str
    security_groups: tuple[str, ...]
    private_ip: str = ""
    public_ip: str | None = None
    instance_id: str | None = None


@dataclass(frozen=True)
class Target:
    id: str  # instance id or IP address
    port: int
    eni_id: str | None  # resolved by inventory; None when it couldn't be
    healthy: bool | None = None


@dataclass(frozen=True)
class TargetGroup:
    arn: str
    name: str
    target_type: str  # instance | ip | lambda | alb
    protocol: str  # TCP | TLS | UDP | TCP_UDP | HTTP | HTTPS
    targets: tuple[Target, ...] = ()
    preserve_client_ip: bool | None = None  # None: the attribute wasn't read; use AWS's default

    @property
    def preserves_client_ip(self):
        if self.preserve_client_ip is not None:
            return self.preserve_client_ip
        if self.target_type == "instance":
            return True
        return self.protocol in ("UDP", "TCP_UDP")


@dataclass(frozen=True)
class Listener:
    port: int
    protocol: str
    target_groups: tuple[str, ...] = ()  # ARNs


@dataclass(frozen=True)
class LoadBalancer:
    name: str
    type: str  # application | network | classic
    vpc_id: str
    subnets: tuple[str, ...]
    security_groups: tuple[str, ...]
    listeners: tuple[Listener, ...]


@dataclass(frozen=True)
class Snapshot:
    vpcs: dict = field(default_factory=dict)  # vpc id -> tuple of CIDRs (IPv4 and IPv6)
    security_groups: dict = field(default_factory=dict)  # id -> SecurityGroup
    acls: tuple[NetworkAcl, ...] = ()
    route_tables: tuple[RouteTable, ...] = ()
    igws: dict = field(default_factory=dict)  # igw id -> frozenset of attached VPC ids
    prefix_lists: dict = field(default_factory=dict)  # id -> PrefixList
    enis: dict = field(default_factory=dict)  # id -> Eni
    target_groups: dict = field(default_factory=dict)  # arn -> TargetGroup
    gateway_endpoints: frozenset[str] = frozenset()  # vpce ids of GWLB / Network Firewall endpoints

    def acl_for(self, subnet_id):
        return next((a for a in self.acls if subnet_id in a.subnets), None)

    def route_table_for(self, subnet_id, vpc_id):
        explicit = next((t for t in self.route_tables if subnet_id in t.subnets), None)
        return explicit or next((t for t in self.route_tables if t.vpc_id == vpc_id and t.main), None)


# --- security groups ----------------------------------------------------------------------------


@dataclass(frozen=True)
class Grant:
    """A security group rule letting some internet addresses in on a port range."""

    ports: tuple[int, int]
    sources: tuple  # address set
    cidr: str  # as written in the rule: "0.0.0.0/0", or "pl-1 (office): 203.0.113.0/24"
    ref: str


def _rule_ref(sg, rule, source):
    lo, hi = rule.ports
    ports = "all" if (lo, hi) == ALL_PORTS else (f"tcp/{lo}" if lo == hi else f"tcp/{lo}-{hi}")
    return f"{sg.id} rule {rule.rule_id} {ports} from {source}"


def grants(snap, sg_ids, vpc_id):
    """(internet grants, notes): the internet sources each group's ingress rules admit over TCP.
    AWS-managed prefix lists become notes: only that service can reach the port."""
    vpc_cidrs = snap.vpcs.get(vpc_id, ())
    found, notes = [], []
    for sg_id in sg_ids:
        sg = snap.security_groups.get(sg_id)
        if sg is None:
            continue
        for rule in sg.ingress:
            if rule.protocol not in TCP or rule.group:
                continue
            if rule.cidr:
                sources = internet.internet_part(rule.cidr, vpc_cidrs)
                if sources:
                    found.append(Grant(rule.ports, sources, rule.cidr, _rule_ref(sg, rule, rule.cidr)))
            elif rule.prefix_list:
                pl = snap.prefix_lists.get(rule.prefix_list)
                if pl is None:
                    notes.append(f"{sg.id} rule {rule.rule_id}: prefix list {rule.prefix_list} unreadable; not analysed")
                elif pl.aws_managed:
                    lo, hi = rule.ports
                    notes.append(f"tcp/{lo}-{hi} reachable only from {pl.name} ({pl.id}), via {sg.id} rule {rule.rule_id}")
                else:
                    for cidr in internet.expand_prefix_list(pl.cidrs, vpc_cidrs):
                        label = f"{pl.id} ({pl.name}): {cidr}"
                        found.append(Grant(rule.ports, internet.internet_part(cidr, vpc_cidrs), label, _rule_ref(sg, rule, label)))
    return found, notes


# --- NACLs --------------------------------------------------------------------------------------


def _segments(ports, entries):
    """Split a port range at every entry boundary, so each piece meets the NACL uniformly."""
    lo, hi = ports
    cuts = {lo, hi + 1}
    for e in entries:
        if e.ports:
            for edge in (e.ports[0], e.ports[1] + 1):
                if lo < edge <= hi:
                    cuts.add(edge)
    edges = sorted(cuts)
    return [(a, b - 1) for a, b in zip(edges, edges[1:])]


def _applies(entry, egress, port_range):
    if entry.egress != egress or entry.protocol not in TCP:
        return False
    return entry.ports is None or (entry.ports[0] <= port_range[0] and port_range[1] <= entry.ports[1])


def _walk(acl, egress, port_range, sources):
    """Rule-order evaluation for one uniform port range: (allowed address set, first allowing
    entry). Entries carve the source set: an address meets only the first entry matching it."""
    remaining, allowed, first = sources, (), None
    for e in sorted(acl.entries, key=lambda e: e.number):
        if not remaining:
            break
        if not _applies(e, egress, port_range):
            continue
        net = (internet.network(e.cidr),)
        hit = internet.intersect(remaining, net)
        if hit and e.allow:
            allowed = internet.collapse(list(allowed) + list(hit))
            first = first or e
        remaining = internet.subtract(remaining, net)
    return allowed, first


def _acl_label(acl, entry, egress):
    direction = "egress " if egress else ""
    return f"{acl.id} {direction}#{entry.number} allow"


def acl_inbound(acl, ports, sources):
    """[(port range, allowed sources, ref)] for the inbound side, merged where uniform."""
    out = []
    for seg in _segments(ports, [e for e in acl.entries if not e.egress]):
        allowed, entry = _walk(acl, False, seg, sources)
        if allowed:
            ref = _acl_label(acl, entry, False)
            if out and out[-1][0][1] + 1 == seg[0] and out[-1][1] == allowed and out[-1][2] == ref:
                out[-1] = ((out[-1][0][0], seg[1]), allowed, ref)
            else:
                out.append((seg, allowed, ref))
    return out


def acl_outbound(acl, destinations):
    """(full, partial, ref): whether replies to destinations can leave on every ephemeral port,
    on only some (a partial path), or on none (both False)."""
    every, some, ref = True, False, None
    for seg in _segments(EPHEMERAL, [e for e in acl.entries if e.egress]):
        allowed, entry = _walk(acl, True, seg, destinations)
        if allowed:
            some = True
            ref = ref or _acl_label(acl, entry, True)
        if allowed != destinations:
            every = False
    if not some:
        return False, False, None
    if every:
        return True, False, f"{ref} 1024-65535"
    return False, True, f"{ref} (partial: replies on only part of 1024-65535)"


# --- routes -------------------------------------------------------------------------------------


def route_out(snap, subnet_id, vpc_id, destinations):
    """[(route destination, verified, ref)] for the most specific routes that send replies to
    some of destinations through an internet gateway attached to this VPC (or an appliance in
    front of one)."""
    table = snap.route_table_for(subnet_id, vpc_id)
    if table is None:
        return []
    edge = any(t.vpc_id == vpc_id and t.gateways and any(g.startswith("igw-") for g in t.gateways) for t in snap.route_tables)
    routes = sorted(
        (r for r in table.routes if r.active),
        key=lambda r: internet.network(r.destination).prefixlen,
        reverse=True,
    )
    out, remaining = [], destinations
    for r in routes:
        net = internet.network(r.destination)
        if not remaining or remaining[0].version != net.version:
            continue
        hit = internet.intersect(remaining, (net,))
        if not hit:
            continue
        ref = f"{table.id} {r.destination} → {r.target}"
        if r.target.startswith("igw-") and vpc_id in snap.igws.get(r.target, frozenset()):
            # Ingress routing on the gateway sends inbound traffic through an appliance first.
            out.append((net, not edge, ref))
        elif r.target in snap.gateway_endpoints or r.target.startswith("tgw-"):
            out.append((net, False, f"{ref} (through an appliance or transit gateway: unverified)"))
        remaining = internet.subtract(remaining, (net,))
    return out


def _narrowed(cidr, allowed, route):
    """The path's source: the rule's, or only the part of it a more specific route returns."""
    if internet.subtract(allowed, (route,)):
        return ", ".join(str(n) for n in internet.intersect(allowed, (route,)))
    return cidr


# --- composition --------------------------------------------------------------------------------


def _through_subnet(snap, subnet_id, vpc_id, grant, port_range, lead=(), route=True):
    """Paths for one grant through one subnet's NACL and, with route, its route table. A load
    balancer's target needs no route of its own: the load balancer delivers the traffic and
    carries the replies."""
    acl = snap.acl_for(subnet_id)
    if acl is None:
        return []
    lo, hi = max(port_range[0], grant.ports[0]), min(port_range[1], grant.ports[1])
    if lo > hi:
        return []
    out = []
    for seg, allowed, acl_ref in acl_inbound(acl, (lo, hi), grant.sources):
        full, partial, out_ref = acl_outbound(acl, allowed)
        if not (full or partial):
            continue
        if not route:
            out.append(Path(seg, (*lead, grant.ref, acl_ref, out_ref), grant.cidr, True, partial))
            continue
        for route, verified, route_ref in route_out(snap, subnet_id, vpc_id, allowed):
            out.append(Path(seg, (*lead, grant.ref, acl_ref, out_ref, route_ref), _narrowed(grant.cidr, allowed, route), verified, partial))
    return out


def _dedupe(paths):
    seen, out = set(), []
    for p in paths:
        if p not in seen:
            seen.add(p)
            out.append(p)
    return tuple(out)


def eni_paths(snap, eni_ids, ports=ALL_PORTS):
    """Paths to the given ENIs (one endpoint's addresses), optionally limited to a port range
    (a database's engine port). Returns (paths, notes)."""
    paths, notes = [], []
    for eni_id in eni_ids:
        eni = snap.enis.get(eni_id)
        if eni is None:
            continue
        found, more = grants(snap, eni.security_groups, eni.vpc_id)
        notes += more
        for g in found:
            paths += _through_subnet(snap, eni.subnet_id, eni.vpc_id, g, ports)
    return _dedupe(paths), tuple(dict.fromkeys(notes))


def _listener_grants(snap, lb, listener):
    found, notes = grants(snap, lb.security_groups, lb.vpc_id)
    return [g for g in found if g.ports[0] <= listener.port <= g.ports[1]], notes


def _open_grant(listener):
    """A network load balancer without security groups admits every source."""
    world = internet.internet()
    return Grant((listener.port, listener.port), world, "0.0.0.0/0", f"no security group on the load balancer: tcp/{listener.port} from anywhere")


def lb_paths(snap, lb):
    """Paths to a load balancer's listeners. Returns (paths, notes)."""
    paths, notes = [], []
    for listener in lb.listeners:
        if listener.protocol in ("UDP",):
            continue
        port = (listener.port, listener.port)
        lead = (f"{lb.name} listener {listener.protocol.lower()}/{listener.port}",)
        if lb.type == "network" and not lb.security_groups:
            front = [_open_grant(listener)]
        else:
            front, more = _listener_grants(snap, lb, listener)
            notes += more
        reached = []
        for g in front:
            for subnet in lb.subnets:
                reached += _through_subnet(snap, subnet, lb.vpc_id, g, port, lead)
        if lb.type != "network" or not reached:
            paths += reached
            continue
        target_paths, more = _nlb_targets(snap, lb, listener, reached)
        paths += target_paths
        notes += more
    return _dedupe(paths), tuple(dict.fromkeys(notes))


def _lb_group_rules(snap, sg_ids, lb_groups):
    """(ports, ref) for the TCP ingress rules in these groups that admit the load balancer's own
    security groups."""
    found = []
    for sg_id in sg_ids:
        sg = snap.security_groups.get(sg_id)
        for rule in sg.ingress if sg else ():
            if rule.protocol in TCP and rule.group in lb_groups:
                found.append((rule.ports, _rule_ref(sg, rule, f"{rule.group} (the load balancer)")))
    return found


def _nlb_targets(snap, lb, listener, front_paths):
    """With client-IP preservation the target's own security group and subnet NACL see the
    client's address, so they must admit it too, either by CIDR or, when the NLB has security
    groups, by a rule that references them; without preservation the target sees the load
    balancer."""
    paths, notes = [], []
    for arn in listener.target_groups:
        tg = snap.target_groups.get(arn)
        if tg is None:
            continue
        if not tg.targets:
            notes.append(f"{lb.name} tcp/{listener.port}: target group {tg.name} has no targets")
            continue
        if not any(t.healthy for t in tg.targets):
            notes.append(f"{lb.name} tcp/{listener.port}: no healthy targets in {tg.name}")
        if not tg.preserves_client_ip:
            for p in front_paths:
                paths.append(Path(p.ports, (*p.refs, f"{tg.name} without client-IP preservation: targets see the load balancer"), p.cidr, p.verified, p.partial))
            continue
        for t in tg.targets:
            eni = snap.enis.get(t.eni_id) if t.eni_id else None
            if eni is None:
                notes.append(f"{lb.name} tcp/{listener.port}: target {t.id} in {tg.name} has no network interface in this account and region (a peered or on-premises address?); its path isn't analysed")
                continue
            target_grants, more = grants(snap, eni.security_groups, eni.vpc_id)
            notes += more
            via_lb = _lb_group_rules(snap, eni.security_groups, set(lb.security_groups))
            for front in front_paths:
                client = internet.collapse(n for c in front.cidr.rsplit(": ", 1)[-1].split(", ") for n in internet.internet_part(c))
                candidates = [Grant(g.ports, internet.intersect(g.sources, client), front.cidr, g.ref) for g in target_grants]
                candidates += [Grant(ports, client, front.cidr, ref) for ports, ref in via_lb]
                for narrowed in candidates:
                    if not narrowed.sources:
                        continue
                    lead = (*front.refs, f"{tg.name} preserves client IP → {t.id}:{t.port}")
                    for p in _through_subnet(snap, eni.subnet_id, eni.vpc_id, narrowed, (t.port, t.port), lead, route=False):
                        paths.append(Path(front.ports, p.refs, front.cidr, p.verified and front.verified, p.partial or front.partial))
    return paths, notes


def lightsail_paths(port_states, instance):
    """Lightsail's firewall is the only control in front of an instance: an open port state with
    an internet CIDR is a path."""
    paths = []
    for s in port_states:
        if s.get("state") != "open" or s.get("protocol") not in ("tcp", "all"):
            continue
        lo, hi = s.get("fromPort", 0), s.get("toPort", 65535)
        if s.get("protocol") == "all":
            lo, hi = ALL_PORTS
        for cidr in list(s.get("cidrs") or ()) + list(s.get("ipv6Cidrs") or ()):
            if internet.is_internet(cidr):
                paths.append(Path((lo, hi), (f"lightsail {instance} firewall tcp/{lo}-{hi} from {cidr}",), cidr))
    return _dedupe(paths)


def by_port(paths, ports):
    """The spec's view of paths: {port: [Path]} for the given ports."""
    return {port: [p for p in paths if p.covers(port)] for port in ports if any(p.covers(port) for p in paths)}
