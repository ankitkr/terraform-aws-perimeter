"""What counts as the internet, and the address-set arithmetic the path analysis needs.

An address set is a tuple of non-overlapping ip_network objects of one family."""

import ipaddress

# Never internet: private (RFC 1918), shared/CGNAT (RFC 6598), loopback, link-local, and
# "this network". Multicast and reserved space can't be a TCP client either.
NOT_INTERNET_V4 = tuple(
    ipaddress.ip_network(n)
    for n in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "224.0.0.0/3",
    )
)
# IPv6: global unicast is 2000::/3; everything else (ULA, link-local, loopback) isn't internet.
GLOBAL_V6 = ipaddress.ip_network("2000::/3")


def network(cidr):
    return ipaddress.ip_network(cidr, strict=False)


def collapse(nets):
    nets = list(nets)
    if not nets:
        return ()
    return tuple(ipaddress.collapse_addresses(nets))


def subtract(nets, removed):
    """nets minus removed (both address sets of one family)."""
    out = list(nets)
    for r in removed:
        if r.version != (out[0].version if out else r.version):
            continue
        next_out = []
        for n in out:
            if not n.overlaps(r):
                next_out.append(n)
            elif r.supernet_of(n) or r == n:
                continue
            else:  # n contains r
                next_out.extend(n.address_exclude(r))
        out = next_out
    return collapse(out)


def intersect(a, b):
    out = []
    for x in a:
        for y in b:
            if x.version != y.version or not x.overlaps(y):
                continue
            out.append(x if y.supernet_of(x) or x == y else y)
    return collapse(out)


def internet(vpc_cidrs=(), version=4):
    """The internet as an address set, given the VPC's own CIDRs (excluded: a VPC can use
    public space internally)."""
    own = [network(c) for c in vpc_cidrs if network(c).version == version]
    if version == 4:
        return subtract([ipaddress.ip_network("0.0.0.0/0")], list(NOT_INTERNET_V4) + own)
    return subtract([GLOBAL_V6], own)


def internet_part(cidr, vpc_cidrs=()):
    """The internet addresses inside cidr (empty when it has none)."""
    net = network(cidr)
    return intersect((net,), internet(vpc_cidrs, net.version))


def is_internet(cidr, vpc_cidrs=()):
    """Whether cidr contains any internet address: 0.0.0.0/0 does, 10.0.0.0/8 doesn't."""
    return bool(internet_part(cidr, vpc_cidrs))


def is_global_ipv4(ip):
    """A single address the scanner may touch: IPv4 and on the internet."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.version == 4 and is_internet(f"{ip}/32")


def expand_prefix_list(prefix_list, vpc_cidrs=()):
    """The internet CIDRs in a customer-managed prefix list's entries."""
    return tuple(c for c in prefix_list if is_internet(c, vpc_cidrs))
