"""What counts as the internet."""

import pytest

from internet import expand_prefix_list, internet_part, is_global_ipv4, is_internet


@pytest.mark.parametrize(
    "cidr",
    ["0.0.0.0/0", "203.0.113.0/24", "8.8.8.8/32", "0.0.0.0/1", "::/0", "2001:db8::/32", "10.0.0.0/7"],
)
def test_internet(cidr):
    assert is_internet(cidr)


@pytest.mark.parametrize(
    "cidr",
    ["10.0.0.0/8", "10.1.2.0/24", "172.16.0.0/12", "192.168.1.0/24", "100.64.0.0/10", "127.0.0.1/32", "169.254.169.254/32", "fd00::/8", "fe80::/10", "::1/128"],
)
def test_not_internet(cidr):
    assert not is_internet(cidr)


def test_the_vpcs_own_ranges_are_not_internet():
    # A VPC built on public space: its own CIDR is internal, the rest of the internet isn't.
    assert is_internet("198.51.100.0/24")
    assert not is_internet("198.51.100.0/24", vpc_cidrs=["198.51.100.0/24"])
    assert is_internet("198.51.0.0/16", vpc_cidrs=["198.51.100.0/24"])


def test_the_internet_part_of_a_wide_range_excludes_private_space():
    part = internet_part("8.0.0.0/5")  # 8.0.0.0 - 15.255.255.255 holds 10/8
    assert all(not n.overlaps(__import__("ipaddress").ip_network("10.0.0.0/8")) for n in part)
    assert sum(n.num_addresses for n in part) == 2**27 - 2**24


def test_prefix_list_expansion_keeps_internet_entries_only():
    assert expand_prefix_list(["10.0.0.0/8", "203.0.113.7/32", "192.168.0.0/16"]) == ("203.0.113.7/32",)


@pytest.mark.parametrize("ip,ok", [("203.0.113.9", True), ("10.0.0.1", False), ("100.64.1.1", False), ("127.0.0.1", False), ("2001:db8::1", False), ("nope", False)])
def test_scanner_targets_are_global_ipv4_only(ip, ok):
    assert is_global_ipv4(ip) is ok
