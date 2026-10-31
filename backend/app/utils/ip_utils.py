"""IP address policy helpers."""

import ipaddress
from ipaddress import IPv4Address, IPv6Address


def ip_flags(address: IPv4Address | IPv6Address) -> dict[str, bool]:
    """Return security-relevant classification flags for an IP address."""
    return {
        "is_private": address.is_private,
        "is_loopback": address.is_loopback,
        "is_link_local": address.is_link_local,
        "is_multicast": address.is_multicast,
        "is_reserved": address.is_reserved,
        "is_global": address.is_global,
    }


def parse_ip(value: str) -> tuple[str, dict[str, bool]]:
    """Parse an IP and return its canonical compressed form and flags."""
    address = ipaddress.ip_address(value)
    return address.compressed, ip_flags(address)
