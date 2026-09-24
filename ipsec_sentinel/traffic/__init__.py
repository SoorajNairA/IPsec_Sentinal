"""Seeded local traffic generators."""

from ipsec_sentinel.traffic.base import register_generator, traffic_classes


def register_builtin_generators() -> None:
    from ipsec_sentinel.traffic.icmp import IcmpGenerator

    registered = set(traffic_classes())
    if "icmp" not in registered:
        register_generator("icmp", IcmpGenerator)
