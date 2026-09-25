"""Seeded local traffic generators."""

from ipsec_sentinel.traffic.base import register_generator, traffic_classes


def register_builtin_generators() -> None:
    from ipsec_sentinel.traffic.icmp import IcmpGenerator
    from ipsec_sentinel.traffic.video import VideoGenerator
    from ipsec_sentinel.traffic.web import WebGenerator

    registered = set(traffic_classes())
    if "icmp" not in registered:
        register_generator(
            "icmp", IcmpGenerator, known_training_class=True,
            version=IcmpGenerator.version,
        )
    if "web" not in registered:
        register_generator(
            "web", WebGenerator, known_training_class=True,
            version=WebGenerator.version,
        )
    if "video" not in registered:
        register_generator(
            "video", VideoGenerator, known_training_class=True,
            version=VideoGenerator.version,
        )
