"""Seeded local traffic generators."""

from ipsec_sentinel.traffic.base import register_generator, traffic_classes


def register_builtin_generators() -> None:
    from ipsec_sentinel.traffic.email import EmailGenerator
    from ipsec_sentinel.traffic.file_transfer import FileTransferGenerator
    from ipsec_sentinel.traffic.icmp import IcmpGenerator
    from ipsec_sentinel.traffic.messaging import MessagingGenerator
    from ipsec_sentinel.traffic.video import VideoGenerator
    from ipsec_sentinel.traffic.voip import VoipGenerator
    from ipsec_sentinel.traffic.web import WebGenerator

    registered = set(traffic_classes())
    if "email" not in registered:
        register_generator(
            "email", EmailGenerator, known_training_class=True,
            version=EmailGenerator.version,
        )
    if "file_transfer" not in registered:
        register_generator(
            "file_transfer", FileTransferGenerator, known_training_class=True,
            version=FileTransferGenerator.version,
        )
    if "icmp" not in registered:
        register_generator(
            "icmp", IcmpGenerator, known_training_class=True,
            version=IcmpGenerator.version,
        )
    if "messaging" not in registered:
        register_generator(
            "messaging", MessagingGenerator, known_training_class=True,
            version=MessagingGenerator.version,
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
    if "voip" not in registered:
        register_generator(
            "voip", VoipGenerator, known_training_class=True,
            version=VoipGenerator.version,
        )
