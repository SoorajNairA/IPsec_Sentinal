from __future__ import annotations

import unittest

from ipsec_sentinel.external.models import (
    EXTERNAL_OBSERVATION_SCHEMA_VERSION,
    ExternalPacketObservation,
    ExternalSession,
)


def _packet(index: int, time_us: int, **changes: object) -> ExternalPacketObservation:
    values: dict[str, object] = {
        "schema_version": EXTERNAL_OBSERVATION_SCHEMA_VERSION,
        "parent_session_id": "source/session-7",
        "packet_index": index,
        "relative_timestamp_us": time_us,
        "packet_size_bytes": 128 + index,
        "direction": "forward" if index % 2 == 0 else "reverse",
        "label": "messaging",
        "source_dataset": "mit_ll_vnat",
        "vpn_protocol": "vpn_unspecified",
    }
    values.update(changes)
    return ExternalPacketObservation(**values)  # type: ignore[arg-type]


class ExternalModelTest(unittest.TestCase):
    def test_observation_requires_nonnegative_monotonic_fields_valid_size_and_direction(self):
        for changes in (
            {"packet_index": -1},
            {"relative_timestamp_us": -1},
            {"packet_size_bytes": 0},
            {"direction": "sideways"},
            {"schema_version": "wrong"},
        ):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                _packet(0, 0, **changes)

        with self.assertRaisesRegex(ValueError, "monotonic"):
            ExternalSession(
                (_packet(0, 10), _packet(1, 9)),
                {"original_label": "Chat"},
                "compatible",
            )
        with self.assertRaisesRegex(ValueError, "packet indices"):
            ExternalSession(
                (_packet(0, 0), _packet(2, 1)),
                {"original_label": "Chat"},
                "compatible",
            )

    def test_session_rejects_mixed_parent_source_protocol_or_label(self):
        with self.assertRaisesRegex(ValueError, "non-empty"):
            ExternalSession((), {}, "compatible")
        for field, value in (
            ("parent_session_id", "other/session"),
            ("source_dataset", "other_source"),
            ("vpn_protocol", "openvpn"),
            ("label", "video"),
        ):
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "mixed"):
                ExternalSession(
                    (_packet(0, 0), _packet(1, 1, **{field: value})),
                    {"original_label": "Chat"},
                    "compatible",
                )


if __name__ == "__main__":
    unittest.main()
