from __future__ import annotations

import hashlib
import json
from pathlib import Path
import stat
import tempfile
import unittest
from zipfile import ZipFile, ZipInfo

import h5py
import numpy as np

from ipsec_sentinel.external.acquire import VerifiedArtifact
from ipsec_sentinel.external.inspect import (
    ArchiveSafetyError,
    inspect_artifact,
    safe_extract_zip,
)
from ipsec_sentinel.external.registry import ExternalDatasetRegistry
from ipsec_sentinel.external.storage import ExternalPaths


REGISTRY = ExternalDatasetRegistry.load(Path("metadata/external-datasets.yaml"))


def _verified(path: Path) -> VerifiedArtifact:
    data = path.read_bytes()
    return VerifiedArtifact(path, len(data), hashlib.sha256(data).hexdigest(), "absent")


class ExternalInspectTest(unittest.TestCase):
    def test_zip_inventory_records_members_types_sizes_and_digest(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            archive = base / "fixture.zip"
            with ZipFile(archive, "w") as output:
                output.writestr("metadata.json", '{"protocol":"ipsec"}')
                output.writestr("runs/status.txt", "ESTABLISHED")
            paths = ExternalPaths.create(base / "external")

            report = inspect_artifact(
                REGISTRY.source("usbvpn2022"), _verified(archive), paths
            )

            self.assertEqual(report.format, "zip")
            self.assertEqual(report.artifact_sha256, hashlib.sha256(archive.read_bytes()).hexdigest())
            self.assertEqual(
                [(item["path"], item["size_bytes"], item["kind"]) for item in report.structure],
                [("metadata.json", 20, "file"), ("runs/status.txt", 11, "file")],
            )
            self.assertTrue(report.inventory_path.is_file())
            persisted = json.loads(report.inventory_path.read_text(encoding="utf-8"))
            self.assertEqual(persisted["member_count"], 2)

    def test_zip_rejects_traversal_absolute_symlink_duplicate_and_expansion_bomb(self):
        cases = ("traversal", "absolute", "symlink", "duplicate", "expansion")
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary)
                archive = base / "unsafe.zip"
                with ZipFile(archive, "w") as output:
                    if case == "traversal":
                        output.writestr("../escape", "bad")
                    elif case == "absolute":
                        output.writestr("/absolute", "bad")
                    elif case == "symlink":
                        info = ZipInfo("link")
                        info.create_system = 3
                        info.external_attr = (stat.S_IFLNK | 0o777) << 16
                        output.writestr(info, "target")
                    elif case == "duplicate":
                        output.writestr("folder/file", "one")
                        output.writestr("folder//file", "two")
                    else:
                        output.writestr("large", "x" * 64)
                destination = base / "published"
                with self.assertRaises(ArchiveSafetyError):
                    safe_extract_zip(
                        _verified(archive), destination,
                        max_expanded_bytes=32 if case == "expansion" else 1024,
                        max_members=10,
                    )
                self.assertFalse(destination.exists())

    def test_hdf5_inventory_records_groups_datasets_dtypes_shapes_and_sample_values(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            source = base / "fixture.h5"
            dtype = np.dtype([
                ("session_id", "i4"),
                ("timestamp", "f8"),
                ("packet_size", "i4"),
                ("direction", "i1"),
                ("label", "S16"),
            ])
            rows = np.array(
                [(7, 0.0, 128, 1, b"Chat"), (7, 0.2, 256, -1, b"Chat")],
                dtype=dtype,
            )
            with h5py.File(source, "w") as output:
                group = output.create_group("vpn")
                group.attrs["protocol"] = "VPN"
                group.create_dataset("packets", data=rows)
            paths = ExternalPaths.create(base / "external")

            report = inspect_artifact(
                REGISTRY.source("mit_ll_vnat"), _verified(source), paths
            )

            dataset = next(item for item in report.structure if item["kind"] == "dataset")
            self.assertEqual(dataset["path"], "/vpn/packets")
            self.assertEqual(dataset["shape"], [2])
            self.assertIn("session_id", dataset["fields"])
            self.assertEqual(dataset["sample"][0]["packet_size"], 128)
            self.assertEqual(report.semantic_findings["timestamp"], "observed")
            self.assertTrue(report.compatible)

    def test_ambiguous_packet_semantics_are_incompatible_with_reason_codes(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            source = base / "ambiguous.h5"
            with h5py.File(source, "w") as output:
                output.create_dataset("numbers", data=[1, 2, 3])
            paths = ExternalPaths.create(base / "external")

            report = inspect_artifact(
                REGISTRY.source("mit_ll_vnat"), _verified(source), paths
            )

            self.assertFalse(report.compatible)
            self.assertEqual(
                set(report.compatibility_reasons),
                {"missing_timestamp", "missing_size", "missing_direction", "missing_session", "missing_label"},
            )

    def test_object_dataset_is_never_deserialized_for_sampling(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            source = base / "object.h5"
            with h5py.File(source, "w") as output:
                output.attrs["empty"] = h5py.Empty("f")
                output.create_dataset(
                    "object_block",
                    data=np.asarray([b"opaque"], dtype=object),
                    dtype=h5py.special_dtype(vlen=bytes),
                )
            paths = ExternalPaths.create(base / "external")

            report = inspect_artifact(
                REGISTRY.source("mit_ll_vnat"), _verified(source), paths
            )

        dataset = next(item for item in report.structure if item["kind"] == "dataset")
        self.assertEqual(dataset["sample_omitted"], "variable-length/object dataset")
        self.assertNotIn("sample", dataset)
        self.assertIn("unbounded_object_block", report.compatibility_reasons)


if __name__ == "__main__":
    unittest.main()
