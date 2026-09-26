from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from ipsec_sentinel.external.config import ExternalConfig
from ipsec_sentinel.external.storage import ExternalPaths, resolve_external_root


class ExternalStorageTest(unittest.TestCase):
    def test_environment_root_overrides_local_config(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            configured = base / "configured"
            overridden = base / "overridden"
            config = base / "external.yaml"
            config.write_text(
                "schema_version: ipsec-sentinel.external-config/v1\n"
                f"external_data_root: {configured}\n",
                encoding="utf-8",
            )

            loaded = ExternalConfig.load(
                config, {"IPSEC_SENTINEL_EXTERNAL_DATA_ROOT": str(overridden)}
            )

            self.assertEqual(loaded.external_data_root, overridden.resolve())

    def test_default_example_resolves_expected_wsl_ext4_root(self):
        loaded = ExternalConfig.load(
            Path("configs/external-datasets.example.yaml"), {}
        )
        self.assertEqual(
            loaded.external_data_root,
            Path("/home/black/ipsec-sentinel-external-datasets"),
        )

    def test_rejects_missing_root_repo_one_drive_mnt_and_symlink_escape(self):
        repo = Path.cwd().resolve()
        rejected = (
            "",
            str(repo),
            str(repo / "external-data"),
            "/mnt/c/external-data",
            "/tmp/OneDrive/external-data",
        )
        for raw in rejected:
            with self.subTest(raw=raw):
                with self.assertRaises(ValueError):
                    resolve_external_root(raw, repo)

        with tempfile.TemporaryDirectory() as temporary:
            link = Path(temporary) / "apparently-safe"
            link.symlink_to(repo, target_is_directory=True)
            with self.assertRaises(ValueError):
                resolve_external_root(str(link / "external"), repo)
            self.assertFalse((repo / "external").exists())

    def test_external_paths_create_only_under_resolved_root(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            root = resolve_external_root(str(parent / "external"), Path.cwd())

            paths = ExternalPaths.create(root)

            self.assertEqual(paths.root, root)
            expected = {
                paths.downloads,
                paths.extracted,
                paths.inventories,
                paths.normalized,
                paths.reports,
                paths.logs,
                paths.tmp,
            }
            self.assertEqual(
                expected,
                {root / name for name in (
                    "downloads", "extracted", "inventories", "normalized",
                    "reports", "logs", "tmp",
                )},
            )
            self.assertTrue(all(path.is_dir() for path in expected))
            self.assertEqual(
                {path.parent for path in expected},
                {root},
            )


if __name__ == "__main__":
    unittest.main()
