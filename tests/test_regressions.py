from __future__ import annotations

import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from cclear.app import format_bytes
from cclear.cache_store import get_snapshot_path, load_snapshot, save_snapshot
from cclear.services import _collect_old_entries, build_risk_level, extension_label, normalize_path, search_files


class RegressionTests(unittest.TestCase):
    def test_normalize_path_preserves_drive_root(self) -> None:
        drive_root = os.environ.get("SystemDrive", "C:") + "\\"
        self.assertEqual(normalize_path(drive_root), os.path.normcase(drive_root))

    def test_collect_old_entries_uses_recursive_directory_size(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            root_path = Path(root)
            old_file = root_path / "old.txt"
            old_file.write_bytes(b"a" * 1000)
            old_dir = root_path / "subdir"
            old_dir.mkdir()
            deep_file = old_dir / "deep_old.txt"
            deep_file.write_bytes(b"b" * 2000)

            old_timestamp = time.time() - 3 * 24 * 60 * 60
            os.utime(old_file, (old_timestamp, old_timestamp))
            os.utime(deep_file, (old_timestamp, old_timestamp))
            os.utime(old_dir, (old_timestamp, old_timestamp))

            result = _collect_old_entries(str(root_path), max_age_days=1)
            targets = {item["name"]: item["size"] for item in result["targets"]}

            self.assertEqual(result["count"], 2)
            self.assertEqual(result["size"], 3000)
            self.assertEqual(targets["old.txt"], 1000)
            self.assertEqual(targets["subdir"], 2000)

    def test_extension_label_preserves_dotfile_name(self) -> None:
        self.assertEqual(extension_label(".gitignore"), ".gitignore")
        self.assertEqual(extension_label(".env"), ".env")
        self.assertEqual(extension_label("README"), "(无扩展名)")

    def test_format_bytes_clamps_negative_value(self) -> None:
        self.assertEqual(format_bytes(-1), "0 B")

    def test_search_files_rejects_negative_min_size(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaisesRegex(ValueError, "最小大小不能为负数"):
                search_files(root, "log", min_size_bytes=-1, prefer_index=False)

    def test_build_risk_level_uses_actual_downloads_path(self) -> None:
        with mock.patch("cclear.services.get_downloads_path", return_value=r"D:\MovedDownloads"):
            with mock.patch.dict(os.environ, {"TEMP": r"C:\Temp"}, clear=False):
                self.assertEqual(build_risk_level(r"D:\MovedDownloads\movie.iso"), "中风险")

    def test_save_snapshot_writes_through_temp_file_then_replaces(self) -> None:
        with tempfile.TemporaryDirectory() as data_dir, tempfile.TemporaryDirectory() as root:
            payload = {
                "root": root,
                "created_at": "2026-04-08T12:00:00",
                "files": [],
                "scan_result": {"root": root, "total_files": 0},
            }
            replace_calls: list[tuple[str, os.PathLike[str]]] = []
            original_replace = os.replace

            def wrapped_replace(source: str, destination: os.PathLike[str]) -> None:
                replace_calls.append((source, destination))
                self.assertTrue(os.path.exists(source))
                self.assertTrue(source.endswith(".tmp"))
                original_replace(source, destination)

            with mock.patch.dict(os.environ, {"CCLEAR_DATA_DIR": data_dir}, clear=False):
                with mock.patch("cclear.cache_store.os.replace", side_effect=wrapped_replace):
                    snapshot_path = save_snapshot(root, payload)

                loaded = load_snapshot(root)
                self.assertIsNotNone(loaded)
                self.assertEqual(loaded["root"], root)
                self.assertEqual(Path(snapshot_path), get_snapshot_path(root))
                self.assertEqual(len(replace_calls), 1)
                self.assertFalse(any(item.suffix == ".tmp" for item in get_snapshot_path(root).parent.iterdir()))


if __name__ == "__main__":
    unittest.main()
