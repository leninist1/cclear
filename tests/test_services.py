from __future__ import annotations

import os
import pathlib
import tempfile
import unittest

from cclear.services import (
    invalidate_scan_cache,
    is_protected_path,
    move_to_recycle_bin,
    run_temp_cleanup,
    scan_directory,
    search_files,
)


class ServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(prefix="cclear-test-")
        self.root = pathlib.Path(self.temp_dir.name)
        self.cache_dir = tempfile.TemporaryDirectory(prefix="cclear-cache-")
        self.previous_cache_dir = os.environ.get("CCLEAR_DATA_DIR")
        os.environ["CCLEAR_DATA_DIR"] = self.cache_dir.name
        (self.root / "logs").mkdir()
        (self.root / "nested").mkdir()
        (self.root / "video-cache.bin").write_bytes(b"x" * 2048)
        (self.root / "logs" / "error.log").write_bytes(b"x" * 1024)
        (self.root / "nested" / "notes.txt").write_text("hello cclear", encoding="utf-8")

    def tearDown(self) -> None:
        if self.previous_cache_dir is None:
            os.environ.pop("CCLEAR_DATA_DIR", None)
        else:
            os.environ["CCLEAR_DATA_DIR"] = self.previous_cache_dir
        self.cache_dir.cleanup()
        self.temp_dir.cleanup()

    def test_scan_directory_returns_expected_summary(self) -> None:
        result = scan_directory(str(self.root))

        self.assertEqual(result["root"], str(self.root))
        self.assertEqual(result["total_files"], 3)
        self.assertGreaterEqual(result["total_directories"], 3)
        self.assertEqual(result["largest_files"][0]["name"], "video-cache.bin")
        self.assertTrue(any(item["extension"] == ".bin" for item in result["extension_stats"]))

    def test_search_files_supports_keyword_and_min_size(self) -> None:
        result = search_files(str(self.root), "log", min_size_bytes=500)
        self.assertEqual(len(result["results"]), 1)
        self.assertEqual(result["results"][0]["name"], "error.log")

        empty_result = search_files(str(self.root), "notes", min_size_bytes=1024)
        self.assertEqual(empty_result["results"], [])

    def test_scan_cache_is_reused_by_scan_and_search(self) -> None:
        first_scan = scan_directory(str(self.root), force_refresh=True)
        self.assertEqual(first_scan["result_source"], "live")

        cached_scan = scan_directory(str(self.root))
        self.assertEqual(cached_scan["result_source"], "cache")

        cached_search = search_files(str(self.root), "cache", min_size_bytes=0)
        self.assertEqual(cached_search["result_source"], "index_cache")
        self.assertEqual(cached_search["results"][0]["name"], "video-cache.bin")

        invalidate_scan_cache(str(self.root))
        live_search = search_files(str(self.root), "cache", min_size_bytes=0)
        self.assertEqual(live_search["result_source"], "live_walk")

    def test_move_to_recycle_bin_blocks_protected_path(self) -> None:
        system_path = os.path.join(os.environ.get("SystemDrive", "C:"), "Windows", "System32")
        self.assertTrue(is_protected_path(system_path))
        with self.assertRaisesRegex(ValueError, "受保护系统目录"):
            move_to_recycle_bin(system_path)

    def test_run_temp_cleanup_counts_success_and_failure(self) -> None:
        def mover(target: str) -> dict:
            if target == "b.tmp":
                raise RuntimeError("locked")
            return {"success": True}

        result = run_temp_cleanup(
            {
                "user_temp": {"targets": [{"path": "a.tmp", "size": 100}, {"path": "b.tmp", "size": 300}]},
                "windows_temp": {"targets": [{"path": "c.tmp", "size": 200}]},
            },
            mover=mover,
        )

        self.assertEqual(result["success_count"], 2)
        self.assertEqual(result["failure_count"], 1)
        self.assertEqual(result["reclaimed_bytes"], 300)


if __name__ == "__main__":
    unittest.main()
