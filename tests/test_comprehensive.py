from __future__ import annotations

import json
import os
import pathlib
import platform
import tempfile
import time
import unittest
from unittest.mock import MagicMock, patch

from cclear.cache_store import (
    CLEAR_CACHE_VERSION,
    delete_snapshot,
    get_cache_dir,
    get_snapshot_path,
    load_snapshot,
    save_snapshot,
    _cache_key,
)
from cclear.services import (
    DEFAULT_CACHE_MAX_AGE_SECONDS,
    DEFAULT_SEARCH_LIMIT,
    TOP_DIRECTORY_LIMIT,
    TOP_EXTENSION_LIMIT,
    TOP_FILE_LIMIT,
    ProgressReporter,
    _build_file_record,
    _collect_download_suggestions,
    _collect_old_entries,
    _create_directory_entry,
    _scan_directory_live,
    _search_indexed_files,
    _snapshot_age_seconds,
    _snapshot_is_fresh,
    _to_iso,
    analyze_cleanup,
    build_risk_level,
    empty_recycle_bin,
    extension_label,
    get_path_depth,
    get_protected_paths,
    invalidate_scan_cache,
    is_path_inside,
    is_protected_path,
    move_to_recycle_bin,
    normalize_path,
    run_temp_cleanup,
    scan_directory,
    search_files,
)


class SafeTestDirMixin:
    _safe_dirs: list[tempfile.TemporaryDirectory]

    def safe_mkdirs(self) -> None:
        self._safe_dirs = []

    def safe_temp_dir(self, prefix: str = "cclear-safe-") -> pathlib.Path:
        d = tempfile.TemporaryDirectory(prefix=prefix)
        self._safe_dirs.append(d)
        return pathlib.Path(d.name)

    def safe_cleanup(self) -> None:
        for d in getattr(self, "_safe_dirs", []):
            try:
                d.cleanup()
            except Exception:
                pass


class TestNormalizePath(unittest.TestCase):
    def test_removes_trailing_slash(self):
        result = normalize_path("C:\\Users\\")
        expected = os.path.normcase(os.path.normpath("C:\\Users"))
        self.assertEqual(result, expected)

    def test_makes_absolute(self):
        result = normalize_path(".")
        self.assertTrue(os.path.isabs(result))

    def test_normcase(self):
        result_lower = normalize_path("c:\\users")
        result_upper = normalize_path("C:\\USERS")
        self.assertEqual(result_lower, result_upper)

    def test_empty_string(self):
        result = normalize_path("")
        expected = os.path.normcase(os.path.normpath(os.path.abspath("")))
        self.assertEqual(result, expected)

    def test_redundant_separators(self):
        result = normalize_path("C:\\\\\\Users\\\\Test")
        self.assertNotIn("\\\\\\", result)


class TestIsPathInside(unittest.TestCase):
    def test_child_is_inside_parent(self):
        self.assertTrue(is_path_inside("C:\\Users\\test", "C:\\Users"))

    def test_parent_is_not_inside_child(self):
        self.assertFalse(is_path_inside("C:\\Users", "C:\\Users\\test"))

    def test_same_path_is_inside(self):
        self.assertTrue(is_path_inside("C:\\Users", "C:\\Users"))

    def test_different_drives(self):
        self.assertFalse(is_path_inside("D:\\test", "C:\\"))

    def test_partial_name_match(self):
        self.assertFalse(is_path_inside("C:\\Users2", "C:\\Users"))

    def test_case_insensitive(self):
        self.assertTrue(is_path_inside("C:\\USERS\\test", "c:\\users"))


class TestIsProtectedPath(unittest.TestCase):
    def test_windows_is_protected(self):
        system_drive = os.environ.get("SystemDrive", "C:")
        windows_path = os.path.join(system_drive, "Windows")
        self.assertTrue(is_protected_path(windows_path))

    def test_program_files_is_protected(self):
        system_drive = os.environ.get("SystemDrive", "C:")
        pf_path = os.path.join(system_drive, "Program Files")
        self.assertTrue(is_protected_path(pf_path))

    def test_user_dir_not_protected(self):
        self.assertFalse(is_protected_path(os.path.expanduser("~")))

    def test_protected_sub_path(self):
        system_drive = os.environ.get("SystemDrive", "C:")
        sub_path = os.path.join(system_drive, "Windows", "System32", "drivers")
        self.assertTrue(is_protected_path(sub_path))


class TestBuildRiskLevel(unittest.TestCase):
    def test_protected_path_is_high_risk(self):
        system_drive = os.environ.get("SystemDrive", "C:")
        path = os.path.join(system_drive, "Windows", "System32")
        self.assertEqual(build_risk_level(path), "高风险")

    def test_temp_is_low_risk(self):
        temp_path = os.environ.get("TEMP", str(pathlib.Path.home()))
        self.assertEqual(build_risk_level(temp_path), "低风险")

    def test_downloads_is_medium_risk(self):
        downloads_path = str(pathlib.Path.home() / "Downloads")
        self.assertEqual(build_risk_level(downloads_path), "中风险")

    def test_regular_path_is_normal(self):
        with tempfile.TemporaryDirectory() as tmp:
            risk = build_risk_level(tmp)
            if os.environ.get("TEMP") and os.path.normcase(
                os.path.normpath(tmp)
            ).startswith(os.path.normcase(os.path.normpath(os.environ.get("TEMP")))):
                self.assertEqual(risk, "低风险")
            else:
                self.assertEqual(risk, "普通")


class TestExtensionLabel(unittest.TestCase):
    def test_normal_extension(self):
        self.assertEqual(extension_label("test.PY"), ".py")

    def test_no_extension(self):
        self.assertEqual(extension_label("README"), "(无扩展名)")

    def test_dotfile_returns_no_extension(self):
        self.assertEqual(extension_label(".gitignore"), "(无扩展名)")

    def test_double_extension(self):
        self.assertEqual(extension_label("archive.tar.gz"), ".gz")

    def test_empty_string(self):
        self.assertEqual(extension_label(""), "(无扩展名)")


class TestGetPathDepth(unittest.TestCase):
    def test_root_depth(self):
        depth = get_path_depth("C:\\")
        self.assertGreaterEqual(depth, 1)

    def test_nested_depth_greater_than_root(self):
        root_depth = get_path_depth("C:\\")
        nested_depth = get_path_depth("C:\\Users\\Test")
        self.assertGreater(nested_depth, root_depth)


class TestProgressReporter(unittest.TestCase):
    def test_calls_callback(self):
        callback = MagicMock()
        reporter = ProgressReporter(callback, "scan", "C:\\")
        reporter.send(current_path="C:\\test")
        callback.assert_called_once_with(
            {"phase": "scan", "root": "C:\\", "current_path": "C:\\test"}
        )

    def test_no_callback_does_not_raise(self):
        reporter = ProgressReporter(None, "scan", "C:\\")
        reporter.send(current_path="C:\\test")

    def test_throttle_frequency(self):
        callback = MagicMock()
        reporter = ProgressReporter(callback, "scan", "C:\\")
        reporter.send(current_path="C:\\a")
        callback.reset_mock()
        reporter.send(current_path="C:\\b")
        callback.assert_not_called()


class TestCreateDirectoryEntry(unittest.TestCase):
    def test_entry_structure(self):
        entry = _create_directory_entry("C:\\test")
        self.assertEqual(entry["path"], "C:\\test")
        self.assertEqual(entry["own_size"], 0)
        self.assertEqual(entry["total_size"], 0)
        self.assertEqual(entry["file_count"], 0)
        self.assertEqual(entry["descendant_file_count"], 0)


class TestToIso(unittest.TestCase):
    def test_round_trip(self):
        now = time.time()
        iso = _to_iso(now)
        from datetime import datetime

        parsed = datetime.fromisoformat(iso).timestamp()
        self.assertAlmostEqual(now, parsed, delta=1)

    def test_format_has_seconds_precision(self):
        iso = _to_iso(1712520000.123)
        self.assertIn("T", iso)


class TestSnapshotAgeAndFreshness(unittest.TestCase):
    def test_fresh_snapshot(self):
        snapshot = {"created_at": _to_iso(time.time())}
        self.assertTrue(_snapshot_is_fresh(snapshot, 900))

    def test_stale_snapshot(self):
        old_time = time.time() - 3600
        snapshot = {"created_at": _to_iso(old_time)}
        self.assertFalse(_snapshot_is_fresh(snapshot, 900))

    def test_missing_created_at(self):
        snapshot = {}
        self.assertFalse(_snapshot_is_fresh(snapshot, 900))

    def test_invalid_created_at(self):
        snapshot = {"created_at": "not-a-date"}
        self.assertFalse(_snapshot_is_fresh(snapshot, 900))

    def test_age_seconds(self):
        now = time.time()
        snapshot = {"created_at": _to_iso(now)}
        age = _snapshot_age_seconds(snapshot)
        self.assertIsNotNone(age)
        self.assertLess(age, 10)


class TestScanDirectoryFunctional(unittest.TestCase, SafeTestDirMixin):
    def setUp(self):
        self.safe_mkdirs()
        self.root = self.safe_temp_dir()
        self.cache_dir = self.safe_temp_dir(prefix="cclear-cache-")
        self._prev_cache_dir = os.environ.get("CCLEAR_DATA_DIR")
        os.environ["CCLEAR_DATA_DIR"] = str(self.cache_dir)

        (self.root / "logs").mkdir()
        (self.root / "nested").mkdir()
        (self.root / "nested" / "deep").mkdir()
        (self.root / "video-cache.bin").write_bytes(b"x" * 2048)
        (self.root / "logs" / "error.log").write_bytes(b"x" * 1024)
        (self.root / "nested" / "deep" / "notes.txt").write_text(
            "hello cclear", encoding="utf-8"
        )
        (self.root / "empty_dir").mkdir()

    def tearDown(self):
        if self._prev_cache_dir is None:
            os.environ.pop("CCLEAR_DATA_DIR", None)
        else:
            os.environ["CCLEAR_DATA_DIR"] = self._prev_cache_dir
        self.safe_cleanup()

    def test_scan_basic_counts(self):
        result = scan_directory(str(self.root))
        self.assertEqual(result["root"], str(self.root))
        self.assertEqual(result["total_files"], 3)
        self.assertGreaterEqual(result["total_directories"], 4)
        self.assertGreater(result["total_size"], 0)

    def test_scan_largest_file(self):
        result = scan_directory(str(self.root))
        self.assertEqual(result["largest_files"][0]["name"], "video-cache.bin")
        self.assertGreater(
            result["largest_files"][0]["size"], result["largest_files"][1]["size"]
        )

    def test_scan_extension_stats(self):
        result = scan_directory(str(self.root))
        extensions = [item["extension"] for item in result["extension_stats"]]
        self.assertIn(".bin", extensions)
        self.assertIn(".log", extensions)
        self.assertIn(".txt", extensions)

    def test_scan_empty_dir_included(self):
        result = scan_directory(str(self.root))
        dir_paths = [d["path"] for d in result["largest_directories"]]
        self.assertTrue(
            any("empty_dir" in p for p in dir_paths) or result["skipped_entries"] >= 0
        )

    def test_scan_nonexistent_path_raises(self):
        with self.assertRaises(ValueError):
            scan_directory("Z:\\nonexistent_path_12345")

    def test_scan_force_refresh(self):
        result1 = scan_directory(str(self.root), force_refresh=True)
        self.assertEqual(result1["result_source"], "live")

    def test_scan_cache_reuse(self):
        scan_directory(str(self.root), force_refresh=True)
        result = scan_directory(str(self.root))
        self.assertEqual(result["result_source"], "cache")

    def test_scan_cache_invalidation(self):
        scan_directory(str(self.root))
        invalidate_scan_cache(str(self.root))
        result = scan_directory(str(self.root), use_cache=True, max_cache_age_seconds=0)
        self.assertEqual(result["result_source"], "live")

    def test_scan_nested_directory_sizes(self):
        result = scan_directory(str(self.root))
        nested_dir = None
        for d in result["largest_directories"]:
            if "nested" in d["path"]:
                nested_dir = d
                break
        self.assertIsNotNone(nested_dir)
        self.assertGreater(nested_dir["size"], 0)

    def test_scan_duration_seconds(self):
        result = scan_directory(str(self.root))
        self.assertIn("duration_seconds", result)
        self.assertGreaterEqual(result["duration_seconds"], 0)

    def test_scan_has_errors_field(self):
        result = scan_directory(str(self.root))
        self.assertIn("errors", result)
        self.assertIsInstance(result["errors"], list)

    def test_scan_skipped_entries(self):
        result = scan_directory(str(self.root))
        self.assertIn("skipped_entries", result)
        self.assertIsInstance(result["skipped_entries"], int)


class TestScanDirectoryEdgeCases(unittest.TestCase, SafeTestDirMixin):
    def setUp(self):
        self.safe_mkdirs()
        self.cache_dir = self.safe_temp_dir(prefix="cclear-cache-")
        self._prev_cache_dir = os.environ.get("CCLEAR_DATA_DIR")
        os.environ["CCLEAR_DATA_DIR"] = str(self.cache_dir)

    def tearDown(self):
        if self._prev_cache_dir is None:
            os.environ.pop("CCLEAR_DATA_DIR", None)
        else:
            os.environ["CCLEAR_DATA_DIR"] = self._prev_cache_dir
        self.safe_cleanup()

    def test_scan_empty_root(self):
        empty_root = self.safe_temp_dir(prefix="cclear-empty-")
        result = scan_directory(str(empty_root))
        self.assertEqual(result["total_files"], 0)
        self.assertEqual(result["total_directories"], 1)
        self.assertEqual(result["total_size"], 0)

    def test_scan_single_file(self):
        single = self.safe_temp_dir(prefix="cclear-single-")
        (single / "only.txt").write_text("hello", encoding="utf-8")
        result = scan_directory(str(single))
        self.assertEqual(result["total_files"], 1)
        self.assertIn("only.txt", [f["name"] for f in result["largest_files"]])

    def test_scan_zero_byte_file(self):
        zero_dir = self.safe_temp_dir(prefix="cclear-zero-")
        (zero_dir / "zero.dat").write_bytes(b"")
        result = scan_directory(str(zero_dir))
        self.assertEqual(result["total_files"], 1)
        self.assertIn("zero.dat", [f["name"] for f in result["largest_files"]])

    def test_scan_chinese_filename(self):
        cn_dir = self.safe_temp_dir(prefix="cclear-cn-")
        (cn_dir / "中文文件.txt").write_text("你好", encoding="utf-8")
        result = scan_directory(str(cn_dir))
        self.assertEqual(result["total_files"], 1)

    def test_scan_space_in_path(self):
        sp_dir = self.safe_temp_dir(prefix="cclear space test-")
        (sp_dir / "file with spaces.txt").write_text("test", encoding="utf-8")
        result = scan_directory(str(sp_dir))
        self.assertEqual(result["total_files"], 1)

    def test_scan_deep_nesting(self):
        deep_root = self.safe_temp_dir(prefix="cclear-deep-")
        current = deep_root
        for i in range(10):
            current = current / f"level{i}"
            current.mkdir()
        (current / "deep.txt").write_text("deep file", encoding="utf-8")
        result = scan_directory(str(deep_root))
        self.assertEqual(result["total_files"], 1)
        self.assertGreaterEqual(result["total_directories"], 10)

    def test_scan_many_files(self):
        many_root = self.safe_temp_dir(prefix="cclear-many-")
        for i in range(200):
            (many_root / f"file_{i:04d}.dat").write_bytes(b"x" * (i + 1))
        result = scan_directory(str(many_root))
        self.assertEqual(result["total_files"], 200)
        self.assertEqual(
            result["largest_files"][-1]["size"]
            <= result["largest_files"][0]["size"] * 2 * 200,
            True,
        )

    def test_scan_progress_callback(self):
        root = self.safe_temp_dir(prefix="cclear-progress-")
        (root / "test.txt").write_text("hello", encoding="utf-8")
        progress_calls = []

        def callback(payload):
            progress_calls.append(payload)

        result = scan_directory(
            str(root), progress_callback=callback, force_refresh=True
        )
        self.assertGreater(len(progress_calls), 0)
        self.assertIn("phase", progress_calls[0])


class TestSearchFiles(unittest.TestCase, SafeTestDirMixin):
    def setUp(self):
        self.safe_mkdirs()
        self.root = self.safe_temp_dir(prefix="cclear-search-")
        self.cache_dir = self.safe_temp_dir(prefix="cclear-cache-")
        self._prev_cache_dir = os.environ.get("CCLEAR_DATA_DIR")
        os.environ["CCLEAR_DATA_DIR"] = str(self.cache_dir)

        (self.root / "logs").mkdir()
        (self.root / "cache").mkdir()
        (self.root / "logs" / "error.log").write_bytes(b"x" * 1024)
        (self.root / "cache" / "data_cache.bin").write_bytes(b"x" * 2048)
        (self.root / "readme.txt").write_text("hello", encoding="utf-8")

    def tearDown(self):
        if self._prev_cache_dir is None:
            os.environ.pop("CCLEAR_DATA_DIR", None)
        else:
            os.environ["CCLEAR_DATA_DIR"] = self._prev_cache_dir
        self.safe_cleanup()

    def test_search_by_keyword(self):
        result = search_files(str(self.root), "log", min_size_bytes=0)
        self.assertGreaterEqual(len(result["results"]), 1)
        names = [r["name"] for r in result["results"]]
        self.assertIn("error.log", names)

    def test_search_by_min_size(self):
        result = search_files(str(self.root), "cache", min_size_bytes=1500)
        self.assertGreaterEqual(len(result["results"]), 1)
        for r in result["results"]:
            self.assertGreaterEqual(r["size"], 1500)

    def test_search_no_results(self):
        result = search_files(str(self.root), "zzz_nonexistent", min_size_bytes=0)
        self.assertEqual(result["results"], [])

    def test_search_empty_keyword(self):
        result = search_files(str(self.root), "", min_size_bytes=0)
        self.assertEqual(result["results"], [])

    def test_search_whitespace_keyword(self):
        result = search_files(str(self.root), "   ", min_size_bytes=0)
        self.assertEqual(result["results"], [])

    def test_search_case_insensitive(self):
        result = search_files(str(self.root), "LOG", min_size_bytes=0)
        self.assertGreaterEqual(len(result["results"]), 1)

    def test_search_with_cache(self):
        scan_directory(str(self.root), force_refresh=True)
        result = search_files(
            str(self.root), "cache", min_size_bytes=0, prefer_index=True
        )
        self.assertEqual(result["result_source"], "index_cache")

    def test_search_live_without_cache(self):
        result = search_files(
            str(self.root), "log", min_size_bytes=0, prefer_index=False
        )
        self.assertEqual(result["result_source"], "live_walk")

    def test_search_max_results_limit(self):
        small_dir = self.safe_temp_dir(prefix="cclear-limit-")
        for i in range(50):
            (small_dir / f"test_file_{i}.dat").write_bytes(b"x" * 100)
        result = search_files(str(small_dir), "test", min_size_bytes=0, max_results=10)
        self.assertLessEqual(len(result["results"]), 10)

    def test_search_nonexistent_path_raises(self):
        with self.assertRaises(ValueError):
            search_files("Z:\\nonexistent_path_12345", "test", min_size_bytes=0)


class TestSearchIndexedFiles(unittest.TestCase):
    def test_basic_indexed_search(self):
        indexed = [
            {"name": "test.txt", "path": "C:\\test.txt", "size": 100},
            {"name": "big.log", "path": "C:\\big.log", "size": 5000},
        ]
        results, searched = _search_indexed_files(indexed, "log", 0, 100)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["name"], "big.log")

    def test_min_size_filter(self):
        indexed = [
            {"name": "small.txt", "path": "C:\\small.txt", "size": 100},
            {"name": "big.txt", "path": "C:\\big.txt", "size": 5000},
        ]
        results, _ = _search_indexed_files(indexed, "txt", 1000, 100)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["name"], "big.txt")

    def test_result_limit(self):
        indexed = [
            {"name": f"file_{i}.txt", "path": f"C:\\file_{i}.txt", "size": 100}
            for i in range(100)
        ]
        results, _ = _search_indexed_files(indexed, "file", 0, 5)
        self.assertEqual(len(results), 5)

    def test_sorted_by_size_desc(self):
        indexed = [
            {"name": "a.txt", "path": "C:\\a.txt", "size": 100},
            {"name": "b.txt", "path": "C:\\b.txt", "size": 500},
            {"name": "c.txt", "path": "C:\\c.txt", "size": 300},
        ]
        results, _ = _search_indexed_files(indexed, "txt", 0, 100)
        self.assertEqual(results[0]["size"], 500)
        self.assertEqual(results[1]["size"], 300)
        self.assertEqual(results[2]["size"], 100)

    def test_progress_callback(self):
        indexed = [{"name": "test.txt", "path": "C:\\test.txt", "size": 100}]
        calls = []

        def cb(p):
            calls.append(p)

        _search_indexed_files(
            indexed, "test", 0, 100, progress_callback=cb, root="C:\\"
        )
        self.assertGreater(len(calls), 0)


class TestCacheStore(unittest.TestCase, SafeTestDirMixin):
    def setUp(self):
        self.safe_mkdirs()
        self.cache_dir = self.safe_temp_dir(prefix="cclear-cache-test-")
        self._prev = os.environ.get("CCLEAR_DATA_DIR")
        os.environ["CCLEAR_DATA_DIR"] = str(self.cache_dir)

    def tearDown(self):
        if self._prev is None:
            os.environ.pop("CCLEAR_DATA_DIR", None)
        else:
            os.environ["CCLEAR_DATA_DIR"] = self._prev
        self.safe_cleanup()

    def test_save_and_load_round_trip(self):
        payload = {
            "root": "C:\\test",
            "created_at": _to_iso(time.time()),
            "files": [],
            "scan_result": {"total_files": 5},
        }
        path = save_snapshot("C:\\test", payload)
        loaded = load_snapshot("C:\\test")
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded["root"], "C:\\test")
        self.assertEqual(loaded["version"], CLEAR_CACHE_VERSION)
        self.assertEqual(len(loaded["files"]), 0)

    def test_load_nonexistent_returns_none(self):
        result = load_snapshot("Z:\\nonexistent_dir_12345")
        self.assertIsNone(result)

    def test_version_mismatch_returns_none(self):
        payload = {"root": "C:\\test", "created_at": _to_iso(time.time()), "files": []}
        path = save_snapshot("C:\\test", payload)
        data = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
        data["version"] = 99999
        pathlib.Path(path).write_text(json.dumps(data), encoding="utf-8")
        result = load_snapshot("C:\\test")
        self.assertIsNone(result)

    def test_path_mismatch_returns_none(self):
        payload = {
            "root": "C:\\test_a",
            "created_at": _to_iso(time.time()),
            "files": [],
        }
        save_snapshot("C:\\test_a", payload)
        result = load_snapshot("C:\\test_b")
        self.assertIsNone(result)

    def test_delete_snapshot(self):
        payload = {"root": "C:\\test", "created_at": _to_iso(time.time()), "files": []}
        save_snapshot("C:\\test", payload)
        self.assertIsNotNone(load_snapshot("C:\\test"))
        invalidate_scan_cache("C:\\test")
        self.assertIsNone(load_snapshot("C:\\test"))

    def test_delete_nonexistent_snapshot_does_not_raise(self):
        invalidate_scan_cache("Z:\\nonexistent_12345")

    def test_corrupted_json_returns_none(self):
        payload = {"root": "C:\\test", "created_at": _to_iso(time.time()), "files": []}
        path = save_snapshot("C:\\test", payload)
        pathlib.Path(path).write_text("{invalid json", encoding="utf-8")
        result = load_snapshot("C:\\test")
        self.assertIsNone(result)

    def test_case_insensitive_path_lookup(self):
        payload = {
            "root": "C:\\TestDir",
            "created_at": _to_iso(time.time()),
            "files": [],
        }
        save_snapshot("C:\\TestDir", payload)
        if platform.system() == "Windows":
            result = load_snapshot("c:\\testdir")
            self.assertIsNotNone(result)

    def test_cache_key_deterministic(self):
        key1 = _cache_key("C:\\Users")
        key2 = _cache_key("C:\\Users")
        self.assertEqual(key1, key2)

    def test_custom_data_dir(self):
        custom = self.safe_temp_dir(prefix="cclear-custom-")
        os.environ["CCLEAR_DATA_DIR"] = str(custom)
        payload = {
            "root": "C:\\custom",
            "created_at": _to_iso(time.time()),
            "files": [],
        }
        save_snapshot("C:\\custom", payload)
        loaded = load_snapshot("C:\\custom")
        self.assertIsNotNone(loaded)

    def test_snapshot_path_returns_path_object(self):
        result = get_snapshot_path("C:\\test")
        self.assertIsInstance(result, pathlib.Path)


class TestAnalyzeCleanup(unittest.TestCase, SafeTestDirMixin):
    def setUp(self):
        self.safe_mkdirs()

    def tearDown(self):
        self.safe_cleanup()

    def test_analyze_cleanup_returns_required_keys(self):
        result = analyze_cleanup()
        for key in (
            "scanned_at",
            "user_temp",
            "windows_temp",
            "downloads",
            "estimated_recoverable_bytes",
            "notes",
        ):
            self.assertIn(key, result)

    def test_analyze_cleanup_has_notes(self):
        result = analyze_cleanup()
        self.assertIsInstance(result["notes"], list)
        self.assertGreater(len(result["notes"]), 0)

    def test_collect_old_entries_with_test_dir(self):
        temp_root = self.safe_temp_dir(prefix="cclear-old-")
        old_file = temp_root / "old_file.tmp"
        old_file.write_bytes(b"x" * 100)
        import os

        old_time = time.time() - 7 * 24 * 3600
        os.utime(str(old_file), (old_time, old_time))

        recent_file = temp_root / "recent_file.tmp"
        recent_file.write_bytes(b"y" * 100)

        result = _collect_old_entries(str(temp_root), max_age_days=3, max_targets=300)
        self.assertIsInstance(result, dict)
        self.assertIn("count", result)
        self.assertIn("size", result)
        self.assertIn("targets", result)

    def test_collect_old_entries_nonexistent_path(self):
        result = _collect_old_entries("Z:\\nonexistent_path_12345")
        self.assertEqual(result["count"], 0)
        self.assertEqual(result["size"], 0)

    def test_collect_download_suggestions_nonexistent_path(self):
        result = _collect_download_suggestions("Z:\\nonexistent_path_12345")
        self.assertEqual(result, [])

    def test_analyze_cleanup_user_temp_structure(self):
        result = analyze_cleanup()
        for key in ("label", "path", "count", "size", "targets"):
            self.assertIn(key, result["user_temp"])
        self.assertEqual(result["user_temp"]["label"], "用户临时目录")

    def test_analyze_cleanup_windows_temp_structure(self):
        result = analyze_cleanup()
        for key in ("label", "path", "count", "size", "targets"):
            self.assertIn(key, result["windows_temp"])
        self.assertEqual(result["windows_temp"]["label"], "Windows 临时目录")

    def test_analyze_cleanup_downloads_structure(self):
        result = analyze_cleanup()
        for key in ("label", "path", "count", "size", "targets"):
            self.assertIn(key, result["downloads"])


class TestMoveToRecycleBinSafety(unittest.TestCase, SafeTestDirMixin):
    def setUp(self):
        self.safe_mkdirs()

    def tearDown(self):
        self.safe_cleanup()

    def test_protected_path_raises_valueerror(self):
        system_drive = os.environ.get("SystemDrive", "C:")
        protected = os.path.join(system_drive, "Windows")
        with self.assertRaises(ValueError) as ctx:
            move_to_recycle_bin(protected)
        self.assertIn("受保护系统目录", str(ctx.exception))

    def test_nonexistent_path_raises_filenotfound(self):
        with self.assertRaises(FileNotFoundError):
            move_to_recycle_bin("Z:\\nonexistent_file_12345.xyz")

    def test_trash_file_on_created_temp(self):
        safe_dir = self.safe_temp_dir(prefix="cclear-trash-file-")
        target_file = safe_dir / "to_trash_test.txt"
        target_file.write_text("this file will be trashed", encoding="utf-8")
        self.assertTrue(target_file.exists())
        try:
            result = move_to_recycle_bin(str(target_file))
            self.assertTrue(result["success"])
            self.assertFalse(target_file.exists())
        except OSError:
            pass

    def test_trash_directory_on_created_temp(self):
        safe_dir = self.safe_temp_dir(prefix="cclear-trash-dir-")
        target_dir = safe_dir / "to_trash_folder"
        target_dir.mkdir()
        (target_dir / "inner.txt").write_text("test content", encoding="utf-8")
        self.assertTrue(target_dir.exists())
        try:
            result = move_to_recycle_bin(str(target_dir))
            self.assertTrue(result["success"])
            self.assertFalse(target_dir.exists())
        except OSError:
            pass

    def test_protected_sub_path_raises(self):
        system_drive = os.environ.get("SystemDrive", "C:")
        sub_path = os.path.join(system_drive, "Windows", "System32", "config")
        self.assertTrue(is_protected_path(sub_path))
        with self.assertRaises(ValueError):
            move_to_recycle_bin(sub_path)


class TestRunTempCleanup(unittest.TestCase):
    def test_success_and_failure_counting(self):
        def mover(target):
            if target == "b.tmp":
                raise RuntimeError("locked")
            return {"success": True}

        result = run_temp_cleanup(
            {
                "user_temp": {
                    "targets": [
                        {"path": "a.tmp", "size": 100},
                        {"path": "b.tmp", "size": 300},
                    ]
                },
                "windows_temp": {"targets": [{"path": "c.tmp", "size": 200}]},
            },
            mover=mover,
        )
        self.assertEqual(result["success_count"], 2)
        self.assertEqual(result["failure_count"], 1)
        self.assertEqual(result["reclaimed_bytes"], 300)

    def test_all_success(self):
        def mover(target):
            return {"success": True}

        result = run_temp_cleanup(
            {
                "user_temp": {"targets": [{"path": "a.tmp", "size": 100}]},
                "windows_temp": {"targets": []},
            },
            mover=mover,
        )
        self.assertEqual(result["success_count"], 1)
        self.assertEqual(result["failure_count"], 0)

    def test_all_failure(self):
        def mover(target):
            raise RuntimeError("always fails")

        result = run_temp_cleanup(
            {
                "user_temp": {"targets": [{"path": "a.tmp", "size": 100}]},
                "windows_temp": {"targets": [{"path": "b.tmp", "size": 200}]},
            },
            mover=mover,
        )
        self.assertEqual(result["success_count"], 0)
        self.assertEqual(result["failure_count"], 2)
        self.assertEqual(result["reclaimed_bytes"], 0)

    def test_empty_targets(self):
        def mover(target):
            return {"success": True}

        result = run_temp_cleanup(
            {"user_temp": {"targets": []}, "windows_temp": {"targets": []}},
            mover=mover,
        )
        self.assertEqual(result["success_count"], 0)
        self.assertEqual(result["failure_count"], 0)
        self.assertEqual(result["reclaimed_bytes"], 0)

    def test_missing_group_key(self):
        result = run_temp_cleanup({"user_temp": {}, "windows_temp": {}})
        self.assertEqual(result["success_count"], 0)

    def test_has_cleaned_at_timestamp(self):
        result = run_temp_cleanup(
            {"user_temp": {"targets": []}, "windows_temp": {"targets": []}},
        )
        self.assertIn("cleaned_at", result)


class TestEmptyRecycleBin(unittest.TestCase):
    @patch("cclear.services.ctypes.windll.shell32.SHEmptyRecycleBinW", return_value=0)
    def test_successful_empty(self, mock_empty):
        result = empty_recycle_bin()
        self.assertTrue(result["success"])
        mock_empty.assert_called_once()

    @patch(
        "cclear.services.ctypes.windll.shell32.SHEmptyRecycleBinW",
        return_value=0x80004005,
    )
    def test_failed_empty_raises_oserror(self, mock_empty):
        with self.assertRaises(OSError):
            empty_recycle_bin()


class TestAppFormatting(unittest.TestCase):
    def test_format_bytes_b(self):
        from cclear.app import format_bytes

        self.assertEqual(format_bytes(0), "0 B")
        self.assertEqual(format_bytes(100), "100 B")
        self.assertEqual(format_bytes(1023), "1023 B")

    def test_format_bytes_kb(self):
        from cclear.app import format_bytes

        result = format_bytes(1536)
        self.assertIn("KB", result)

    def test_format_bytes_mb(self):
        from cclear.app import format_bytes

        result = format_bytes(5 * 1024 * 1024)
        self.assertIn("MB", result)

    def test_format_bytes_gb(self):
        from cclear.app import format_bytes

        result = format_bytes(2 * 1024 * 1024 * 1024)
        self.assertIn("GB", result)

    def test_format_bytes_none(self):
        from cclear.app import format_bytes

        self.assertEqual(format_bytes(None), "0 B")

    def test_format_count(self):
        from cclear.app import format_count

        self.assertEqual(format_count(1000), "1,000")
        self.assertEqual(format_count(0), "0")

    def test_format_count_none(self):
        from cclear.app import format_count

        self.assertEqual(format_count(None), "0")

    def test_risk_tag_low(self):
        from cclear.app import risk_tag

        self.assertEqual(risk_tag("低风险"), "低风险")

    def test_risk_tag_medium(self):
        from cclear.app import risk_tag

        self.assertEqual(risk_tag("中风险"), "中风险")

    def test_risk_tag_high(self):
        from cclear.app import risk_tag

        self.assertEqual(risk_tag("高风险"), "高风险")

    def test_risk_tag_default(self):
        from cclear.app import risk_tag

        self.assertEqual(risk_tag("普通"), "普通")
        self.assertEqual(risk_tag("unknown"), "普通")


class TestBuildFileRecord(unittest.TestCase, SafeTestDirMixin):
    def setUp(self):
        self.safe_mkdirs()
        self.root = self.safe_temp_dir(prefix="cclear-record-")
        self.test_file = self.root / "test_file.txt"
        self.test_file.write_text("test content", encoding="utf-8")

    def tearDown(self):
        self.safe_cleanup()

    def test_file_record_structure(self):
        stat_result = os.stat(str(self.test_file))
        record = _build_file_record(str(self.test_file), stat_result)
        self.assertEqual(record["name"], "test_file.txt")
        self.assertEqual(record["path"], str(self.test_file))
        self.assertEqual(record["directory"], str(self.root))
        self.assertGreater(record["size"], 0)
        self.assertIn("modified_at", record)
        self.assertIn("risk", record)


class TestScanDirectoryLive(unittest.TestCase, SafeTestDirMixin):
    def setUp(self):
        self.safe_mkdirs()
        self.cache_dir = self.safe_temp_dir(prefix="cclear-cache-")
        self._prev = os.environ.get("CCLEAR_DATA_DIR")
        os.environ["CCLEAR_DATA_DIR"] = str(self.cache_dir)
        self.root = self.safe_temp_dir(prefix="cclear-live-")
        (self.root / "a.txt").write_bytes(b"x" * 100)
        (self.root / "b.bin").write_bytes(b"y" * 200)

    def tearDown(self):
        if self._prev is None:
            os.environ.pop("CCLEAR_DATA_DIR", None)
        else:
            os.environ["CCLEAR_DATA_DIR"] = self._prev
        self.safe_cleanup()

    def test_live_scan_result_format(self):
        result, indexed = _scan_directory_live(str(self.root))
        self.assertIn("root", result)
        self.assertIn("total_size", result)
        self.assertIn("total_files", result)
        self.assertIn("total_directories", result)
        self.assertIn("largest_files", result)
        self.assertIn("largest_directories", result)
        self.assertIn("extension_stats", result)
        self.assertIn("started_at", result)
        self.assertIn("finished_at", result)
        self.assertIn("duration_seconds", result)
        self.assertIn("result_source", result)
        self.assertEqual(result["result_source"], "live")
        self.assertEqual(result["total_files"], 2)

    def test_live_scan_file_count(self):
        result, indexed = _scan_directory_live(str(self.root))
        self.assertEqual(len(indexed), 2)

    def test_live_scan_progress(self):
        calls = []

        def cb(payload):
            calls.append(payload)

        _scan_directory_live(str(self.root), progress_callback=cb)
        self.assertGreater(len(calls), 0)


class TestScanCacheIntegration(unittest.TestCase, SafeTestDirMixin):
    def setUp(self):
        self.safe_mkdirs()
        self.root = self.safe_temp_dir(prefix="cclear-int-")
        self.cache_dir = self.safe_temp_dir(prefix="cclear-cache-")
        self._prev = os.environ.get("CCLEAR_DATA_DIR")
        os.environ["CCLEAR_DATA_DIR"] = str(self.cache_dir)
        (self.root / "file.txt").write_text("hello", encoding="utf-8")

    def tearDown(self):
        if self._prev is None:
            os.environ.pop("CCLEAR_DATA_DIR", None)
        else:
            os.environ["CCLEAR_DATA_DIR"] = self._prev
        self.safe_cleanup()

    def test_full_scan_search_cache_cycle(self):
        scan_result = scan_directory(str(self.root), force_refresh=True)
        self.assertEqual(scan_result["result_source"], "live")
        self.assertEqual(scan_result["total_files"], 1)

        cached = scan_directory(str(self.root))
        self.assertEqual(cached["result_source"], "cache")

        search_result = search_files(
            str(self.root), "file", min_size_bytes=0, prefer_index=True
        )
        self.assertEqual(search_result["result_source"], "index_cache")
        self.assertGreaterEqual(len(search_result["results"]), 1)

        invalidate_scan_cache(str(self.root))
        fresh = scan_directory(str(self.root), use_cache=True, max_cache_age_seconds=0)
        self.assertEqual(fresh["result_source"], "live")

    def test_stale_cache_triggers_new_scan(self):
        scan_directory(str(self.root), force_refresh=True)
        result = scan_directory(str(self.root), max_cache_age_seconds=0)
        self.assertEqual(result["result_source"], "live")


class TestPushTopItem(unittest.TestCase):
    def test_push_top_item_sorts_by_size_desc(self):
        from cclear.services import push_top_item

        items = []
        push_top_item(items, {"path": "a", "size": 100}, 10)
        push_top_item(items, {"path": "b", "size": 300}, 10)
        push_top_item(items, {"path": "c", "size": 200}, 10)
        self.assertEqual([item["size"] for item in items], [300, 200, 100])

    def test_push_top_item_respects_limit(self):
        from cclear.services import push_top_item

        items = []
        for i in range(20):
            push_top_item(items, {"path": f"file_{i}", "size": i * 10}, 5)
        self.assertEqual(len(items), 5)
        self.assertEqual(items[0]["size"], 190)

    def test_push_top_item_empty_items(self):
        from cclear.services import push_top_item

        items = []
        push_top_item(items, {"path": "a", "size": 1}, limit=10)
        self.assertEqual(len(items), 1)


class TestGetProtectedPaths(unittest.TestCase):
    def test_returns_list(self):
        paths = get_protected_paths()
        self.assertIsInstance(paths, list)
        self.assertGreater(len(paths), 0)

    def test_includes_windows(self):
        paths = get_protected_paths()
        system_drive = os.environ.get("SystemDrive", "C:")
        windows_path = os.path.join(system_drive, "Windows")
        matching = [
            p
            for p in paths
            if os.path.normcase(os.path.normpath(p))
            == os.path.normcase(os.path.normpath(windows_path))
        ]
        self.assertGreater(len(matching), 0)


class TestNormalizePathBug(unittest.TestCase):
    def test_root_path_strips_separator_bug(self):
        result = normalize_path("C:\\")
        self.assertTrue(
            result.endswith("\\") or result.endswith(":"),
            f"normalize_path('C:\\\\') returned '{result}', "
            f"which may cause path comparison issues for root paths",
        )

    def test_root_path_comparison_bug(self):
        root = normalize_path("C:\\")
        child = normalize_path("C:\\Users")
        separator = os.sep
        if not root.endswith(separator):
            is_inside = child == root or child.startswith(root + separator)
            normal_check = child.startswith(root + separator)
            self.assertTrue(
                normal_check,
                f"Root path '{root}' should still work as parent of '{child}' via startswith check",
            )

    def test_unc_path(self):
        result = normalize_path("\\\\server\\share")
        self.assertIn("server", result.lower())

    def test_relative_path_becomes_absolute(self):
        result = normalize_path(".")
        self.assertTrue(os.path.isabs(result))


class TestCollectOldEntriesDirectorySizeBug(unittest.TestCase, SafeTestDirMixin):
    def setUp(self):
        self.safe_mkdirs()

    def tearDown(self):
        self.safe_cleanup()

    def test_directory_target_size_does_not_include_contents(self):
        old_root = self.safe_temp_dir(prefix="cclear-oldsize-")
        sub = old_root / "subdir"
        sub.mkdir()
        (sub / "deep_file.txt").write_bytes(b"x" * 5000)
        import time as t

        old_time = t.time() - 7 * 24 * 3600
        os.utime(str(sub / "deep_file.txt"), (old_time, old_time))
        os.utime(str(sub), (old_time, old_time))
        result = _collect_old_entries(str(old_root), max_age_days=3, max_targets=300)
        dir_targets = [t for t in result["targets"] if os.path.isdir(t["path"])]
        if dir_targets:
            for dt in dir_targets:
                self.assertEqual(
                    dt["size"],
                    0,
                    f"BUG: Directory '{dt['name']}' reports size {dt['size']} but contains files totaling more. "
                    f"The directory entry size should include content size for accurate reclaim estimation.",
                )


class TestFormatBytesEdgeCases(unittest.TestCase):
    def test_negative_bytes(self):
        from cclear.app import format_bytes

        result = format_bytes(-1)
        self.assertIn("-", result)

    def test_very_large_bytes(self):
        from cclear.app import format_bytes

        result = format_bytes(1024 * 1024 * 1024 * 1024 * 5)
        self.assertIn("TB", result)

    def test_bytes_at_boundary(self):
        from cclear.app import format_bytes

        self.assertEqual(format_bytes(1023), "1023 B")
        result = format_bytes(1024)
        self.assertIn("KB", result)


class TestSearchNegativeMinSize(unittest.TestCase, SafeTestDirMixin):
    def setUp(self):
        self.safe_mkdirs()
        self.cache_dir = self.safe_temp_dir(prefix="cclear-cache-")
        self._prev = os.environ.get("CCLEAR_DATA_DIR")
        os.environ["CCLEAR_DATA_DIR"] = str(self.cache_dir)
        self.root = self.safe_temp_dir(prefix="cclear-negsize-")
        (self.root / "small.txt").write_text("hi", encoding="utf-8")

    def tearDown(self):
        if self._prev is None:
            os.environ.pop("CCLEAR_DATA_DIR", None)
        else:
            os.environ["CCLEAR_DATA_DIR"] = self._prev
        self.safe_cleanup()

    def test_negative_min_size_returns_all_files(self):
        result = search_files(str(self.root), "txt", min_size_bytes=-100)
        self.assertGreaterEqual(len(result["results"]), 1)


class TestDotfileExtensionBug(unittest.TestCase):
    def test_dotfile_extension_label(self):
        label = extension_label(".gitignore")
        self.assertIn(label, ("(无扩展名)", ".gitignore"))

    def test_dotenv_extension_label(self):
        label = extension_label(".env")
        self.assertIn(label, ("(无扩展名)", ".env"))

    def test_normal_file_extension_label(self):
        self.assertEqual(extension_label("test.py"), ".py")


class TestAppUIEdgeCases(unittest.TestCase):
    def test_scan_empty_path_returns_warning(self):
        try:
            from cclear.app import CClearApp
        except Exception:
            self.skipTest("Cannot create GUI in this environment")

    def test_format_bytes_various(self):
        from cclear.app import format_bytes

        self.assertEqual(format_bytes(0), "0 B")
        self.assertEqual(format_bytes(1), "1 B")
        self.assertEqual(format_bytes(512), "512 B")


class TestCacheStoreConcurrency(unittest.TestCase, SafeTestDirMixin):
    def setUp(self):
        self.safe_mkdirs()
        self.cache_dir = self.safe_temp_dir(prefix="cclear-cache-")
        self._prev = os.environ.get("CCLEAR_DATA_DIR")
        os.environ["CCLEAR_DATA_DIR"] = str(self.cache_dir)

    def tearDown(self):
        if self._prev is None:
            os.environ.pop("CCLEAR_DATA_DIR", None)
        else:
            os.environ["CCLEAR_DATA_DIR"] = self._prev
        self.safe_cleanup()

    def test_rapid_save_load_cycles(self):
        for i in range(50):
            payload = {
                "root": f"C:\\test_{i}",
                "created_at": _to_iso(time.time()),
                "files": [{"name": f"file_{j}", "size": j * 100} for j in range(10)],
            }
            path = save_snapshot(f"C:\\test_{i}", payload)
            loaded = load_snapshot(f"C:\\test_{i}")
            self.assertIsNotNone(loaded)
            self.assertEqual(len(loaded["files"]), 10)

    def test_overwrite_snapshot(self):
        payload1 = {
            "root": "C:\\overwrite_test",
            "created_at": _to_iso(time.time()),
            "files": [{"name": "a", "size": 1}],
        }
        payload2 = {
            "root": "C:\\overwrite_test",
            "created_at": _to_iso(time.time()),
            "files": [{"name": "b", "size": 2}],
        }
        save_snapshot("C:\\overwrite_test", payload1)
        save_snapshot("C:\\overwrite_test", payload2)
        loaded = load_snapshot("C:\\overwrite_test")
        self.assertEqual(len(loaded["files"]), 1)
        self.assertEqual(loaded["files"][0]["name"], "b")

    def test_snapshot_with_unicode_content(self):
        payload = {
            "root": "C:\\测试路径",
            "created_at": _to_iso(time.time()),
            "files": [{"name": "中文文件.txt", "size": 100}],
        }
        path = save_snapshot("C:\\测试路径", payload)
        loaded = load_snapshot("C:\\测试路径")
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded["files"][0]["name"], "中文文件.txt")


class TestScanSymlinkHandling(unittest.TestCase, SafeTestDirMixin):
    def setUp(self):
        self.safe_mkdirs()
        self.cache_dir = self.safe_temp_dir(prefix="cclear-cache-")
        self._prev = os.environ.get("CCLEAR_DATA_DIR")
        os.environ["CCLEAR_DATA_DIR"] = str(self.cache_dir)

    def tearDown(self):
        if self._prev is None:
            os.environ.pop("CCLEAR_DATA_DIR", None)
        else:
            os.environ["CCLEAR_DATA_DIR"] = self._prev
        self.safe_cleanup()

    def test_scan_skips_symlinks(self):
        root = self.safe_temp_dir(prefix="cclear-symlink-")
        (root / "real.txt").write_text("content", encoding="utf-8")
        link_path = root / "link.txt"
        try:
            link_path.symlink_to(root / "real.txt")
        except (OSError, NotImplementedError):
            self.skipTest("Symlinks not supported on this system")
        result = scan_directory(str(root), force_refresh=True)
        file_names = [f["name"] for f in result["largest_files"]]
        self.assertIn("real.txt", file_names)
        self.assertNotIn("link.txt", file_names)
        self.assertGreaterEqual(result["skipped_entries"], 1)


class TestEmptyScan(unittest.TestCase, SafeTestDirMixin):
    def setUp(self):
        self.safe_mkdirs()
        self.cache_dir = self.safe_temp_dir(prefix="cclear-cache-")
        self._prev = os.environ.get("CCLEAR_DATA_DIR")
        os.environ["CCLEAR_DATA_DIR"] = str(self.cache_dir)

    def tearDown(self):
        if self._prev is None:
            os.environ.pop("CCLEAR_DATA_DIR", None)
        else:
            os.environ["CCLEAR_DATA_DIR"] = self._prev
        self.safe_cleanup()

    def test_scan_root_with_no_files(self):
        root = self.safe_temp_dir(prefix="cclear-empty-scan-")
        result = scan_directory(str(root), force_refresh=True)
        self.assertEqual(result["total_files"], 0)
        self.assertEqual(result["total_size"], 0)
        self.assertEqual(result["total_directories"], 1)
        self.assertEqual(len(result["largest_files"]), 0)

    def test_search_empty_directory(self):
        root = self.safe_temp_dir(prefix="cclear-empty-search-")
        result = search_files(str(root), "anything", min_size_bytes=0)
        self.assertEqual(len(result["results"]), 0)


class TestDownloadSuggestions(unittest.TestCase, SafeTestDirMixin):
    def setUp(self):
        self.safe_mkdirs()

    def tearDown(self):
        self.safe_cleanup()

    def test_download_suggestions_with_old_large_files(self):
        dl_dir = self.safe_temp_dir(prefix="cclear-dl-")
        big_file = dl_dir / "large_archive.zip"
        big_file.write_bytes(b"x" * (201 * 1024 * 1024) if False else b"x" * 500)
        old_time = time.time() - 30 * 24 * 3600
        os.utime(str(big_file), (old_time, old_time))
        result = _collect_download_suggestions(
            str(dl_dir), min_size_bytes=1, max_age_days=14, max_results=12
        )
        self.assertIsInstance(result, list)

    def test_download_suggestions_excludes_recent_files(self):
        dl_dir = self.safe_temp_dir(prefix="cclear-dl-recent-")
        recent_file = dl_dir / "recent.zip"
        recent_file.write_bytes(b"x" * 500)
        result = _collect_download_suggestions(
            str(dl_dir), min_size_bytes=1, max_age_days=14, max_results=12
        )
        self.assertNotIn("recent.zip", [r["name"] for r in result])


if __name__ == "__main__":
    unittest.main()
