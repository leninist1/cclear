from __future__ import annotations

import ctypes
import os
import pathlib
import time
from ctypes import wintypes
from datetime import datetime
from typing import Callable

from .cache_store import delete_snapshot, load_snapshot, save_snapshot


TOP_FILE_LIMIT = 20
TOP_DIRECTORY_LIMIT = 20
TOP_EXTENSION_LIMIT = 12
DEFAULT_SEARCH_LIMIT = 200
DEFAULT_CACHE_MAX_AGE_SECONDS = 15 * 60

FO_DELETE = 0x0003
FOF_SILENT = 0x0004
FOF_NOCONFIRMATION = 0x0010
FOF_ALLOWUNDO = 0x0040
FOF_NOERRORUI = 0x0400

SHERB_NOCONFIRMATION = 0x00000001
SHERB_NOPROGRESSUI = 0x00000002
SHERB_NOSOUND = 0x00000004


class SHFILEOPSTRUCTW(ctypes.Structure):
    _fields_ = [
        ("hwnd", wintypes.HWND),
        ("wFunc", wintypes.UINT),
        ("pFrom", wintypes.LPCWSTR),
        ("pTo", wintypes.LPCWSTR),
        ("fFlags", ctypes.c_ushort),
        ("fAnyOperationsAborted", wintypes.BOOL),
        ("hNameMappings", wintypes.LPVOID),
        ("lpszProgressTitle", wintypes.LPCWSTR),
    ]


def normalize_path(target_path: str) -> str:
    normalized = os.path.abspath(target_path)
    normalized = os.path.normpath(normalized)
    return os.path.normcase(normalized.rstrip("\\/"))


def is_path_inside(target_path: str, parent_path: str) -> bool:
    target = normalize_path(target_path)
    parent = normalize_path(parent_path)
    return target == parent or target.startswith(parent + os.sep)


def get_protected_paths() -> list[str]:
    system_drive = os.environ.get("SystemDrive", "C:")
    return [
        os.path.join(system_drive, "Windows"),
        os.path.join(system_drive, "Program Files"),
        os.path.join(system_drive, "Program Files (x86)"),
        os.path.join(system_drive, "ProgramData"),
        os.path.join(system_drive, "System Volume Information"),
    ]


def is_protected_path(target_path: str) -> bool:
    return any(is_path_inside(target_path, item) for item in get_protected_paths())


def build_risk_level(target_path: str) -> str:
    if is_protected_path(target_path):
        return "高风险"

    temp_path = normalize_path(pathlib.Path(os.environ.get("TEMP", pathlib.Path.home())).as_posix())
    downloads_path = normalize_path(str(pathlib.Path.home() / "Downloads"))
    target = normalize_path(target_path)

    if is_path_inside(target, temp_path):
        return "低风险"

    if is_path_inside(target, downloads_path):
        return "中风险"

    return "普通"


def extension_label(file_path: str) -> str:
    extension = pathlib.Path(file_path).suffix.lower()
    return extension or "(无扩展名)"


def get_path_depth(target_path: str) -> int:
    return len(pathlib.Path(os.path.abspath(target_path)).parts)


def push_top_item(items: list[dict], item: dict, limit: int) -> None:
    items.append(item)
    items.sort(key=lambda entry: (-entry["size"], entry["path"]))
    del items[limit:]


class ProgressReporter:
    def __init__(self, callback: Callable[[dict], None] | None, phase: str, root: str) -> None:
        self.callback = callback
        self.phase = phase
        self.root = root
        self.last_sent = 0.0

    def send(self, **payload: object) -> None:
        if self.callback is None:
            return

        now = time.monotonic()
        if now - self.last_sent < 0.2:
            return

        self.last_sent = now
        self.callback({"phase": self.phase, "root": self.root, **payload})


def _create_directory_entry(target_path: str) -> dict:
    return {
        "path": target_path,
        "depth": get_path_depth(target_path),
        "own_size": 0,
        "total_size": 0,
        "file_count": 0,
        "descendant_file_count": 0,
    }


def _to_iso(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp).isoformat(timespec="seconds")


def _parse_iso_timestamp(value: str | None) -> float | None:
    if not value:
        return None

    try:
        return datetime.fromisoformat(value).timestamp()
    except ValueError:
        return None


def _snapshot_age_seconds(snapshot: dict) -> float | None:
    created_at = _parse_iso_timestamp(snapshot.get("created_at"))
    if created_at is None:
        return None

    return max(0.0, time.time() - created_at)


def _snapshot_is_fresh(snapshot: dict, max_age_seconds: int) -> bool:
    age_seconds = _snapshot_age_seconds(snapshot)
    if age_seconds is None:
        return False

    return age_seconds <= max_age_seconds


def _build_file_record(full_path: str, stat_result: os.stat_result) -> dict:
    return {
        "path": full_path,
        "name": os.path.basename(full_path),
        "directory": os.path.dirname(full_path),
        "size": stat_result.st_size,
        "modified_at": _to_iso(stat_result.st_mtime),
        "risk": build_risk_level(full_path),
    }


def _scan_directory_live(
    root: str,
    progress_callback: Callable[[dict], None] | None = None,
    top_file_limit: int = TOP_FILE_LIMIT,
    top_directory_limit: int = TOP_DIRECTORY_LIMIT,
    top_extension_limit: int = TOP_EXTENSION_LIMIT,
) -> tuple[dict, list[dict]]:
    started_at = time.time()
    report_progress = ProgressReporter(progress_callback, "scan", root)

    directories: dict[str, dict] = {root: _create_directory_entry(root)}
    indexed_files: list[dict] = []
    top_files: list[dict] = []
    extension_stats: dict[str, dict] = {}
    errors: list[dict] = []
    stack = [root]

    total_size = 0
    total_files = 0
    total_directories = 1
    skipped_entries = 0

    while stack:
        current_directory = stack.pop()

        try:
            entries = list(os.scandir(current_directory))
        except OSError as error:
            skipped_entries += 1
            errors.append({"path": current_directory, "message": str(error)})
            continue

        for entry in entries:
            full_path = entry.path

            if entry.is_symlink():
                skipped_entries += 1
                continue

            try:
                if entry.is_dir(follow_symlinks=False):
                    if full_path not in directories:
                        directories[full_path] = _create_directory_entry(full_path)
                        total_directories += 1
                    stack.append(full_path)
                    report_progress.send(
                        current_path=full_path,
                        total_files=total_files,
                        total_directories=total_directories,
                        total_size=total_size,
                    )
                    continue

                if not entry.is_file(follow_symlinks=False):
                    skipped_entries += 1
                    continue

                stat_result = entry.stat(follow_symlinks=False)
            except OSError as error:
                skipped_entries += 1
                errors.append({"path": full_path, "message": str(error)})
                continue

            file_record = _build_file_record(full_path, stat_result)
            indexed_files.append(file_record)

            size = stat_result.st_size
            directory_entry = directories[current_directory]
            directory_entry["own_size"] += size
            directory_entry["file_count"] += 1

            total_files += 1
            total_size += size

            push_top_item(top_files, file_record, top_file_limit)

            extension = extension_label(full_path)
            previous = extension_stats.get(extension, {"extension": extension, "size": 0, "count": 0})
            extension_stats[extension] = {
                "extension": extension,
                "size": previous["size"] + size,
                "count": previous["count"] + 1,
            }

            report_progress.send(
                current_path=full_path,
                total_files=total_files,
                total_directories=total_directories,
                total_size=total_size,
            )

    directory_entries = sorted(directories.values(), key=lambda item: item["depth"], reverse=True)
    for item in directory_entries:
        item["total_size"] += item["own_size"]
        item["descendant_file_count"] += item["file_count"]

        if item["path"] == root:
            continue

        parent_path = os.path.dirname(item["path"])
        parent = directories.get(parent_path)
        if parent is None:
            continue

        parent["total_size"] += item["total_size"]
        parent["descendant_file_count"] += item["descendant_file_count"]

    finished_at = time.time()
    result = {
        "root": root,
        "started_at": _to_iso(started_at),
        "finished_at": _to_iso(finished_at),
        "duration_seconds": round(finished_at - started_at, 2),
        "total_size": total_size,
        "total_files": total_files,
        "total_directories": total_directories,
        "largest_files": top_files,
        "largest_directories": sorted(
            [
                {
                    "path": item["path"],
                    "name": item["path"] if item["path"] == root else os.path.basename(item["path"]) or item["path"],
                    "size": item["total_size"],
                    "file_count": item["descendant_file_count"],
                    "risk": build_risk_level(item["path"]),
                }
                for item in directories.values()
            ],
            key=lambda entry: (-entry["size"], entry["path"]),
        )[:top_directory_limit],
        "extension_stats": sorted(
            extension_stats.values(), key=lambda item: (-item["size"], item["extension"])
        )[:top_extension_limit],
        "skipped_entries": skipped_entries,
        "errors": errors[:30],
        "result_source": "live",
        "snapshot_created_at": _to_iso(finished_at),
        "index_age_seconds": 0.0,
    }
    return result, indexed_files


def _build_cached_scan_result(snapshot: dict) -> dict:
    cached_result = dict(snapshot.get("scan_result", {}))
    cached_result["result_source"] = "cache"
    cached_result["snapshot_created_at"] = snapshot.get("created_at")
    age_seconds = _snapshot_age_seconds(snapshot)
    cached_result["index_age_seconds"] = round(age_seconds, 2) if age_seconds is not None else None
    return cached_result


def scan_directory(
    root_path: str,
    progress_callback: Callable[[dict], None] | None = None,
    top_file_limit: int = TOP_FILE_LIMIT,
    top_directory_limit: int = TOP_DIRECTORY_LIMIT,
    top_extension_limit: int = TOP_EXTENSION_LIMIT,
    use_cache: bool = True,
    force_refresh: bool = False,
    max_cache_age_seconds: int = DEFAULT_CACHE_MAX_AGE_SECONDS,
) -> dict:
    root = os.path.abspath(root_path)
    if not os.path.isdir(root):
        raise ValueError("请选择有效的目录或磁盘根路径")

    snapshot = load_snapshot(root) if use_cache and not force_refresh else None
    if snapshot and _snapshot_is_fresh(snapshot, max_cache_age_seconds):
        return _build_cached_scan_result(snapshot)

    live_result, indexed_files = _scan_directory_live(
        root,
        progress_callback=progress_callback,
        top_file_limit=top_file_limit,
        top_directory_limit=top_directory_limit,
        top_extension_limit=top_extension_limit,
    )

    snapshot_created_at = live_result["snapshot_created_at"]
    snapshot_path = save_snapshot(
        root,
        {
            "root": root,
            "created_at": snapshot_created_at,
            "files": indexed_files,
            "scan_result": {
                key: value
                for key, value in live_result.items()
                if key not in {"result_source", "snapshot_created_at", "index_age_seconds"}
            },
        },
    )
    live_result["snapshot_path"] = snapshot_path
    return live_result


def _search_indexed_files(
    indexed_files: list[dict],
    query: str,
    min_size_bytes: int,
    max_results: int,
    progress_callback: Callable[[dict], None] | None = None,
    root: str | None = None,
) -> tuple[list[dict], int]:
    normalized_query = query.strip().lower()
    report_progress = ProgressReporter(progress_callback, "search", root or "")
    results: list[dict] = []
    searched_files = 0

    for item in indexed_files:
        searched_files += 1
        if normalized_query not in item["name"].lower():
            report_progress.send(
                current_path=item["path"],
                searched_files=searched_files,
                results=len(results),
            )
            continue

        if item["size"] < min_size_bytes:
            report_progress.send(
                current_path=item["path"],
                searched_files=searched_files,
                results=len(results),
            )
            continue

        results.append(item)
        report_progress.send(
            current_path=item["path"],
            searched_files=searched_files,
            results=len(results),
        )

        if len(results) >= max_results:
            break

    results.sort(key=lambda item: (-item["size"], item["path"]))
    return results, searched_files


def search_files(
    root_path: str,
    query: str,
    min_size_bytes: int = 0,
    max_results: int = DEFAULT_SEARCH_LIMIT,
    progress_callback: Callable[[dict], None] | None = None,
    prefer_index: bool = True,
    max_cache_age_seconds: int = DEFAULT_CACHE_MAX_AGE_SECONDS,
) -> dict:
    root = os.path.abspath(root_path)
    if not os.path.isdir(root):
        raise ValueError("请选择有效的目录或磁盘根路径")

    normalized_query = query.strip().lower()
    report_progress = ProgressReporter(progress_callback, "search", root)

    if not normalized_query:
        return {
            "root": root,
            "query": "",
            "results": [],
            "searched_files": 0,
            "skipped_entries": 0,
            "errors": [],
        }

    if prefer_index:
        snapshot = load_snapshot(root)
        if snapshot and _snapshot_is_fresh(snapshot, max_cache_age_seconds):
            indexed_files = snapshot.get("files", [])
            results, searched_files = _search_indexed_files(
                indexed_files,
                query,
                min_size_bytes,
                max_results,
                progress_callback=progress_callback,
                root=root,
            )
            age_seconds = _snapshot_age_seconds(snapshot)
            return {
                "root": root,
                "query": query,
                "results": results,
                "searched_files": searched_files,
                "skipped_entries": 0,
                "errors": [],
                "result_source": "index_cache",
                "snapshot_created_at": snapshot.get("created_at"),
                "index_age_seconds": round(age_seconds, 2) if age_seconds is not None else None,
            }

    stack = [root]
    results: list[dict] = []
    errors: list[dict] = []
    searched_files = 0
    skipped_entries = 0

    while stack and len(results) < max_results:
        current_directory = stack.pop()

        try:
            entries = list(os.scandir(current_directory))
        except OSError as error:
            skipped_entries += 1
            errors.append({"path": current_directory, "message": str(error)})
            continue

        for entry in entries:
            full_path = entry.path

            if entry.is_symlink():
                skipped_entries += 1
                continue

            try:
                if entry.is_dir(follow_symlinks=False):
                    stack.append(full_path)
                    report_progress.send(
                        current_path=full_path,
                        searched_files=searched_files,
                        results=len(results),
                    )
                    continue

                if not entry.is_file(follow_symlinks=False):
                    skipped_entries += 1
                    continue
            except OSError as error:
                skipped_entries += 1
                errors.append({"path": full_path, "message": str(error)})
                continue

            searched_files += 1
            if normalized_query not in entry.name.lower():
                report_progress.send(
                    current_path=full_path,
                    searched_files=searched_files,
                    results=len(results),
                )
                continue

            try:
                stat = entry.stat(follow_symlinks=False)
            except OSError as error:
                skipped_entries += 1
                errors.append({"path": full_path, "message": str(error)})
                continue

            if stat.st_size < min_size_bytes:
                report_progress.send(
                    current_path=full_path,
                    searched_files=searched_files,
                    results=len(results),
                )
                continue

            results.append(_build_file_record(full_path, stat))

            report_progress.send(
                current_path=full_path,
                searched_files=searched_files,
                results=len(results),
            )

            if len(results) >= max_results:
                break

    results.sort(key=lambda item: (-item["size"], item["path"]))
    return {
        "root": root,
        "query": query,
        "results": results,
        "searched_files": searched_files,
        "skipped_entries": skipped_entries,
        "errors": errors[:20],
        "result_source": "live_walk",
        "snapshot_created_at": None,
        "index_age_seconds": None,
    }


def _collect_old_entries(root_path: str, max_age_days: int = 3, max_targets: int = 300) -> dict:
    if not os.path.exists(root_path):
        return {"root": root_path, "count": 0, "size": 0, "targets": []}

    cutoff = time.time() - max_age_days * 24 * 60 * 60
    stack = [root_path]
    targets: list[dict] = []
    total_size = 0

    while stack and len(targets) < max_targets:
        current_directory = stack.pop()

        try:
            entries = list(os.scandir(current_directory))
        except OSError:
            continue

        for entry in entries:
            if entry.is_symlink():
                continue

            full_path = entry.path
            try:
                stat = entry.stat(follow_symlinks=False)
            except OSError:
                continue

            if entry.is_dir(follow_symlinks=False):
                stack.append(full_path)

            if stat.st_mtime > cutoff:
                continue

            targets.append(
                {
                    "path": full_path,
                    "name": os.path.basename(full_path),
                    "size": stat.st_size,
                    "modified_at": _to_iso(stat.st_mtime),
                    "risk": build_risk_level(full_path),
                }
            )
            total_size += stat.st_size

            if len(targets) >= max_targets:
                break

    return {"root": root_path, "count": len(targets), "size": total_size, "targets": targets}


def _collect_download_suggestions(
    root_path: str, min_size_bytes: int = 200 * 1024 * 1024, max_age_days: int = 14, max_results: int = 12
) -> list[dict]:
    if not os.path.exists(root_path):
        return []

    cutoff = time.time() - max_age_days * 24 * 60 * 60
    stack = [root_path]
    results: list[dict] = []

    while stack:
        current_directory = stack.pop()

        try:
            entries = list(os.scandir(current_directory))
        except OSError:
            continue

        for entry in entries:
            if entry.is_symlink():
                continue

            full_path = entry.path

            try:
                if entry.is_dir(follow_symlinks=False):
                    stack.append(full_path)
                    continue

                if not entry.is_file(follow_symlinks=False):
                    continue

                stat = entry.stat(follow_symlinks=False)
            except OSError:
                continue

            if stat.st_size < min_size_bytes or stat.st_mtime > cutoff:
                continue

            results.append(
                {
                    "path": full_path,
                    "name": os.path.basename(full_path),
                    "size": stat.st_size,
                    "modified_at": _to_iso(stat.st_mtime),
                    "risk": build_risk_level(full_path),
                }
            )

    results.sort(key=lambda item: (-item["size"], item["path"]))
    return results[:max_results]


def analyze_cleanup(
    max_age_days: int = 3,
    download_min_size_bytes: int = 200 * 1024 * 1024,
    download_max_age_days: int = 14,
) -> dict:
    user_temp_path = os.environ.get("TEMP", str(pathlib.Path.home()))
    windows_temp_path = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "Temp")
    downloads_path = str(pathlib.Path.home() / "Downloads")

    user_temp = _collect_old_entries(user_temp_path, max_age_days=max_age_days, max_targets=300)
    windows_temp = _collect_old_entries(windows_temp_path, max_age_days=max_age_days, max_targets=200)
    download_targets = _collect_download_suggestions(
        downloads_path,
        min_size_bytes=download_min_size_bytes,
        max_age_days=download_max_age_days,
        max_results=12,
    )

    return {
        "scanned_at": _to_iso(time.time()),
        "user_temp": {
            "label": "用户临时目录",
            "path": user_temp_path,
            "count": user_temp["count"],
            "size": user_temp["size"],
            "targets": user_temp["targets"],
        },
        "windows_temp": {
            "label": "Windows 临时目录",
            "path": windows_temp_path,
            "count": windows_temp["count"],
            "size": windows_temp["size"],
            "targets": windows_temp["targets"],
        },
        "downloads": {
            "label": "下载目录大文件建议",
            "path": downloads_path,
            "count": len(download_targets),
            "size": sum(item["size"] for item in download_targets),
            "targets": download_targets,
        },
        "estimated_recoverable_bytes": user_temp["size"] + windows_temp["size"],
        "notes": [
            "默认只建议清理临时文件和用户可识别的大文件",
            "系统关键目录不会进入一键删除范围",
            "Windows 临时目录部分文件可能因权限或占用而无法删除",
        ],
    }


def move_to_recycle_bin(target_path: str) -> dict:
    resolved_path = os.path.abspath(target_path)
    if is_protected_path(resolved_path):
        raise ValueError("该路径属于受保护系统目录，已阻止删除")

    if not os.path.exists(resolved_path):
        raise FileNotFoundError("目标路径不存在")

    file_operation = SHFILEOPSTRUCTW()
    file_operation.wFunc = FO_DELETE
    file_operation.pFrom = resolved_path + "\0\0"
    file_operation.fFlags = FOF_ALLOWUNDO | FOF_NOCONFIRMATION | FOF_SILENT | FOF_NOERRORUI

    result = ctypes.windll.shell32.SHFileOperationW(ctypes.byref(file_operation))
    if result != 0:
        raise OSError(f"移动到回收站失败，错误码: {result}")

    return {"path": resolved_path, "success": True}


def run_temp_cleanup(analysis: dict, mover: Callable[[str], dict] | None = None) -> dict:
    mover = mover or move_to_recycle_bin
    results: list[dict] = []
    reclaimed_bytes = 0

    for group_name in ("user_temp", "windows_temp"):
        group = analysis.get(group_name, {})
        for target in group.get("targets", []):
            try:
                mover(target["path"])
                reclaimed_bytes += target["size"]
                results.append({"path": target["path"], "size": target["size"], "success": True})
            except Exception as error:
                results.append(
                    {
                        "path": target["path"],
                        "size": target["size"],
                        "success": False,
                        "message": str(error),
                    }
                )

    return {
        "cleaned_at": _to_iso(time.time()),
        "reclaimed_bytes": reclaimed_bytes,
        "success_count": sum(1 for item in results if item["success"]),
        "failure_count": sum(1 for item in results if not item["success"]),
        "results": results,
    }


def empty_recycle_bin() -> dict:
    result = ctypes.windll.shell32.SHEmptyRecycleBinW(
        None, None, SHERB_NOCONFIRMATION | SHERB_NOPROGRESSUI | SHERB_NOSOUND
    )
    if result != 0:
        raise OSError(f"清空回收站失败，错误码: {result}")
    return {"success": True}


def invalidate_scan_cache(root_path: str) -> None:
    delete_snapshot(root_path)
