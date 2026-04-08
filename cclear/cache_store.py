from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path


CLEAR_CACHE_VERSION = 1


def get_data_dir() -> Path:
    custom_path = os.environ.get("CCLEAR_DATA_DIR")
    if custom_path:
        return Path(custom_path)

    return Path.home() / ".cclear"


def get_cache_dir() -> Path:
    cache_dir = get_data_dir() / "cache"
    cache_dir.mkdir(parents=True, exist_ok=True)
    return cache_dir


def _cache_key(root_path: str) -> str:
    normalized_root = os.path.normcase(os.path.normpath(os.path.abspath(root_path)))
    return hashlib.sha1(normalized_root.encode("utf-8")).hexdigest()


def get_snapshot_path(root_path: str) -> Path:
    return get_cache_dir() / f"{_cache_key(root_path)}.json"


def load_snapshot(root_path: str) -> dict | None:
    snapshot_path = get_snapshot_path(root_path)
    if not snapshot_path.exists():
        return None

    try:
        content = json.loads(snapshot_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None

    if content.get("version") != CLEAR_CACHE_VERSION:
        return None

    snapshot_root = content.get("root")
    if not snapshot_root:
        return None

    normalized_input = os.path.normcase(os.path.normpath(os.path.abspath(root_path)))
    normalized_snapshot = os.path.normcase(os.path.normpath(os.path.abspath(snapshot_root)))
    if normalized_input != normalized_snapshot:
        return None

    return content


def save_snapshot(root_path: str, payload: dict) -> str:
    snapshot_path = get_snapshot_path(root_path)
    snapshot_content = {
        "version": CLEAR_CACHE_VERSION,
        **payload,
    }
    snapshot_path.write_text(json.dumps(snapshot_content, ensure_ascii=False), encoding="utf-8")
    return str(snapshot_path)


def delete_snapshot(root_path: str) -> None:
    snapshot_path = get_snapshot_path(root_path)
    try:
        snapshot_path.unlink()
    except FileNotFoundError:
        return
