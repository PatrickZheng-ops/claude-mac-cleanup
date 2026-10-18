#!/usr/bin/env python3
"""Declare local cleanup boundaries. Never scans contents or authorizes deletion."""
from __future__ import annotations

import argparse
import contextlib
import json
import os
from pathlib import Path
import stat
import sys

NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
DIRECTORY = getattr(os, "O_DIRECTORY", 0)
MAX_CONFIG_BYTES = 1024 * 1024
FIELDS = {"schema_version", "kind", "mode", "protected_roots",
          "no_protected_roots", "audit_base", "chrome_user_data_dirs", "shared_paths"}


class SetupError(ValueError):
    """Messages contain categories only, never the supplied private paths."""


class PrivateArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        # argparse's normal error includes unknown user-supplied argument values.
        self.exit(2, '{"status":"failed","reason":"invalid_arguments",'
                     '"deletion_authorized":false}\n')


def absolute_path(value: str | Path) -> Path:
    if not isinstance(value, (str, Path)) or not str(value) or "\x00" in str(value):
        raise SetupError("invalid_path")
    p = Path(value)
    if not p.is_absolute() or ".." in p.parts:
        raise SetupError("absolute_path_without_parent_traversal_required")
    return p


@contextlib.contextmanager
def directory_fd(path: str | Path):
    """Pin every ancestor without following even intermediate symbolic links."""
    p = absolute_path(path)
    fd = os.open(p.anchor, os.O_RDONLY | DIRECTORY | NOFOLLOW)
    try:
        for part in p.parts[1:]:
            nxt = os.open(part, os.O_RDONLY | DIRECTORY | NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = nxt
        yield fd
    finally:
        os.close(fd)


def identity(s: os.stat_result) -> tuple:
    return s.st_dev, s.st_ino


def existing_directory(value: str | Path) -> Path:
    p = absolute_path(value)
    # Opening first is deliberate: resolve() alone would silently follow links.
    with directory_fd(p) as fd:
        before = os.fstat(fd)
        canonical = p.resolve(strict=True)
        if canonical != p:
            raise SetupError("symbolic_link_or_noncanonical_directory")
        with directory_fd(canonical) as check_fd:
            if identity(before) != identity(os.fstat(check_fd)):
                raise SetupError("directory_changed")
    return canonical


def inside(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def overlaps(first: Path, second: Path) -> bool:
    return inside(first, second) or inside(second, first)


def directories(values, category: str) -> list[Path]:
    if not isinstance(values, list) or any(not isinstance(v, str) for v in values):
        raise SetupError("invalid_" + category)
    paths = [existing_directory(v) for v in values]
    if len(set(paths)) != len(paths):
        raise SetupError("duplicate_" + category)
    return paths


def validate_config(data: dict) -> dict:
    if not isinstance(data, dict) or set(data) != FIELDS:
        raise SetupError("invalid_config_fields")
    if type(data["schema_version"]) is not int or data["schema_version"] != 1:
        raise SetupError("unsupported_config_version")
    if data["kind"] != "claude_mac_cleanup_local_config" or data["mode"] != "audit":
        raise SetupError("configuration_must_default_to_audit")
    if type(data["no_protected_roots"]) is not bool:
        raise SetupError("explicit_protection_declaration_required")
    protected = directories(data["protected_roots"], "protected_roots")
    if bool(protected) == data["no_protected_roots"]:
        raise SetupError("explicit_protection_declaration_required")
    chrome = directories(data["chrome_user_data_dirs"], "chrome_user_data_dirs")
    shared = directories(data["shared_paths"], "shared_paths")
    if not isinstance(data["audit_base"], str):
        raise SetupError("invalid_audit_base")
    audit = existing_directory(data["audit_base"])
    if any(overlaps(audit, p) for p in protected + chrome + shared):
        raise SetupError("audit_base_overlaps_a_declared_source")
    return {"schema_version": 1, "kind": "claude_mac_cleanup_local_config",
            "mode": "audit", "protected_roots": [str(p) for p in protected],
            "no_protected_roots": not bool(protected), "audit_base": str(audit),
            "chrome_user_data_dirs": [str(p) for p in chrome],
            "shared_paths": [str(p) for p in shared]}


def source_roots(data: dict) -> list[Path]:
    return [Path(p) for key in ("protected_roots", "chrome_user_data_dirs", "shared_paths")
            for p in data[key]]


def config_location(value: str | Path, data: dict) -> Path:
    p = absolute_path(value)
    parent = existing_directory(p.parent)
    p = parent / p.name
    if any(inside(p, root) for root in source_roots(data)):
        raise SetupError("config_must_be_outside_declared_sources")
    return p


def private_parent(fd: int) -> None:
    s = os.fstat(fd)
    if s.st_uid != os.geteuid() or stat.S_IMODE(s.st_mode) & 0o022:
        raise SetupError("config_parent_must_be_owned_and_not_shared_writable")


def write_new(path: str | Path, data: dict) -> None:
    data = validate_config(data)
    p = config_location(path, data)
    encoded = (json.dumps(data, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    with directory_fd(p.parent) as dfd:
        private_parent(dfd)
        pinned = os.fstat(dfd)
        fd = os.open(p.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | NOFOLLOW, 0o600,
                     dir_fd=dfd)
        with os.fdopen(fd, "wb") as handle:
            os.fchmod(handle.fileno(), 0o600)
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        with directory_fd(p.parent) as current_fd:
            if identity(pinned) != identity(os.fstat(current_fd)):
                raise SetupError("config_delivery_location_changed")


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise SetupError("duplicate_json_key")
        result[key] = value
    return result


def read_config(path: str | Path) -> dict:
    p = absolute_path(path)
    with directory_fd(p.parent) as dfd:
        private_parent(dfd)
        fd = os.open(p.name, os.O_RDONLY | NOFOLLOW | getattr(os, "O_NONBLOCK", 0), dir_fd=dfd)
        with os.fdopen(fd, "rb") as handle:
            before = os.fstat(handle.fileno())
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
                    or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1):
                raise SetupError("config_must_be_private_owned_regular_file")
            if before.st_size > MAX_CONFIG_BYTES:
                raise SetupError("config_too_large")
            raw = handle.read(MAX_CONFIG_BYTES + 1)
            after = os.fstat(handle.fileno())
            if (len(raw) > MAX_CONFIG_BYTES or before.st_size != after.st_size
                    or before.st_mtime_ns != after.st_mtime_ns
                    or before.st_ctime_ns != after.st_ctime_ns):
                raise SetupError("config_changed_during_read")
    data = validate_config(json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object))
    config_location(p, data)
    return data


def summary(data: dict, status: str) -> dict:
    return {"status": status, "mode": "audit",
            "protected_root_count": len(data["protected_roots"]),
            "chrome_user_data_dir_count": len(data["chrome_user_data_dirs"]),
            "shared_path_count": len(data["shared_paths"]),
            "deletion_authorized": False}


def parser() -> argparse.ArgumentParser:
    p = PrivateArgumentParser(description=__doc__)
    commands = p.add_subparsers(dest="command", required=True)
    init = commands.add_parser("init", help="Create a new private local declaration")
    protection = init.add_mutually_exclusive_group(required=True)
    protection.add_argument("--protected-root", action="append")
    protection.add_argument("--no-protected-roots", action="store_true")
    init.add_argument("--audit-base", required=True)
    init.add_argument("--chrome-user-data-dir", action="append", default=[])
    init.add_argument("--shared-path", action="append", default=[])
    init.add_argument("--out", required=True)
    check = commands.add_parser("check", help="Revalidate declared paths; no source contents read")
    check.add_argument("--config", required=True)
    return p


def main(argv=None) -> int:
    args = parser().parse_args(argv)
    try:
        if not NOFOLLOW or not DIRECTORY:
            raise SetupError("platform_requires_nofollow_directory_support")
        if args.command == "init":
            data = validate_config({"schema_version": 1,
                    "kind": "claude_mac_cleanup_local_config", "mode": "audit",
                    "protected_roots": args.protected_root or [],
                    "no_protected_roots": args.no_protected_roots,
                    "audit_base": args.audit_base,
                    "chrome_user_data_dirs": args.chrome_user_data_dir,
                    "shared_paths": args.shared_path})
            write_new(args.out, data)
            result = summary(read_config(args.out), "created_and_checked")
        else:
            result = summary(read_config(args.config), "checked")
        print(json.dumps(result, sort_keys=True))
        return 0
    except (OSError, ValueError, UnicodeError) as exc:
        reason = str(exc) if isinstance(exc, SetupError) else type(exc).__name__
        print(json.dumps({"status": "failed", "reason": reason,
                          "deletion_authorized": False}, sort_keys=True), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
