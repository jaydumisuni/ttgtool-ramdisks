#!/usr/bin/env python3
"""Inventory a local ramdisk ZIP without executing or extracting its contents."""

from __future__ import annotations

import argparse
import hashlib
import json
import stat
import sys
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

MAX_ARCHIVE_BYTES = 8 * 1024 * 1024 * 1024
MAX_MEMBER_BYTES = 2 * 1024 * 1024 * 1024
MAX_MEMBERS = 10_000

ROLE_BY_NAME = {
    "gaster": "gaster_executable",
    "gaster.exe": "gaster_executable",
    "irecovery": "irecovery_executable",
    "irecovery.exe": "irecovery_executable",
    "ibss.img4": "ibss",
    "ibec.img4": "ibec",
    "logo.img4": "logo",
    "ramdisk.img4": "ramdisk",
    "devicetree.img4": "devicetree",
    "trustcache.img4": "trustcache",
    "kernelcache.img4": "kernelcache",
}


def _safe_name(name: str) -> PurePosixPath:
    if not name or "\x00" in name or "\\" in name:
        raise ValueError(f"unsafe member path: {name!r}")
    path = PurePosixPath(name)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError(f"unsafe member path: {name!r}")
    return path


def _is_symlink(info: zipfile.ZipInfo) -> bool:
    mode = (info.external_attr >> 16) & 0xFFFF
    return stat.S_ISLNK(mode)


def _hash_member(archive: zipfile.ZipFile, info: zipfile.ZipInfo) -> str:
    digest = hashlib.sha256()
    read_bytes = 0
    with archive.open(info, "r") as source:
        while True:
            block = source.read(1024 * 1024)
            if not block:
                break
            read_bytes += len(block)
            if read_bytes > MAX_MEMBER_BYTES:
                raise ValueError(f"member exceeds limit while reading: {info.filename}")
            digest.update(block)
    if read_bytes != info.file_size:
        raise ValueError(f"member size changed while reading: {info.filename}")
    return digest.hexdigest()


def inventory(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise ValueError(f"archive not found: {path}")
    if path.stat().st_size > MAX_ARCHIVE_BYTES:
        raise ValueError("archive exceeds maximum accepted size")

    archive_hash = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            archive_hash.update(block)

    members: list[dict[str, Any]] = []
    classified: list[dict[str, Any]] = []
    seen_paths: set[str] = set()
    total_uncompressed = 0

    with zipfile.ZipFile(path, "r") as archive:
        infos = archive.infolist()
        if len(infos) > MAX_MEMBERS:
            raise ValueError("archive has too many members")
        for info in infos:
            safe_path = _safe_name(info.filename)
            normalized = safe_path.as_posix()
            if normalized.casefold() in seen_paths:
                raise ValueError(f"duplicate case-insensitive member path: {normalized}")
            seen_paths.add(normalized.casefold())
            if info.is_dir():
                continue
            if _is_symlink(info):
                raise ValueError(f"symbolic-link member is not accepted: {normalized}")
            if info.file_size <= 0 or info.file_size > MAX_MEMBER_BYTES:
                raise ValueError(f"invalid member size: {normalized}")
            total_uncompressed += info.file_size
            if total_uncompressed > MAX_ARCHIVE_BYTES:
                raise ValueError("archive expands beyond the accepted total size")

            sha256 = _hash_member(archive, info)
            record = {
                "relative_path": normalized,
                "byte_len": info.file_size,
                "compressed_byte_len": info.compress_size,
                "sha256": sha256,
            }
            members.append(record)
            role = ROLE_BY_NAME.get(safe_path.name.casefold())
            if role:
                classified.append(
                    {
                        "role": role,
                        "relative_path": normalized,
                        "sha256": sha256,
                        "byte_len": info.file_size,
                        "redistribution_allowed": False,
                    }
                )

    duplicate_roles = sorted(
        role for role in {item["role"] for item in classified}
        if sum(1 for item in classified if item["role"] == role) > 1
    )
    if duplicate_roles:
        raise ValueError(f"duplicate classified roles: {duplicate_roles}")

    return {
        "schema_version": "tgcheckm8.package-inventory.v1",
        "archive_name": path.name,
        "archive_byte_len": path.stat().st_size,
        "archive_sha256": archive_hash.hexdigest(),
        "member_count": len(members),
        "total_uncompressed_bytes": total_uncompressed,
        "classified_assets": sorted(classified, key=lambda item: item["role"]),
        "members": sorted(members, key=lambda item: item["relative_path"]),
        "execution_performed": False,
        "extraction_performed": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Create a non-executing SHA-256 inventory of a ramdisk ZIP"
    )
    parser.add_argument("archive", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)

    try:
        result = inventory(args.archive.resolve())
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        print(f"inventory failed: {exc}", file=sys.stderr)
        return 2

    payload = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        output = args.output.resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(payload, encoding="utf-8")
    else:
        sys.stdout.write(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
