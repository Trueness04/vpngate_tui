#!/usr/bin/env python3
"""Package a PyInstaller terminal executable for release (no external deps)."""
from __future__ import annotations

import sys
import tarfile
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit("Usage: python scripts/package_release.py BINARY ARCHIVE")
    binary = Path(sys.argv[1])
    archive = Path(sys.argv[2])
    if not binary.is_file():
        raise SystemExit(f"Missing built executable: {binary}")
    archive.parent.mkdir(parents=True, exist_ok=True)
    if archive.name.endswith(".zip"):
        with ZipFile(archive, "w", compression=ZIP_DEFLATED, compresslevel=9) as output:
            output.write(binary, arcname=binary.name)
    elif archive.name.endswith(".tar.gz"):
        with tarfile.open(archive, "w:gz") as output:
            output.add(binary, arcname=binary.name)
    else:
        raise SystemExit(f"Unsupported archive format: {archive}")
    print(f"Created {archive} ({archive.stat().st_size:,} bytes)")


if __name__ == "__main__":
    main()
