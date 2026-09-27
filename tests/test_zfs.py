#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Run MiniLoader's ZFS reader against the compact reference pool fixture."""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: test_zfs.py TEST_BINARY")
    root = Path(__file__).resolve().parent
    archive = root / "fixtures" / "zol-0.6.2.tar.bz2"
    with tempfile.TemporaryDirectory(prefix="miniloader-zfs-") as temporary:
        target = Path(temporary)
        subprocess.run(
            ["tar", "-xjf", str(archive), "-C", str(target),
             "--strip-components=1"],
            check=True,
        )
        paths = [str(target / f"vdev{index}") for index in range(4)]
        subprocess.run([sys.argv[1], *paths], check=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
