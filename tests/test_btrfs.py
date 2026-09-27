#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Exercise the read-only Btrfs driver against a generated filesystem image."""

import subprocess
import sys
import tempfile
from pathlib import Path

from make_btrfs_image import create_image


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: test_btrfs.py BTRFS_TEST")
    executable = sys.argv[1]
    with tempfile.TemporaryDirectory(prefix="miniloader-btrfs-") as temporary:
        directory = Path(temporary)
        root = directory / "root"
        boot = root / "boot"
        boot.mkdir(parents=True)
        (boot / "miniloader.conf").write_bytes(
            b"timeout=5\ndefault=btrfs-test\n")
        payload = bytes((((index * 37) ^ (index >> 7)) & 0xFF)
                        for index in range(300123))
        (boot / "payload.bin").write_bytes(payload)
        image = directory / "btrfs.img"
        create_image(image, root,
                     "4b1f3ed4-0dd0-4aac-9c8f-5a881de1724c")
        subprocess.run([executable, str(image)], check=True)
    print("Btrfs image-backed file read tests passed")


if __name__ == "__main__":
    main()
