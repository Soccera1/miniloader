#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: test_xfs.py TEST_BINARY")
    if not shutil.which("mkfs.xfs"):
        raise SystemExit("mkfs.xfs is required for XFS reader tests")
    with tempfile.TemporaryDirectory(prefix="miniloader-xfs-") as temp:
        root = Path(temp)
        tree = root / "tree"
        (tree / "boot").mkdir(parents=True)
        (tree / "boot" / "hello.txt").write_bytes(b"MiniLoader XFS fixture\n")
        (tree / "boot" / "hello-link").symlink_to("hello.txt")
        image = root / "fixture.xfs"
        with image.open("wb") as stream:
            stream.truncate(512 * 1024 * 1024)
        subprocess.run(["mkfs.xfs", "-f", "-q", "-p", str(tree), str(image)],
                       check=True)
        subprocess.run([sys.argv[1], str(image)], check=True)


if __name__ == "__main__":
    main()
