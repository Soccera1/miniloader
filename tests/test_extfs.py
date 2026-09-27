# SPDX-License-Identifier: GPL-3.0-or-later
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


def run(*args):
    try:
        subprocess.run(args, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError as error:
        sys.stderr.buffer.write(error.stdout or b"")
        sys.stderr.buffer.write(error.stderr or b"")
        raise


def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: test_extfs.py EXT2_TEST EXT4_TEST")
    mkfs = shutil.which("mke2fs")
    if not mkfs:
        print("ext filesystem image tests skipped (mke2fs is unavailable)")
        return

    ext2_test, ext4_test = sys.argv[1:]
    with tempfile.TemporaryDirectory(prefix="miniloader-ext-") as temporary:
        root = Path(temporary) / "root"
        boot = root / "boot"
        boot.mkdir(parents=True)
        payload_path = boot / "kernel"
        payload = bytes((i * 37 + (i >> 8) * 13) & 0xFF for i in range(900_000))
        payload_path.write_bytes(payload)
        config = boot / "miniloader.conf"
        config.write_bytes(b"timeout=5\ndefault=linux\n")

        images = []
        for fs_type, executable in (("ext2", ext2_test),
                                    ("ext3", ext2_test),
                                    ("ext4", ext4_test)):
            image = Path(temporary) / f"{fs_type}.img"
            with image.open("wb") as output:
                output.truncate(96 * 1024 * 1024)
            options = "^dir_index" if fs_type != "ext4" else ""
            command = [mkfs, "-q", "-F", "-t", fs_type]
            if options:
                command.extend(("-O", options))
            command.extend(("-d", str(root), str(image)))
            run(*command)
            run(executable, str(image), str(payload_path))
            images.append(image)

        damaged = Path(temporary) / "unsupported-feature.img"
        shutil.copyfile(images[-1], damaged)
        with damaged.open("r+b") as image:
            image.seek(1024 + 96)
            current = int.from_bytes(image.read(4), "little")
            image.seek(1024 + 96)
            image.write((current | 0x40000000).to_bytes(4, "little"))
        run(ext4_test, str(damaged), str(payload_path), "reject")
    print("ext2/ext3/ext4 image tests passed")


if __name__ == "__main__":
    main()
