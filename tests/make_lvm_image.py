#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Wrap an ext4 image in a small single-PV LVM2 linear logical volume."""

import argparse
import subprocess
from pathlib import Path


SECTOR = 512
PV_START_LBA = 2048
PV_BYTES = 128 * 1024 * 1024
PE_START_SECTORS = 2048
MDA_OFFSET = 4096
MDA_SIZE = 65536
PV_RAW_ID = b"0123456789abcdefghijklmnopqrstuv"
PV_ID = "012345-6789-abcd-efgh-ijkl-mnop-qrstuv"
VG_ID = "abcdef-1234-5678-90ab-cdef-1234-567890"
LV_ID = "987654-3210-fedc-ba98-7654-3210-fedcba"


def put_le32(buffer, offset, value):
    buffer[offset:offset + 4] = value.to_bytes(4, "little")


def put_le64(buffer, offset, value):
    buffer[offset:offset + 8] = value.to_bytes(8, "little")


def create_image(disk_path, lv_path):
    disk_path = Path(disk_path)
    lv_path = Path(lv_path)
    if lv_path.stat().st_size > PV_BYTES - PE_START_SECTORS * SECTOR:
        raise SystemExit("logical volume image exceeds the LVM physical data area")

    with disk_path.open("wb") as disk:
        disk.truncate(160 * 1024 * 1024)
    subprocess.run([
        "sgdisk", "--clear", "--new=1:2048:+128M", "--typecode=1:8e00",
        str(disk_path),
    ], check=True, stdout=subprocess.DEVNULL)

    label = bytearray(SECTOR)
    label[0:8] = b"LABELONE"
    put_le64(label, 8, 1)
    put_le32(label, 20, 32)
    label[24:32] = b"LVM2 001"
    pvh = 32
    label[pvh:pvh + 32] = PV_RAW_ID
    put_le64(label, pvh + 32, PV_BYTES)
    put_le64(label, pvh + 40, 1024 * 1024)
    put_le64(label, pvh + 48, PV_BYTES - 1024 * 1024)
    put_le64(label, pvh + 72, MDA_OFFSET)
    put_le64(label, pvh + 80, MDA_SIZE)

    metadata = (
        "vgtest {\n"
        f" id = \"{VG_ID}\"\n"
        " extent_size = 128\n"
        " physical_volumes {\n"
        f"  pv0 {{ id = \"{PV_ID}\" pe_start = {PE_START_SECTORS} }}\n"
        " }\n"
        " logical_volumes {\n"
        "  root {\n"
        f"   id = \"{LV_ID}\"\n"
        "   status = [ \"READ\", \"WRITE\", \"VISIBLE\" ]\n"
        "   segment_count = 1\n"
        "   segment1 { start_extent = 0 extent_count = 1024 type = \"linear\" stripe_count = 1 stripes = [ \"pv0\", 0 ] }\n"
        "  }\n"
        " }\n"
        "}\n"
    ).encode("ascii")

    mda = bytearray(MDA_SIZE)
    mda[4:20] = b" LVM2 x[5A%r0N*>"
    put_le32(mda, 20, 1)
    put_le64(mda, 24, MDA_OFFSET)
    put_le64(mda, 32, MDA_SIZE)
    put_le64(mda, 40, 512)
    put_le64(mda, 48, len(metadata))
    mda[512:512 + len(metadata)] = metadata

    partition_offset = PV_START_LBA * SECTOR
    with disk_path.open("r+b") as disk:
        disk.seek(partition_offset + SECTOR)
        disk.write(label)
        disk.seek(partition_offset + MDA_OFFSET)
        disk.write(mda)
        disk.seek(partition_offset + PE_START_SECTORS * SECTOR)
        disk.write(lv_path.read_bytes())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("disk")
    parser.add_argument("logical_volume")
    args = parser.parse_args()
    create_image(args.disk, args.logical_volume)


if __name__ == "__main__":
    main()
