# SPDX-License-Identifier: GPL-3.0-or-later
import subprocess
import sys
import tempfile
from pathlib import Path


def set_fat12(table, cluster, value):
    offset = cluster + cluster // 2
    pair = table[offset] | table[offset + 1] << 8
    if cluster & 1:
        pair = (pair & 0x000f) | ((value & 0x0fff) << 4)
    else:
        pair = (pair & 0xf000) | (value & 0x0fff)
    table[offset] = pair & 0xff
    table[offset + 1] = pair >> 8


def set_fat_entry(table, bits, cluster, value):
    if bits == 12:
        set_fat12(table, cluster, value)
    elif bits == 16:
        table[cluster * 2:cluster * 2 + 2] = value.to_bytes(2, "little")
    else:
        table[cluster * 4:cluster * 4 + 4] = value.to_bytes(4, "little")


def short_checksum(name):
    checksum = 0
    for byte in name:
        checksum = (((0x80 if checksum & 1 else 0) + (checksum >> 1) + byte)
                    & 0xff)
    return checksum


def short_entry(name, attributes, cluster, size=0):
    entry = bytearray(32)
    entry[:11] = name
    entry[11] = attributes
    entry[26:28] = (cluster & 0xffff).to_bytes(2, "little")
    entry[20:22] = ((cluster >> 16) & 0xffff).to_bytes(2, "little")
    entry[28:32] = size.to_bytes(4, "little")
    return entry


def lfn_entries(name, sfn):
    chars = [ord(ch) for ch in name]
    slots = (len(chars) + 1 + 12) // 13
    chars += [0] + [0xffff] * (slots * 13 - len(chars) - 1)
    offsets = (1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30)
    checksum = short_checksum(sfn)
    result = []
    for ordinal in range(slots, 0, -1):
        entry = bytearray(32)
        entry[0] = ordinal | (0x40 if ordinal == slots else 0)
        entry[11] = 0x0f
        entry[12] = 0
        entry[13] = checksum
        entry[26:28] = bytes(2)
        piece = chars[(ordinal - 1) * 13:ordinal * 13]
        for offset, char in zip(offsets, piece):
            entry[offset:offset + 2] = char.to_bytes(2, "little")
        result.append(entry)
    return result


def make_image(path, expected, fat_type):
    if fat_type == 12:
        bps, spc, reserved, fats, root_entries = 512, 1, 1, 2, 224
        total, fat_sectors, root_cluster = 2880, 9, 0
    elif fat_type == 16:
        bps, spc, reserved, fats, root_entries = 512, 1, 1, 2, 512
        total, fat_sectors, root_cluster = 8192, 32, 0
    else:
        bps, spc, reserved, fats, root_entries = 512, 1, 32, 2, 0
        total, fat_sectors, root_cluster = 131072, 1024, 2
    root_sectors = (root_entries * 32 + bps - 1) // bps
    data_start = reserved + fats * fat_sectors + root_sectors
    image_size = total * bps
    table = bytearray(fat_sectors * bps)
    end_marker = {12: 0xfff, 16: 0xffff, 32: 0x0fffffff}[fat_type]
    first_marker = {12: 0xff8, 16: 0xfff8, 32: 0x0ffffff8}[fat_type]
    set_fat_entry(table, fat_type, 0, first_marker)
    set_fat_entry(table, fat_type, 1, end_marker)
    if fat_type == 32:
        set_fat_entry(table, fat_type, 2, end_marker)
    set_fat_entry(table, fat_type, 3, end_marker)
    file_clusters = (len(expected) + bps - 1) // bps
    for index in range(file_clusters):
        set_fat_entry(table, fat_type, 4 + index,
                      4 + index + 1 if index + 1 < file_clusters else end_marker)

    boot = bytearray(512)
    boot[0:3] = b"\xeb\x3c\x90"
    boot[3:11] = b"MINILOAD"
    boot[11:13] = bps.to_bytes(2, "little")
    boot[13] = spc
    boot[14:16] = reserved.to_bytes(2, "little")
    boot[16] = fats
    boot[17:19] = root_entries.to_bytes(2, "little")
    if total <= 0xffff:
        boot[19:21] = total.to_bytes(2, "little")
    else:
        boot[32:36] = total.to_bytes(4, "little")
    boot[21] = 0xf8
    if fat_type == 32:
        boot[36:40] = fat_sectors.to_bytes(4, "little")
        boot[40:42] = bytes(2)
        boot[42:44] = bytes(2)
        boot[44:48] = root_cluster.to_bytes(4, "little")
        boot[48:50] = (1).to_bytes(2, "little")
        boot[50:52] = (6).to_bytes(2, "little")
        boot[64] = 0x80
        boot[66] = 0x29
        boot[82:90] = b"FAT32   "
    else:
        boot[22:24] = fat_sectors.to_bytes(2, "little")
        boot[36] = 0x80
        boot[38] = 0x29
        boot[54:62] = {12: b"FAT12   ", 16: b"FAT16   "}[fat_type]
    boot[510:512] = b"\x55\xaa"

    sfn = b"MINILO~1CNF"
    boot_entry = short_entry(b"BOOT       ", 0x10, 3)
    config_entry = short_entry(sfn, 0x20, 4, len(expected))
    long_entries = lfn_entries("miniloader.conf", sfn)
    config_directory = b"".join(long_entries) + config_entry + bytes(32)
    with path.open("wb") as image:
        image.truncate(image_size)
        image.seek(0)
        image.write(boot)
        fat_offset = reserved * bps
        image.seek(fat_offset)
        image.write(table)
        image.seek(fat_offset + fat_sectors * bps)
        image.write(table)
        if fat_type == 32:
            root_data_offset = (data_start + root_cluster - 2) * bps
            image.seek(root_data_offset)
            image.write(boot_entry + bytes(480))
        else:
            root_offset = (reserved + fats * fat_sectors) * bps
            image.seek(root_offset)
            image.write(boot_entry + bytes(root_entries * 32 - 32))
        boot_dir_offset = (data_start + 3 - 2) * bps
        image.seek(boot_dir_offset)
        image.write(config_directory + bytes(512 - len(config_directory)))
        for index in range(file_clusters):
            start = index * bps
            chunk = expected[start:start + bps].ljust(bps, b"\0")
            cluster = 4 + index
            image.seek((data_start + cluster - 2) * bps)
            image.write(chunk)


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: test_vfat.py VFAT_TEST")
    executable = sys.argv[1]
    with tempfile.TemporaryDirectory(prefix="miniloader-vfat-") as temporary:
        root = Path(temporary)
        expected = bytes((index * 29 + 11) & 0xff for index in range(1500))
        expected_path = root / "miniloader.conf"
        expected_path.write_bytes(expected)
        for fat_type in (12, 16, 32):
            image = root / f"fat{fat_type}.img"
            make_image(image, expected, fat_type)
            subprocess.run([executable, str(image), str(expected_path)], check=True)
        valid_fat32 = root / "fat32.img"
        for name, offset, value, expected_error in (
            ("bad-version.img", 42, b"\x01\x00", "unsupported"),
            ("bad-root.img", 44, bytes(4), "bad-format"),
        ):
            malformed = root / name
            malformed.write_bytes(valid_fat32.read_bytes())
            with malformed.open("r+b") as image:
                image.seek(offset)
                image.write(value)
            subprocess.run([executable, str(malformed), "check-error",
                            expected_error], check=True)
    print("FAT12/FAT16/FAT32 fixtures passed")


if __name__ == "__main__":
    main()
