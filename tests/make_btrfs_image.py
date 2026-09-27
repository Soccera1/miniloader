#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Build a compact, read-only Btrfs image for MiniLoader integration tests."""

import argparse
import os
import struct
import uuid as uuid_module
from pathlib import Path


SECTOR_SIZE = 4096
SUPER_OFFSET = 0x10000
ROOT_TREE = 0x20000
FS_TREE = 0x21000
CHUNK_TREE = 0x22000
DATA_START = 0x40000
MIN_IMAGE_SIZE = 16 * 1024 * 1024
HEADER_SIZE = 0x65
CSUM_SEED = 0


def crc32c(data, seed=CSUM_SEED):
    crc = seed ^ 0xFFFFFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
    return crc ^ 0xFFFFFFFF


def align(value, boundary):
    return (value + boundary - 1) & ~(boundary - 1)


def key(object_id, item_type, offset):
    return struct.pack("<QBQ", object_id, item_type, offset)


def inode_item(size, mode):
    payload = bytearray(160)
    struct.pack_into("<Q", payload, 0x10, size)
    struct.pack_into("<I", payload, 0x34, mode)
    return bytes(payload)


def dir_item(target_id, name, kind):
    encoded = name.encode("utf-8")
    offset = (~crc32c(encoded, 1)) & 0xFFFFFFFF
    payload = (key(target_id, 1, 0) + bytes(8) +
               struct.pack("<HHB", 0, len(encoded), kind) + encoded)
    return offset, payload


def file_extent(size, logical_address):
    return struct.pack("<QQBBHBQQQQ", 0, size, 0, 0, 0, 1,
                       logical_address, size, 0, size)


def set_tree_checksum(block):
    block[:4] = struct.pack("<I", crc32c(block[0x20:]))


def make_leaf(address, fs_uuid, items, block_size=SECTOR_SIZE):
    items = sorted(items, key=lambda item: struct.unpack("<QBQ", item[0]))
    block = bytearray(block_size)
    block[0x20:0x30] = fs_uuid
    struct.pack_into("<Q", block, 0x30, address)
    struct.pack_into("<I", block, 0x60, len(items))
    block[0x64] = 0
    payload_offset = len(items) * 25
    for index, (item_key, item_value) in enumerate(items):
        descriptor = HEADER_SIZE + index * 25
        block[descriptor:descriptor + 17] = item_key
        struct.pack_into("<II", block, descriptor + 17,
                         payload_offset, len(item_value))
        start = HEADER_SIZE + payload_offset
        end = start + len(item_value)
        if end > block_size:
            raise ValueError("Btrfs leaf exceeds its 4 KiB node")
        block[start:end] = item_value
        payload_offset += len(item_value)
    set_tree_checksum(block)
    return block


def create_image(output_path, root, fs_uuid):
    output_path = Path(output_path)
    root = Path(root)
    if not root.is_dir():
        raise ValueError(f"Btrfs root is not a directory: {root}")

    fs_id = uuid_module.UUID(fs_uuid).bytes
    directories = {Path(".")}
    files = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if path.is_dir():
            directories.add(relative)
            for parent in relative.parents:
                directories.add(parent)
        elif path.is_file():
            files.append((relative, path.read_bytes()))
            for parent in relative.parents:
                directories.add(parent)

    directory_list = [Path(".")] + sorted(
        (path for path in directories if path != Path(".")),
        key=lambda path: (len(path.parts), path.as_posix()),
    )
    inode_ids = {Path("."): 256}
    for index, path in enumerate(directory_list[1:], start=257):
        inode_ids[path] = index
    next_inode = 256 + len(directory_list)
    file_ids = {}
    for relative, _ in files:
        file_ids[relative] = next_inode
        next_inode += 1

    tree_items = []
    for directory in directory_list:
        inode_id = inode_ids[directory]
        tree_items.append((key(inode_id, 1, 0), inode_item(0, 0o040755)))
    for relative, contents in files:
        inode_id = file_ids[relative]
        tree_items.append((key(inode_id, 1, 0),
                           inode_item(len(contents), 0o100644)))

    directory_children = {directory: [] for directory in directory_list}
    for directory in directory_list[1:]:
        parent = directory.parent
        directory_children[parent].append(
            (directory.name, inode_ids[directory], 2))
    for relative, _ in files:
        directory_children[relative.parent].append(
            (relative.name, file_ids[relative], 1))
    for directory, children in directory_children.items():
        parent_id = inode_ids[directory]
        for name, target_id, kind in children:
            name_hash, payload = dir_item(target_id, name, kind)
            tree_items.append((key(parent_id, 0x54, name_hash), payload))

    cursor = DATA_START
    data_extents = []
    for relative, contents in files:
        if not contents:
            continue
        cursor = align(cursor, 4096)
        address = cursor
        cursor += len(contents)
        data_extents.append((relative, address, contents))
        tree_items.append((key(file_ids[relative], 0x6C, 0),
                           file_extent(len(contents), address)))

    image_size = align(max(MIN_IMAGE_SIZE, cursor + 4096), 4096)
    image = bytearray(image_size)

    root_value = bytearray(192)
    struct.pack_into("<Q", root_value, 0xB0, FS_TREE)
    struct.pack_into("<Q", root_value, 0xB8, 256)
    root_leaf = make_leaf(ROOT_TREE, fs_id,
                         [(key(5, 0x84, 0), bytes(root_value))])
    fs_leaf = make_leaf(FS_TREE, fs_id, tree_items)
    chunk_leaf = make_leaf(CHUNK_TREE, fs_id, [])
    image[ROOT_TREE:ROOT_TREE + len(root_leaf)] = root_leaf
    image[FS_TREE:FS_TREE + len(fs_leaf)] = fs_leaf
    image[CHUNK_TREE:CHUNK_TREE + len(chunk_leaf)] = chunk_leaf
    for _, address, contents in data_extents:
        image[address:address + len(contents)] = contents

    superblock = memoryview(image)[SUPER_OFFSET:SUPER_OFFSET + 4096]
    superblock[0x20:0x30] = fs_id
    superblock[0x40:0x48] = b"_BHRfS_M"
    struct.pack_into("<Q", superblock, 0x48, 1)  # generation
    struct.pack_into("<Q", superblock, 0x50, ROOT_TREE)
    struct.pack_into("<Q", superblock, 0x58, CHUNK_TREE)
    struct.pack_into("<Q", superblock, 0x80, 256)
    struct.pack_into("<H", superblock, 0xC4, 0)  # CRC32C checksum
    struct.pack_into("<Q", superblock, 0xC9, 1)  # devid
    struct.pack_into("<Q", superblock, 0xD1, image_size)

    # Btrfs' CRC32C checksum covers the 4 KiB superblock after its 32-byte
    # checksum/UUID prefix and is stored little endian in the first four bytes.
    superblock[:4] = struct.pack("<I", crc32c(superblock[0x20:]))

    # The superblock's system chunk array maps the test volume's logical
    # address range directly onto its single device.
    mapping = 0x32B
    superblock[mapping:mapping + 17] = key(0x100, 0xE4, 0)
    chunk = struct.pack("<QQQQ12xHH", image_size, 0, 65536, 0, 1, 1)
    superblock[mapping + 17:mapping + 17 + len(chunk)] = chunk
    stripe = struct.pack("<QQ", 1, 0) + fs_id
    stripe_start = mapping + 17 + len(chunk)
    superblock[stripe_start:stripe_start + len(stripe)] = stripe
    superblock[:4] = struct.pack("<I", crc32c(superblock[0x20:]))

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(image)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    parser.add_argument("--root", required=True)
    parser.add_argument("--uuid", default="4b1f3ed4-0dd0-4aac-9c8f-5a881de1724c")
    args = parser.parse_args()
    create_image(args.output, args.root, args.uuid)


if __name__ == "__main__":
    main()
