/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * Read-only ext2/3/4 filesystem support.
 *
 * The on-disk structures and the read-only block and extent mapping approach
 * follow the GRUB ext2 driver in GRUB 2.14, Copyright (C) 2003-2009 Free
 * Software Foundation, Inc. This standalone implementation does not include
 * GRUB runtime or command-interpreter code.
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details. You should have received a copy of the GNU General Public
 * License along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
#include "ml_extfs.h"

#ifndef ML_ENABLE_FS_EXT2
#define ML_ENABLE_FS_EXT2 0
#endif
#ifndef ML_ENABLE_FS_EXT4
#define ML_ENABLE_FS_EXT4 0
#endif

#define EXT_MAGIC 0xef53u
#define EXT_SUPER_OFFSET 1024u
#define EXT_SUPER_SIZE 1024u
#define EXT_INODE_MIN 128u
#define EXT_DIR_HEADER_SIZE 8u
#define EXT_ROOT_INODE 2u
#define EXT_FLAG_ENCRYPT 0x00000800u
#define EXT_FLAG_EXTENTS 0x00080000u

#define EXT_INCOMP_FILETYPE 0x00000002u
#define EXT_INCOMP_RECOVER 0x00000004u
#define EXT_INCOMP_JOURNAL_DEV 0x00000008u
#define EXT_INCOMP_META_BG 0x00000010u
#define EXT_INCOMP_EXTENTS 0x00000040u
#define EXT_INCOMP_64BIT 0x00000080u
#define EXT_INCOMP_MMP 0x00000100u
#define EXT_INCOMP_FLEX_BG 0x00000200u
#define EXT_INCOMP_CSUM_SEED 0x00002000u
#define EXT_INCOMP_LARGEDIR 0x00004000u
#define EXT_INCOMP_ENCRYPT 0x00010000u
#define EXT_INCOMP_CASEFOLD 0x00020000u
#define EXT_RO_BIGALLOC 0x00000200u
#define EXT_RO_VERITY 0x00008000u
#define EXT_RO_ORPHAN 0x00010000u

static uint16_t ext_le16(const uint8_t *p)
{
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static uint32_t ext_le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void ext_copy(uint8_t *dst, const uint8_t *src, size_t length)
{
    size_t i;
    for (i = 0; i < length; ++i) dst[i] = src[i];
}

static int ext_equal(const char *a, const char *b, size_t length)
{
    size_t i;
    for (i = 0; i < length; ++i) if (a[i] != b[i]) return 0;
    return 1;
}

static ml_extfs_result ext_fail(ml_extfs_result result, const char **message,
                                const char *text)
{
    if (message) *message = text;
    return result;
}

static int ext_block_offset(const ml_extfs *fs, uint64_t block,
                            uint64_t *offset)
{
    if (!fs || !offset || block >= fs->blocks_count ||
        block > UINT64_MAX / fs->block_size)
        return 0;
    *offset = block * fs->block_size;
    return *offset <= fs->device->byte_size &&
           fs->block_size <= fs->device->byte_size - *offset;
}

static ml_extfs_result ext_read_block(const ml_extfs *fs, uint64_t block,
                                      void *buffer, const char **message)
{
    uint64_t offset;
    if (!ext_block_offset(fs, block, &offset))
        return ext_fail(ML_EXTFS_BAD_FORMAT, message,
                        "filesystem block number is outside the volume");
    if (ml_block_read(fs->device, offset, buffer, fs->block_size) != ML_BLOCK_OK)
        return ext_fail(ML_EXTFS_IO, message, "cannot read filesystem block");
    return ML_EXTFS_OK;
}

static ml_extfs_result ext_read_inode(const ml_extfs *fs, uint64_t inode_number,
                                      uint8_t inode[ML_EXTFS_INODE_BYTES],
                                      const char **message)
{
    uint64_t group, local, desc_base, desc_offset, inode_table, inode_offset;
    uint64_t filesystem_bytes;
    uint8_t descriptor[64];
    uint64_t groups;
    uint64_t gdt_first_block;
    size_t descriptor_read_size;
    ml_extfs_result result;

    if (inode_number == 0 || inode_number > fs->inodes_count)
        return ext_fail(ML_EXTFS_BAD_FORMAT, message,
                        "inode number is outside the filesystem");
    group = (inode_number - 1) / fs->inodes_per_group;
    local = (inode_number - 1) % fs->inodes_per_group;
    groups = (fs->blocks_count - fs->first_data_block +
              fs->blocks_per_group - 1) / fs->blocks_per_group;
    if (group >= groups || group > UINT64_MAX / fs->descriptor_size)
        return ext_fail(ML_EXTFS_BAD_FORMAT, message,
                        "inode group descriptor is outside the filesystem");
    gdt_first_block = (uint64_t)fs->first_data_block + 1;
    if (gdt_first_block >= fs->blocks_count ||
        gdt_first_block > UINT64_MAX / fs->block_size)
        return ext_fail(ML_EXTFS_BAD_FORMAT, message,
                        "group descriptor table is outside the filesystem");
    desc_base = gdt_first_block * fs->block_size;
    desc_offset = group * fs->descriptor_size;
    filesystem_bytes = fs->blocks_count * fs->block_size;
    if (desc_offset > UINT64_MAX - desc_base ||
        desc_base + desc_offset > filesystem_bytes ||
        fs->descriptor_size > filesystem_bytes - (desc_base + desc_offset))
        return ext_fail(ML_EXTFS_BAD_FORMAT, message,
                        "group descriptor table is truncated");
    descriptor_read_size = fs->descriptor_size < sizeof(descriptor)
        ? fs->descriptor_size : sizeof(descriptor);
    result = ml_block_read(fs->device, desc_base + desc_offset,
                           descriptor, descriptor_read_size) == ML_BLOCK_OK
        ? ML_EXTFS_OK : ML_EXTFS_IO;
    if (result != ML_EXTFS_OK)
        return ext_fail(result, message, "cannot read inode group descriptor");
    inode_table = ext_le32(descriptor + 8);
    if (fs->descriptor_size >= 64)
        inode_table |= (uint64_t)ext_le32(descriptor + 40) << 32;
    if (inode_table >= fs->blocks_count ||
        local > UINT64_MAX / fs->inode_size)
        return ext_fail(ML_EXTFS_BAD_FORMAT, message,
                        "inode table is outside the filesystem");
    inode_offset = inode_table * fs->block_size;
    if (local * fs->inode_size > UINT64_MAX - inode_offset)
        return ext_fail(ML_EXTFS_BAD_FORMAT, message, "inode offset overflow");
    inode_offset += local * fs->inode_size;
    if (inode_offset > filesystem_bytes ||
        EXT_INODE_MIN > filesystem_bytes - inode_offset)
        return ext_fail(ML_EXTFS_BAD_FORMAT, message, "inode table is truncated");
    if (ml_block_read(fs->device, inode_offset, inode,
                      ML_EXTFS_INODE_BYTES) != ML_BLOCK_OK)
        return ext_fail(ML_EXTFS_IO, message, "cannot read filesystem inode");
    return ML_EXTFS_OK;
}

ml_extfs_result ml_extfs_mount(ml_extfs *fs, const ml_block_device *device,
                               void *scratch, size_t scratch_size,
                               const char **message)
{
    uint8_t super[EXT_SUPER_SIZE];
    uint32_t log_block, revision, inode_size, incompat, compat, ro_compat;
    uint64_t blocks_count, bytes_needed;
    /* orphan_file is safe to read when the separate ORPHAN_PRESENT
     * read-only feature bit is clear; a pending orphan list is rejected. */
    const uint32_t known_compat = 0x00001fffu;
    const uint32_t known_ro = 0x00003fffu | EXT_RO_VERITY | EXT_RO_ORPHAN;
    uint32_t known_incompat = EXT_INCOMP_FILETYPE | EXT_INCOMP_MMP |
                              EXT_INCOMP_CSUM_SEED | EXT_INCOMP_LARGEDIR;

    if (message) *message = NULL;
    if (!fs || !device || !device->read_at)
        return ext_fail(ML_EXTFS_INVALID, message, "invalid filesystem arguments");
#if !ML_ENABLE_FS_EXT2 && !ML_ENABLE_FS_EXT4
    return ext_fail(ML_EXTFS_UNSUPPORTED, message,
                    "ext filesystem support is disabled in this build");
#endif
    if (ml_block_read(device, EXT_SUPER_OFFSET, super, sizeof(super)) != ML_BLOCK_OK)
        return ext_fail(ML_EXTFS_IO, message, "cannot read ext superblock");
    if (ext_le16(super + 56) != EXT_MAGIC)
        return ext_fail(ML_EXTFS_BAD_FORMAT, message, "volume is not ext2/3/4");
    log_block = ext_le32(super + 24);
    if (log_block > 6)
        return ext_fail(ML_EXTFS_UNSUPPORTED, message,
                        "ext block sizes above 64 KiB are unsupported");
    revision = ext_le32(super + 76);
    if (revision > 1)
        return ext_fail(ML_EXTFS_UNSUPPORTED, message,
                        "unsupported ext filesystem revision");
    inode_size = revision == 0 ? EXT_INODE_MIN : ext_le16(super + 88);
    if (inode_size < EXT_INODE_MIN || inode_size > (1024u * 1024u) ||
        (inode_size & 3u) != 0)
        return ext_fail(ML_EXTFS_BAD_FORMAT, message, "invalid ext inode size");
    incompat = ext_le32(super + 96);
    compat = ext_le32(super + 92);
    ro_compat = ext_le32(super + 100);

#if ML_ENABLE_FS_EXT4
    known_incompat |= EXT_INCOMP_EXTENTS | EXT_INCOMP_64BIT |
                      EXT_INCOMP_FLEX_BG;
#endif
    if (incompat & EXT_INCOMP_RECOVER)
        return ext_fail(ML_EXTFS_UNSUPPORTED, message,
                        "ext journal recovery is required; MiniLoader is read-only");
    if (incompat & (EXT_INCOMP_JOURNAL_DEV | EXT_INCOMP_META_BG |
                    EXT_INCOMP_ENCRYPT | EXT_INCOMP_CASEFOLD))
        return ext_fail(ML_EXTFS_UNSUPPORTED, message,
                        "ext filesystem uses an unsupported incompatible feature");
    if (incompat & ~known_incompat)
        return ext_fail(ML_EXTFS_UNSUPPORTED, message,
                        (incompat & EXT_INCOMP_EXTENTS) && !ML_ENABLE_FS_EXT4
                            ? "ext4 extents are disabled in this build"
                            : "ext filesystem has an unsupported incompatible feature");
    if (compat & ~known_compat)
        return ext_fail(ML_EXTFS_UNSUPPORTED, message,
                        "ext filesystem has an unsupported compatible feature");
    if (ro_compat & ~known_ro)
        return ext_fail(ML_EXTFS_UNSUPPORTED, message,
                        "ext filesystem has an unsupported read-only feature");
    if (ro_compat & EXT_RO_BIGALLOC)
        return ext_fail(ML_EXTFS_UNSUPPORTED, message,
                        "ext bigalloc filesystems are unsupported");
    if (ro_compat & (EXT_RO_VERITY | EXT_RO_ORPHAN))
        return ext_fail(ML_EXTFS_UNSUPPORTED, message,
                        "ext verity/orphan metadata is unsupported");
    if ((incompat & (EXT_INCOMP_EXTENTS | EXT_INCOMP_64BIT |
                     EXT_INCOMP_FLEX_BG)) && !ML_ENABLE_FS_EXT4)
        return ext_fail(ML_EXTFS_UNSUPPORTED, message,
                        "ext4 features are disabled in this build");

    blocks_count = ext_le32(super + 4);
    if (incompat & EXT_INCOMP_64BIT)
        blocks_count |= (uint64_t)ext_le32(super + 336) << 32;
    if (blocks_count == 0 || blocks_count > UINT64_MAX / (1024u << log_block))
        return ext_fail(ML_EXTFS_BAD_FORMAT, message, "invalid ext block count");
    bytes_needed = blocks_count * (1024u << log_block);
    if (bytes_needed > device->byte_size)
        return ext_fail(ML_EXTFS_BAD_FORMAT, message,
                        "ext filesystem extends beyond the volume");

    fs->device = device;
    fs->scratch = (uint8_t *)scratch;
    fs->scratch_size = scratch_size;
    fs->block_size = 1024u << log_block;
    fs->inode_size = inode_size;
    fs->first_data_block = ext_le32(super + 20);
    fs->blocks_count = blocks_count;
    fs->inodes_count = ext_le32(super);
    fs->blocks_per_group = ext_le32(super + 32);
    fs->inodes_per_group = ext_le32(super + 40);
    fs->compat_features = compat;
    fs->incompat_features = incompat;
    fs->ro_compat_features = ro_compat;
    fs->descriptor_size = (incompat & EXT_INCOMP_64BIT)
        ? ext_le16(super + 254) : 32u;
    if (fs->descriptor_size == 0 && !(incompat & EXT_INCOMP_64BIT))
        fs->descriptor_size = 32;
    if (fs->blocks_per_group == 0 || fs->inodes_per_group == 0 ||
        fs->inodes_count < EXT_ROOT_INODE ||
        fs->first_data_block >= fs->blocks_count ||
        fs->descriptor_size < 32 || fs->descriptor_size > fs->block_size ||
        (fs->descriptor_size & 7u) != 0 ||
        ((incompat & EXT_INCOMP_64BIT) &&
         (fs->descriptor_size < 64 ||
          (fs->descriptor_size & (fs->descriptor_size - 1)) != 0)) ||
        inode_size > fs->block_size)
        return ext_fail(ML_EXTFS_BAD_FORMAT, message,
                        "invalid ext geometry or group descriptor size");
    ext_copy(fs->uuid, super + 104, sizeof(fs->uuid));
    if (scratch_size < fs->block_size || !scratch)
        return ext_fail(ML_EXTFS_RANGE, message,
                        "filesystem scratch buffer is smaller than its block size");
    {
        uint8_t root_inode[ML_EXTFS_INODE_BYTES];
        ml_extfs_result result = ext_read_inode(fs, EXT_ROOT_INODE,
                                                 root_inode, message);
        if (result != ML_EXTFS_OK) return result;
        if ((ext_le16(root_inode) & 0xf000u) != 0x4000u)
            return ext_fail(ML_EXTFS_BAD_FORMAT, message,
                            "ext root inode is not a directory");
    }
    return ML_EXTFS_OK;
}

/* Map a logical file block through ext4 extents. 1 denotes a sparse or
 * unwritten block, 0 a data block, and -1 malformed metadata or I/O failure. */
static int ext_map_extent(const ml_extfs *fs, const uint8_t *inode,
                          uint64_t logical, uint64_t *physical,
                          const char **message)
{
    const uint8_t *node = inode + 40;
    uint16_t depth, entries;
    unsigned level = 0;
    if (ext_le16(node) != 0xf30au) {
        (void)ext_fail(ML_EXTFS_BAD_FORMAT, message, "invalid ext4 extent header");
        return -1;
    }
    depth = ext_le16(node + 6);
    if (depth > 5) {
        (void)ext_fail(ML_EXTFS_UNSUPPORTED, message,
                       "ext4 extent tree is deeper than supported");
        return -1;
    }
    while (1) {
        uint16_t max_entries = ext_le16(node + 4);
        size_t capacity = node == inode + 40
            ? (60u - 12u) / 12u : (fs->block_size - 12u) / 12u;
        size_t i;
        entries = ext_le16(node + 2);
        if (entries > max_entries || max_entries > capacity) {
            (void)ext_fail(ML_EXTFS_BAD_FORMAT, message,
                           "invalid ext4 extent entry count");
            return -1;
        }
        if (depth == 0) {
            const uint8_t *extents = node + 12;
            for (i = 0; i < entries; ++i) {
                const uint8_t *extent = extents + i * 12u;
                uint64_t first = ext_le32(extent);
                uint16_t encoded_len = ext_le16(extent + 4);
                uint64_t count;
                uint64_t start = ext_le32(extent + 8) |
                                 ((uint64_t)ext_le16(extent + 6) << 32);
                int unwritten = encoded_len > 0x8000u;
                if (unwritten) count = encoded_len - 0x8000u;
                else count = encoded_len;
                if (count == 0) {
                    (void)ext_fail(ML_EXTFS_BAD_FORMAT, message,
                                   "zero-length ext4 extent");
                    return -1;
                }
                if (first > UINT32_MAX || count > UINT64_MAX - first ||
                    start >= fs->blocks_count || count > fs->blocks_count - start) {
                    (void)ext_fail(ML_EXTFS_BAD_FORMAT, message,
                                   "ext4 extent is outside the filesystem");
                    return -1;
                }
                if (logical >= first && logical - first < count) {
                    if (unwritten) return 1;
                    *physical = start + (logical - first);
                    return 0;
                }
                if (logical < first) return 1;
            }
            return 1;
        }
        if (level++ > 5) {
            (void)ext_fail(ML_EXTFS_BAD_FORMAT, message,
                           "invalid ext4 extent depth");
            return -1;
        }
        {
            const uint8_t *indexes = node + 12;
            int selected = -1;
            uint64_t next_block;
            for (i = 0; i < entries; ++i) {
                uint64_t key = ext_le32(indexes + i * 12u);
                if (logical < key) break;
                selected = (int)i;
            }
            if (selected < 0) return 1;
            indexes += (size_t)selected * 12u;
            next_block = ext_le32(indexes + 4) |
                         ((uint64_t)ext_le16(indexes + 8) << 32);
            if (ext_read_block(fs, next_block, fs->scratch, message) != ML_EXTFS_OK)
                return -1;
            node = fs->scratch;
            if (ext_le16(node + 6) + 1 != depth) {
                (void)ext_fail(ML_EXTFS_BAD_FORMAT, message,
                               "inconsistent ext4 extent tree depth");
                return -1;
            }
            depth--;
        }
    }
}

static int ext_map_indirect(const ml_extfs *fs, const uint8_t *inode,
                            uint64_t logical, uint64_t *physical,
                            const char **message)
{
    uint64_t pointers_per_block = fs->block_size / 4u;
    uint64_t span = pointers_per_block;
    unsigned level;
    uint64_t root;
    if (logical < 12) {
        root = ext_le32(inode + 40 + (size_t)logical * 4u);
        if (!root) return 1;
        if (root >= fs->blocks_count) goto invalid;
        *physical = root;
        return 0;
    }
    logical -= 12;
    for (level = 1; level <= 3; ++level) {
        if (logical < span) break;
        logical -= span;
        if (level == 3) return 1;
        if (span > UINT64_MAX / pointers_per_block) return 1;
        span *= pointers_per_block;
    }
    root = ext_le32(inode + 40 + (11u + level) * 4u);
    if (!root) return 1;
    while (level > 0) {
        uint64_t divisor = 1, index;
        unsigned n;
        for (n = 1; n < level; ++n) divisor *= pointers_per_block;
        index = logical / divisor;
        logical %= divisor;
        if (index >= pointers_per_block || root >= fs->blocks_count)
            goto invalid;
        if (ext_read_block(fs, root, fs->scratch, message) != ML_EXTFS_OK)
            return -1;
        root = ext_le32(fs->scratch + index * 4u);
        if (!root) return 1;
        level--;
    }
    if (root >= fs->blocks_count) goto invalid;
    *physical = root;
    return 0;

invalid:
    (void)ext_fail(ML_EXTFS_BAD_FORMAT, message,
                   "ext indirect block pointer is outside the filesystem");
    return -1;
}

static ml_extfs_result ext_read_inode_data(const ml_extfs *fs,
                                           const uint8_t *inode,
                                           uint64_t inode_size,
                                           uint64_t offset, void *buffer,
                                           size_t length, size_t *read_size,
                                           const char **message)
{
    uint8_t *out = (uint8_t *)buffer;
    size_t done = 0;
    if (read_size) *read_size = 0;
    if (offset > inode_size)
        return ext_fail(ML_EXTFS_RANGE, message, "read starts past end of file");
    if ((uint64_t)length > inode_size - offset)
        length = (size_t)(inode_size - offset);
    while (done < length) {
        uint64_t at = offset + done;
        uint64_t logical = at / fs->block_size;
        size_t in_block = (size_t)(at % fs->block_size);
        size_t amount = fs->block_size - in_block;
        uint64_t physical = 0, disk_offset;
        int mapping;
        if (amount > length - done) amount = length - done;
        if (ext_le32(inode + 32) & EXT_FLAG_EXTENTS) {
            mapping = ext_map_extent(fs, inode, logical, &physical, message);
        } else {
            mapping = ext_map_indirect(fs, inode, logical, &physical, message);
        }
        if (mapping < 0) return ML_EXTFS_BAD_FORMAT;
        if (mapping == 1) {
            size_t i;
            for (i = 0; i < amount; ++i) out[done + i] = 0;
        } else {
            if (physical > UINT64_MAX / fs->block_size)
                return ext_fail(ML_EXTFS_BAD_FORMAT, message,
                                "ext file block offset overflow");
            disk_offset = physical * fs->block_size;
            if (disk_offset > UINT64_MAX - in_block ||
                ml_block_read(fs->device, disk_offset + in_block,
                              out + done, amount) != ML_BLOCK_OK)
                return ext_fail(ML_EXTFS_IO, message,
                                "cannot read ext file data");
        }
        done += amount;
    }
    if (read_size) *read_size = done;
    return ML_EXTFS_OK;
}

static uint32_t ext_dir_rec_len(const ml_extfs *fs, uint16_t encoded)
{
    if (fs->block_size == 65536u && (encoded == 0 || encoded == 0xffffu))
        return 65536u;
    return encoded;
}

static ml_extfs_result ext_dir_lookup(const ml_extfs *fs, uint64_t dir_ino,
                                      const uint8_t *dir_inode,
                                      const char *name, size_t name_length,
                                      uint64_t *found_inode,
                                      const char **message)
{
    uint64_t size;
    uint8_t header[EXT_DIR_HEADER_SIZE];
    uint8_t name_buffer[256];
    uint64_t offset = 0;
    uint16_t mode = ext_le16(dir_inode);
    (void)dir_ino;
    if ((mode & 0xf000u) != 0x4000u)
        return ext_fail(ML_EXTFS_NOT_FILE, message,
                        "path component is not a directory");
    size = ext_le32(dir_inode + 4);
    size |= (uint64_t)ext_le32(dir_inode + 108) << 32;
    while (offset < size) {
        uint32_t inode_number, rec_len;
        uint16_t rec_raw;
        uint16_t entry_name_len;
        size_t got = 0;
        size_t within_block = (size_t)(offset % fs->block_size);
        ml_extfs_result result;
        result = ext_read_inode_data(fs, dir_inode, size, offset, header,
                                     sizeof(header), &got, message);
        if (result != ML_EXTFS_OK) return result;
        if (got != sizeof(header))
            return ext_fail(ML_EXTFS_BAD_FORMAT, message,
                            "truncated ext directory entry");
        inode_number = ext_le32(header);
        rec_raw = ext_le16(header + 4);
        rec_len = ext_dir_rec_len(fs, rec_raw);
        entry_name_len = (fs->incompat_features & EXT_INCOMP_FILETYPE)
            ? header[6] : ext_le16(header + 6);
        if (rec_len < EXT_DIR_HEADER_SIZE || (rec_len & 3u) != 0 ||
            rec_len > size - offset ||
            rec_len > fs->block_size - within_block ||
            entry_name_len > rec_len - EXT_DIR_HEADER_SIZE ||
            entry_name_len > 255u)
            return ext_fail(ML_EXTFS_BAD_FORMAT, message,
                            "invalid ext directory entry length");
        if (inode_number != 0 && entry_name_len == name_length &&
            name_length != 0) {
            result = ext_read_inode_data(fs, dir_inode, size,
                offset + EXT_DIR_HEADER_SIZE, name_buffer, entry_name_len,
                &got, message);
            if (result != ML_EXTFS_OK) return result;
            if (got != entry_name_len)
                return ext_fail(ML_EXTFS_BAD_FORMAT, message,
                                "truncated ext directory name");
            if (ext_equal((const char *)name_buffer, name, name_length)) {
                if (inode_number > fs->inodes_count)
                    return ext_fail(ML_EXTFS_BAD_FORMAT, message,
                                    "directory inode number is invalid");
                *found_inode = inode_number;
                return ML_EXTFS_OK;
            }
        }
        offset += rec_len;
    }
    return ext_fail(ML_EXTFS_NOT_FOUND, message, "path was not found on ext volume");
}

ml_extfs_result ml_extfs_open(ml_extfs_file *file, const ml_extfs *fs,
                              const char *path, const char **message)
{
    uint64_t current = EXT_ROOT_INODE;
    uint8_t current_inode[ML_EXTFS_INODE_BYTES];
    const char *cursor;
    ml_extfs_result result;
    if (message) *message = NULL;
    if (!file || !fs || !path)
        return ext_fail(ML_EXTFS_INVALID, message, "invalid ext path arguments");
    result = ext_read_inode(fs, current, current_inode, message);
    if (result != ML_EXTFS_OK) return result;
    cursor = path;
    while (*cursor == '/') cursor++;
    while (*cursor) {
        const char *component = cursor;
        size_t component_length;
        uint64_t next;
        while (*cursor && *cursor != '/') cursor++;
        component_length = (size_t)(cursor - component);
        while (*cursor == '/') cursor++;
        if (component_length == 0 ||
            (component_length == 1 && component[0] == '.'))
            continue;
        if (component_length > 255)
            return ext_fail(ML_EXTFS_INVALID, message,
                            "ext path component exceeds 255 bytes");
        if (component_length == 2 && component[0] == '.' && component[1] == '.') {
            if (current == EXT_ROOT_INODE) continue;
        }
        result = ext_dir_lookup(fs, current, current_inode, component,
                                component_length, &next, message);
        if (result != ML_EXTFS_OK) return result;
        current = next;
        result = ext_read_inode(fs, current, current_inode, message);
        if (result != ML_EXTFS_OK) return result;
        if (ext_le16(current_inode) & 0xf000u) {
            uint16_t type = ext_le16(current_inode) & 0xf000u;
            if (type == 0xa000u)
                return ext_fail(ML_EXTFS_UNSUPPORTED, message,
                                "symbolic links are unsupported by MiniLoader ext reader");
            if (type != 0x4000u && *cursor)
                return ext_fail(ML_EXTFS_NOT_FILE, message,
                                "intermediate path component is not a directory");
        }
    }
    {
        uint16_t type = ext_le16(current_inode) & 0xf000u;
        uint64_t size = ext_le32(current_inode + 4);
        if (type == 0xa000u)
            return ext_fail(ML_EXTFS_UNSUPPORTED, message,
                            "symbolic links are unsupported by MiniLoader ext reader");
        if (type != 0x8000u)
            return ext_fail(ML_EXTFS_NOT_FILE, message,
                            "ext path does not identify a regular file");
        size |= (uint64_t)ext_le32(current_inode + 108) << 32;
        if (ext_le32(current_inode + 32) & EXT_FLAG_ENCRYPT)
            return ext_fail(ML_EXTFS_UNSUPPORTED, message,
                            "encrypted ext files are unsupported");
        if ((ext_le32(current_inode + 32) & EXT_FLAG_EXTENTS) &&
            !(fs->incompat_features & EXT_INCOMP_EXTENTS))
            return ext_fail(ML_EXTFS_BAD_FORMAT, message,
                            "ext inode uses extents without the filesystem feature");
        file->filesystem = fs;
        file->inode_number = current;
        file->size = size;
        ext_copy(file->inode, current_inode, sizeof(file->inode));
    }
    return ML_EXTFS_OK;
}

ml_extfs_result ml_extfs_read(const ml_extfs_file *file, uint64_t offset,
                              void *buffer, size_t length, size_t *bytes_read,
                              const char **message)
{
    if (message) *message = NULL;
    if (bytes_read) *bytes_read = 0;
    if (!file || !file->filesystem || (!buffer && length != 0))
        return ext_fail(ML_EXTFS_INVALID, message, "invalid ext file read arguments");
    if (offset > file->size)
        return ext_fail(ML_EXTFS_RANGE, message, "read starts past end of file");
    return ext_read_inode_data(file->filesystem, file->inode, file->size,
                               offset, buffer, length, bytes_read, message);
}

void ml_extfs_format_uuid(const ml_extfs *fs, char output[37])
{
    static const char hex[] = "0123456789abcdef";
    size_t i, position = 0;
    if (!output) return;
    if (!fs) { output[0] = '\0'; return; }
    for (i = 0; i < ML_EXTFS_UUID_BYTES; ++i) {
        if (i == 4 || i == 6 || i == 8 || i == 10) output[position++] = '-';
        output[position++] = hex[fs->uuid[i] >> 4];
        output[position++] = hex[fs->uuid[i] & 0xf];
    }
    output[position] = '\0';
}
