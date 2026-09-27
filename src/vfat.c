/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Independent, read-only FAT12/16/32 reader with VFAT long-name lookup. */
#include "ml_vfat.h"

#ifndef ML_ENABLE_FS_VFAT
#define ML_ENABLE_FS_VFAT 0
#endif

#define FAT_ENTRY_BYTES 32u
#define FAT_MAX_COMPONENT 255u
#define FAT_LFN_CHARS 260u

typedef struct {
    uint32_t first_cluster;
    uint64_t fixed_offset;
    uint64_t fixed_size;
    uint8_t fixed_root;
} fat_directory;

typedef struct {
    uint32_t first_cluster;
    uint32_t size;
    uint8_t attributes;
} fat_dirent;

static uint16_t fat_le16(const uint8_t *p)
{
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static uint32_t fat_le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static ml_vfat_result fat_fail(ml_vfat_result result, const char **message,
                               const char *text)
{
    if (message) *message = text;
    return result;
}

static int fat_power_of_two(uint32_t value)
{
    return value && !(value & (value - 1u));
}

static int fat_cluster_valid(const ml_vfat *fs, uint32_t cluster)
{
    return cluster >= 2 && (uint64_t)cluster < (uint64_t)fs->cluster_count + 2;
}

static int fat_read_entry(const ml_vfat *fs, uint32_t cluster,
                          uint32_t *value)
{
    uint8_t bytes[4] = {0};
    uint64_t index, offset;
    size_t read_size;
    if (!fat_cluster_valid(fs, cluster) || !value) return 0;
    if (fs->fat_bits == 12) {
        index = (uint64_t)cluster + cluster / 2u;
        read_size = 2;
    } else if (fs->fat_bits == 16) {
        index = (uint64_t)cluster * 2u;
        read_size = 2;
    } else {
        index = (uint64_t)cluster * 4u;
        read_size = 4;
    }
    if (index > fs->fat_size_bytes || read_size > fs->fat_size_bytes - index ||
        fs->fat_offset > UINT64_MAX - index)
        return 0;
    offset = fs->fat_offset + index;
    if (ml_block_read(fs->device, offset, bytes, read_size) != ML_BLOCK_OK)
        return 0;
    if (fs->fat_bits == 12) {
        uint16_t pair = fat_le16(bytes);
        *value = (cluster & 1u) ? pair >> 4 : pair & 0x0fffu;
    } else if (fs->fat_bits == 16) {
        *value = fat_le16(bytes);
    } else {
        *value = fat_le32(bytes) & 0x0fffffffu;
    }
    return 1;
}

/* Returns 1 for a next cluster, 0 at end of chain, and -1 on corruption/I/O. */
static int fat_next_cluster(const ml_vfat *fs, uint32_t cluster,
                            uint32_t *next)
{
    uint32_t value, end;
    if (!fat_read_entry(fs, cluster, &value)) return -1;
    end = fs->fat_bits == 12 ? 0x0ff8u :
          fs->fat_bits == 16 ? 0xfff8u : 0x0ffffff8u;
    if (value >= end) return 0;
    if (!fat_cluster_valid(fs, value)) return -1;
    *next = value;
    return 1;
}

static int fat_cluster_offset(const ml_vfat *fs, uint32_t cluster,
                              uint64_t *offset)
{
    uint64_t index;
    if (!fat_cluster_valid(fs, cluster) || !offset) return 0;
    index = (uint64_t)(cluster - 2u) * fs->cluster_size;
    if (fs->data_offset > UINT64_MAX - index) return 0;
    *offset = fs->data_offset + index;
    return *offset <= fs->device->byte_size &&
           fs->cluster_size <= fs->device->byte_size - *offset;
}

static uint8_t fat_short_checksum(const uint8_t name[11])
{
    uint8_t checksum = 0;
    unsigned i;
    for (i = 0; i < 11; ++i)
        checksum = (uint8_t)(((checksum & 1u) ? 0x80u : 0u) +
                             (checksum >> 1) + name[i]);
    return checksum;
}

static int fat_ascii_equal(const char *a, const char *b)
{
    size_t i = 0;
    while (a[i] && b[i]) {
        char x = a[i], y = b[i];
        if (x >= 'A' && x <= 'Z') x = (char)(x + ('a' - 'A'));
        if (y >= 'A' && y <= 'Z') y = (char)(y + ('a' - 'A'));
        if (x != y) return 0;
        ++i;
    }
    return a[i] == b[i];
}

static void fat_lfn_piece(char name[FAT_LFN_CHARS + 1],
                          const uint8_t entry[FAT_ENTRY_BYTES], unsigned slot)
{
    static const uint8_t offsets[13] = {
        1,3,5,7,9,14,16,18,20,22,24,28,30
    };
    unsigned i;
    size_t base = (size_t)(slot - 1u) * 13u;
    for (i = 0; i < 13; ++i) {
        uint16_t ch = fat_le16(entry + offsets[i]);
        if (ch == 0 || ch == 0xffffu) name[base + i] = '\0';
        else name[base + i] = ch <= 0x7fu ? (char)ch : '?';
    }
    name[FAT_LFN_CHARS] = '\0';
}

static void fat_short_name(const uint8_t entry[FAT_ENTRY_BYTES], char name[13])
{
    size_t at = 0, i, base_end = 8, ext_end = 3;
    while (base_end && entry[base_end - 1] == ' ') --base_end;
    while (ext_end && entry[8 + ext_end - 1] == ' ') --ext_end;
    for (i = 0; i < base_end; ++i) {
        uint8_t ch = entry[i] == 0x05u && i == 0 ? 0xe5u : entry[i];
        if (entry[12] & 0x08u && ch >= 'A' && ch <= 'Z') ch += 'a' - 'A';
        name[at++] = ch < 0x80u ? (char)ch : '?';
    }
    if (ext_end) {
        name[at++] = '.';
        for (i = 0; i < ext_end; ++i) {
            uint8_t ch = entry[8 + i];
            if (entry[12] & 0x10u && ch >= 'A' && ch <= 'Z') ch += 'a' - 'A';
            name[at++] = ch < 0x80u ? (char)ch : '?';
        }
    }
    name[at] = '\0';
}

static ml_vfat_result fat_scan_directory(const ml_vfat *fs,
                                         const fat_directory *directory,
                                         const char *component,
                                         fat_dirent *found,
                                         const char **message)
{
    uint8_t entry[FAT_ENTRY_BYTES];
    char long_name[FAT_LFN_CHARS + 1], short_name[13];
    uint8_t lfn_checksum = 0, lfn_next = 0;
    int lfn_valid = 0;
    uint32_t cluster = directory->first_cluster;
    uint32_t chain_steps = 0;

    while (directory->fixed_root || chain_steps < fs->cluster_count) {
        uint64_t base, area_size;
        uint32_t cluster_entries = 0, next;
        int chain_result;
        if (directory->fixed_root) {
            base = directory->fixed_offset;
            area_size = directory->fixed_size;
        } else {
            if (!fat_cluster_offset(fs, cluster, &base))
                return fat_fail(ML_VFAT_BAD_FORMAT, message,
                                "VFAT directory cluster is outside the volume");
            area_size = fs->cluster_size;
        }
        while (cluster_entries * FAT_ENTRY_BYTES < area_size) {
            uint8_t attr;
            if (ml_block_read(fs->device,
                    base + (uint64_t)cluster_entries * FAT_ENTRY_BYTES,
                    entry, sizeof(entry)) != ML_BLOCK_OK)
                return fat_fail(ML_VFAT_IO, message,
                                "cannot read VFAT directory entry");
            cluster_entries++;
            if (entry[0] == 0) return ML_VFAT_NOT_FOUND;
            if (entry[0] == 0xe5u) {
                lfn_valid = 0;
                lfn_next = 0;
                continue;
            }
            attr = entry[11];
            if (attr == 0x0fu) {
                uint8_t ordinal = entry[0] & 0x1fu;
                if (entry[0] & 0x40u) {
                    unsigned i;
                    for (i = 0; i <= FAT_LFN_CHARS; ++i) long_name[i] = '\0';
                    lfn_valid = ordinal != 0 && ordinal <= 20;
                    lfn_next = ordinal;
                    lfn_checksum = entry[13];
                }
                if (!lfn_valid || ordinal == 0 || ordinal != lfn_next ||
                    entry[13] != lfn_checksum || (entry[0] & 0x80u)) {
                    lfn_valid = 0;
                    lfn_next = 0;
                    continue;
                }
                fat_lfn_piece(long_name, entry, ordinal);
                lfn_next--;
                continue;
            }
            fat_short_name(entry, short_name);
            if (lfn_valid && lfn_next == 0 &&
                fat_short_checksum(entry) == lfn_checksum)
                short_name[0] = '\0';
            {
                const char *entry_name = short_name[0] ? short_name : long_name;
                if (!(attr & 0x08u) && fat_ascii_equal(entry_name, component)) {
                    found->attributes = attr;
                    found->first_cluster = fat_le16(entry + 26);
                    if (fs->fat_bits == 32)
                        found->first_cluster |=
                            (fat_le16(entry + 20) & 0x0fffu) << 16;
                    found->size = fat_le32(entry + 28);
                    return ML_VFAT_OK;
                }
            }
            lfn_valid = 0;
            lfn_next = 0;
            if (directory->fixed_root &&
                (uint64_t)cluster_entries * FAT_ENTRY_BYTES >= directory->fixed_size)
                return ML_VFAT_NOT_FOUND;
        }
        if (directory->fixed_root) return ML_VFAT_NOT_FOUND;
        chain_result = fat_next_cluster(fs, cluster, &next);
        if (chain_result <= 0)
            return chain_result == 0 ? ML_VFAT_NOT_FOUND :
                fat_fail(ML_VFAT_BAD_FORMAT, message,
                         "VFAT directory cluster chain is invalid");
        cluster = next;
        chain_steps++;
    }
    if (!directory->fixed_root && chain_steps >= fs->cluster_count)
        return fat_fail(ML_VFAT_BAD_FORMAT, message,
                        "VFAT directory cluster chain is cyclic");
    return ML_VFAT_NOT_FOUND;
}

ml_vfat_result ml_vfat_mount(ml_vfat *fs, const ml_block_device *device,
                             const char **message)
{
    uint8_t boot[512];
    uint32_t bytes_per_sector, sectors_per_cluster, reserved, fats;
    uint32_t total_sectors, fat_sectors, root_entries, root_sectors;
    uint64_t fat_area, data_sector, data_sectors, cluster_count;
    uint64_t fat_bytes, fat_entries_needed, volume_bytes;
    uint32_t root_cluster = 0;
    uint8_t bits;
    if (message) *message = NULL;
    if (!fs || !device || !device->read_at)
        return fat_fail(ML_VFAT_INVALID, message, "invalid VFAT mount arguments");
    if (ml_block_read(device, 0, boot, sizeof(boot)) != ML_BLOCK_OK)
        return fat_fail(ML_VFAT_IO, message, "cannot read VFAT boot sector");
    if (boot[510] != 0x55u || boot[511] != 0xaau)
        return ML_VFAT_NOT_VFAT;
    bytes_per_sector = fat_le16(boot + 11);
    sectors_per_cluster = boot[13];
    reserved = fat_le16(boot + 14);
    fats = boot[16];
    root_entries = fat_le16(boot + 17);
    total_sectors = fat_le16(boot + 19);
    if (!total_sectors) total_sectors = fat_le32(boot + 32);
    fat_sectors = fat_le16(boot + 22);
    if (!fat_sectors) fat_sectors = fat_le32(boot + 36);
    if (fat_le16(boot + 22) == 0) root_cluster = fat_le32(boot + 44) & 0x0fffffffu;
    if (!fat_power_of_two(bytes_per_sector) || bytes_per_sector < 512 ||
        bytes_per_sector > 4096 || !fat_power_of_two(sectors_per_cluster) ||
        sectors_per_cluster > 128 || reserved == 0 || fats == 0 || fats > 4 ||
        total_sectors == 0 || fat_sectors == 0)
        return fat_fail(ML_VFAT_BAD_FORMAT, message,
                        "invalid VFAT BIOS parameter block");
    root_sectors = (root_entries * FAT_ENTRY_BYTES + bytes_per_sector - 1) /
                   bytes_per_sector;
    fat_area = (uint64_t)reserved + (uint64_t)fats * fat_sectors;
    if (fat_area > total_sectors || root_sectors > total_sectors - fat_area)
        return fat_fail(ML_VFAT_BAD_FORMAT, message,
                        "VFAT metadata exceeds the declared volume size");
    data_sector = fat_area + root_sectors;
    data_sectors = total_sectors - data_sector;
    cluster_count = data_sectors / sectors_per_cluster;
    if (cluster_count == 0 || cluster_count > 0x0ffffff5u)
        return fat_fail(ML_VFAT_BAD_FORMAT, message,
                        "invalid VFAT data cluster count");
    bits = cluster_count < 4085 ? 12 : cluster_count < 65525 ? 16 : 32;
    if ((bits == 32 && (root_entries != 0 || fat_le16(boot + 22) != 0)) ||
        (bits != 32 && (root_entries == 0 || fat_le16(boot + 22) == 0)))
        return fat_fail(ML_VFAT_BAD_FORMAT, message,
                        "VFAT table size does not match the FAT type");
    if (bits == 32 && fat_le16(boot + 42) != 0)
        return fat_fail(ML_VFAT_UNSUPPORTED, message,
                        "VFAT32 version is unsupported");
    if (bits == 32 && ((fat_le16(boot + 40) & 0x0070u) ||
        ((fat_le16(boot + 40) & 0x0080u) &&
         (fat_le16(boot + 40) & 0x000fu))))
        return fat_fail(ML_VFAT_UNSUPPORTED, message,
                        "VFAT32 selects an unsupported active allocation table");
    if (bits == 32 && !fat_cluster_valid(&(ml_vfat){.cluster_count=(uint32_t)cluster_count}, root_cluster))
        return fat_fail(ML_VFAT_BAD_FORMAT, message,
                        "invalid VFAT32 root directory cluster");
    fat_bytes = (uint64_t)fat_sectors * bytes_per_sector;
    fat_entries_needed = bits == 12 ? ((cluster_count + 2) * 3 + 1) / 2 :
                         bits == 16 ? (cluster_count + 2) * 2 :
                                      (cluster_count + 2) * 4;
    if (fat_bytes < fat_entries_needed ||
        (uint64_t)total_sectors > UINT64_MAX / bytes_per_sector)
        return fat_fail(ML_VFAT_BAD_FORMAT, message,
                        "VFAT allocation table is too small");
    volume_bytes = (uint64_t)total_sectors * bytes_per_sector;
    if (volume_bytes > device->byte_size)
        return fat_fail(ML_VFAT_BAD_FORMAT, message,
                        "VFAT volume extends beyond its block device");
    fs->device = device;
    fs->bytes_per_sector = (uint16_t)bytes_per_sector;
    fs->sectors_per_cluster = (uint8_t)sectors_per_cluster;
    fs->cluster_size = bytes_per_sector * sectors_per_cluster;
    fs->cluster_count = (uint32_t)cluster_count;
    fs->fat_bits = bits;
    fs->fat_offset = (uint64_t)reserved * bytes_per_sector;
    fs->fat_size_bytes = fat_bytes;
    fs->data_offset = data_sector * bytes_per_sector;
    fs->root_cluster = root_cluster;
    fs->root_offset = fat_area * bytes_per_sector;
    fs->root_size = (uint64_t)root_entries * FAT_ENTRY_BYTES;
    return ML_VFAT_OK;
}

ml_vfat_result ml_vfat_open(ml_vfat_file *file, const ml_vfat *fs,
                            const char *path, const char **message)
{
    fat_directory directory;
    const char *part;
    if (message) *message = NULL;
    if (!file || !fs || !path)
        return fat_fail(ML_VFAT_INVALID, message, "invalid VFAT file arguments");
    directory.first_cluster = fs->root_cluster;
    directory.fixed_root = fs->fat_bits != 32;
    directory.fixed_offset = fs->root_offset;
    directory.fixed_size = fs->root_size;
    part = path;
    while (*part == '/' || *part == '\\') ++part;
    if (!*part)
        return fat_fail(ML_VFAT_NOT_FILE, message,
                        "VFAT root directory is not a file");
    for (;;) {
        char component[FAT_MAX_COMPONENT + 1];
        size_t length = 0;
        fat_dirent found;
        ml_vfat_result result;
        int more;
        while (*part && *part != '/' && *part != '\\') {
            if (length >= FAT_MAX_COMPONENT)
                return fat_fail(ML_VFAT_RANGE, message,
                                "VFAT path component is too long");
            component[length++] = *part++;
        }
        if (!length)
            return fat_fail(ML_VFAT_INVALID, message,
                            "VFAT path contains an empty component");
        component[length] = '\0';
        while (*part == '/' || *part == '\\') ++part;
        more = *part != '\0';
        if (fat_ascii_equal(component, ".") || fat_ascii_equal(component, ".."))
            return fat_fail(ML_VFAT_UNSUPPORTED, message,
                            "relative VFAT path components are unsupported");
        result = fat_scan_directory(fs, &directory, component, &found, message);
        if (result != ML_VFAT_OK) {
            if (result == ML_VFAT_NOT_FOUND)
                fat_fail(result, message, "file was not found on VFAT volume");
            return result;
        }
        if (more) {
            if (!(found.attributes & 0x10u))
                return fat_fail(ML_VFAT_NOT_FOUND, message,
                                "VFAT path component is not a directory");
            if (!fat_cluster_valid(fs, found.first_cluster))
                return fat_fail(ML_VFAT_BAD_FORMAT, message,
                                "VFAT directory entry has an invalid cluster");
            directory.first_cluster = found.first_cluster;
            directory.fixed_root = 0;
            directory.fixed_offset = 0;
            directory.fixed_size = 0;
        } else {
            file->filesystem = fs;
            file->first_cluster = found.first_cluster;
            file->size = found.size;
            file->is_directory = !!(found.attributes & 0x10u);
            if (file->is_directory)
                return fat_fail(ML_VFAT_NOT_FILE, message,
                                "VFAT path names a directory");
            if (file->size && !fat_cluster_valid(fs, file->first_cluster))
                return fat_fail(ML_VFAT_BAD_FORMAT, message,
                                "VFAT file entry has an invalid cluster");
            return ML_VFAT_OK;
        }
    }
}

ml_vfat_result ml_vfat_read(const ml_vfat_file *file, uint64_t offset,
                            void *buffer, size_t length, size_t *bytes_read,
                            const char **message)
{
    const ml_vfat *fs;
    uint8_t *out = (uint8_t *)buffer;
    uint64_t remaining;
    uint32_t cluster, next;
    uint64_t cluster_index, within;
    size_t done = 0;
    uint32_t steps = 0;
    if (message) *message = NULL;
    if (bytes_read) *bytes_read = 0;
    if (!file || !file->filesystem || (!buffer && length) || !bytes_read)
        return fat_fail(ML_VFAT_INVALID, message, "invalid VFAT read arguments");
    if (file->is_directory)
        return fat_fail(ML_VFAT_NOT_FILE, message, "VFAT entry is a directory");
    if (offset >= file->size || length == 0) return ML_VFAT_OK;
    fs = file->filesystem;
    remaining = file->size - offset;
    if (remaining > length) remaining = length;
    cluster_index = offset / fs->cluster_size;
    within = offset % fs->cluster_size;
    cluster = file->first_cluster;
    while (cluster_index--) {
        int result = fat_next_cluster(fs, cluster, &next);
        if (result <= 0)
            return fat_fail(ML_VFAT_BAD_FORMAT, message,
                            "VFAT file cluster chain is shorter than its size");
        cluster = next;
        if (++steps >= fs->cluster_count)
            return fat_fail(ML_VFAT_BAD_FORMAT, message,
                            "VFAT file cluster chain is cyclic");
    }
    while (remaining) {
        uint64_t physical;
        size_t amount = (size_t)(fs->cluster_size - within);
        if (amount > remaining) amount = (size_t)remaining;
        if (!fat_cluster_offset(fs, cluster, &physical) ||
            physical > UINT64_MAX - within ||
            ml_block_read(fs->device, physical + within, out + done,
                          amount) != ML_BLOCK_OK)
            return fat_fail(ML_VFAT_IO, message,
                            "cannot read VFAT file data");
        done += amount;
        remaining -= amount;
        within = 0;
        if (remaining) {
            int result = fat_next_cluster(fs, cluster, &next);
            if (result <= 0)
                return fat_fail(ML_VFAT_BAD_FORMAT, message,
                                "VFAT file cluster chain is shorter than its size");
            cluster = next;
            if (++steps >= fs->cluster_count)
                return fat_fail(ML_VFAT_BAD_FORMAT, message,
                                "VFAT file cluster chain is cyclic");
        }
    }
    *bytes_read = done;
    return ML_VFAT_OK;
}
