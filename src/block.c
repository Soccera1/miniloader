/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "ml_block.h"

#define GPT_HEADER_MIN_SIZE 92u
#define GPT_ENTRY_MIN_SIZE 128u
#define GPT_ENTRY_MAX_SIZE 4096u
#define GPT_MAX_ENTRY_COUNT 4096u
#define GPT_MAX_TABLE_BYTES (16u * 1024u * 1024u)

static uint32_t read_le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t read_le64(const uint8_t *p)
{
    return (uint64_t)read_le32(p) | ((uint64_t)read_le32(p + 4) << 32);
}

static uint32_t crc32_update(uint32_t crc, const uint8_t *data, size_t length)
{
    size_t i;
    for (i = 0; i < length; ++i) {
        unsigned bit;
        crc ^= data[i];
        for (bit = 0; bit < 8; ++bit)
            crc = (crc >> 1) ^ (0xedb88320u & (uint32_t)-(int32_t)(crc & 1));
    }
    return crc;
}

static uint32_t gpt_header_crc(const uint8_t *header, size_t length)
{
    uint32_t crc = 0xffffffffu;
    static const uint8_t zeros[4] = {0, 0, 0, 0};
    crc = crc32_update(crc, header, 16);
    crc = crc32_update(crc, zeros, sizeof(zeros));
    crc = crc32_update(crc, header + 20, length - 20);
    return ~crc;
}

static int slice_read(void *context, uint64_t offset,
                      void *buffer, size_t length);

static int bytes_equal(const uint8_t *a, const uint8_t *b, size_t length)
{
    size_t i;
    for (i = 0; i < length; ++i) if (a[i] != b[i]) return 0;
    return 1;
}

int ml_block_read(const ml_block_device *device, uint64_t offset,
                  void *buffer, size_t length)
{
    if (!device || !device->read_at || (!buffer && length != 0))
        return ML_BLOCK_INVALID;
    if (offset > device->byte_size || (uint64_t)length > device->byte_size - offset)
        return ML_BLOCK_RANGE;
    if (length == 0) return ML_BLOCK_OK;
    return device->read_at(device->context, offset, buffer, length) == 0
        ? ML_BLOCK_OK : ML_BLOCK_IO;
}

static int slice_read(void *context, uint64_t offset, void *buffer, size_t length)
{
    ml_block_slice *slice = (ml_block_slice *)context;
    if (!slice || !slice->parent || offset > slice->device.byte_size ||
        (uint64_t)length > slice->device.byte_size - offset)
        return -1;
    if (slice->base_offset > UINT64_MAX - offset) return -1;
    return ml_block_read(slice->parent, slice->base_offset + offset,
                         buffer, length) == ML_BLOCK_OK ? 0 : -1;
}

int ml_block_slice_init(ml_block_slice *slice, const ml_block_device *parent,
                        uint64_t first_lba, uint64_t block_count)
{
    uint64_t byte_offset, byte_size;
    if (!slice || !parent || !parent->read_at || parent->logical_block_size == 0 ||
        block_count == 0)
        return ML_BLOCK_INVALID;
    if (first_lba > UINT64_MAX / parent->logical_block_size ||
        block_count > UINT64_MAX / parent->logical_block_size)
        return ML_BLOCK_RANGE;
    byte_offset = first_lba * parent->logical_block_size;
    byte_size = block_count * parent->logical_block_size;
    if (byte_offset > parent->byte_size || byte_size > parent->byte_size - byte_offset)
        return ML_BLOCK_RANGE;
    slice->parent = parent;
    slice->base_offset = byte_offset;
    slice->device.context = slice;
    slice->device.byte_size = byte_size;
    slice->device.logical_block_size = parent->logical_block_size;
    slice->device.read_at = slice_read;
    return ML_BLOCK_OK;
}

int ml_gpt_find_partition(const ml_block_device *disk,
                           const uint8_t partition_guid[16],
                           void *scratch_buffer, size_t scratch_size,
                           ml_gpt_partition *partition)
{
    uint8_t *scratch = (uint8_t *)scratch_buffer;
    const uint8_t *header;
    uint32_t header_size, stored_header_crc, entry_count, entry_size;
    uint64_t total_lbas, table_lba, table_bytes, table_offset;
    uint64_t first_usable, last_usable, found_first = 0, found_last = 0;
    uint32_t stored_table_crc, table_crc = 0xffffffffu;
    uint64_t i;
    int found = 0;

    if (!disk || !partition_guid || !scratch || !partition || !disk->read_at ||
        disk->logical_block_size < 512 || disk->logical_block_size > GPT_ENTRY_MAX_SIZE ||
        (disk->logical_block_size & (disk->logical_block_size - 1)) != 0 ||
        scratch_size < disk->logical_block_size || disk->byte_size < 2ull * disk->logical_block_size)
        return ML_BLOCK_INVALID;
    total_lbas = disk->byte_size / disk->logical_block_size;
    if (ml_block_read(disk, disk->logical_block_size, scratch,
                      disk->logical_block_size) != ML_BLOCK_OK)
        return ML_BLOCK_IO;
    header = scratch;
    if (header[0] != 'E' || header[1] != 'F' || header[2] != 'I' || header[3] != ' ' ||
        header[4] != 'P' || header[5] != 'A' || header[6] != 'R' || header[7] != 'T')
        return ML_BLOCK_BAD_FORMAT;
    header_size = read_le32(header + 12);
    stored_header_crc = read_le32(header + 16);
    if (header_size < GPT_HEADER_MIN_SIZE || header_size > disk->logical_block_size)
        return ML_BLOCK_BAD_FORMAT;
    if (gpt_header_crc(header, header_size) != stored_header_crc)
        return ML_BLOCK_BAD_FORMAT;
    if (read_le64(header + 24) != 1 || read_le64(header + 32) >= total_lbas)
        return ML_BLOCK_BAD_FORMAT;
    first_usable = read_le64(header + 40);
    last_usable = read_le64(header + 48);
    table_lba = read_le64(header + 72);
    entry_count = read_le32(header + 80);
    entry_size = read_le32(header + 84);
    stored_table_crc = read_le32(header + 88);
    if (first_usable > last_usable || last_usable >= total_lbas ||
        entry_count == 0 || entry_count > GPT_MAX_ENTRY_COUNT ||
        entry_size < GPT_ENTRY_MIN_SIZE || entry_size > GPT_ENTRY_MAX_SIZE ||
        (entry_size & 7) != 0 || scratch_size < entry_size)
        return ML_BLOCK_BAD_FORMAT;
    table_bytes = (uint64_t)entry_count * entry_size;
    if (table_bytes > GPT_MAX_TABLE_BYTES || table_lba > UINT64_MAX / disk->logical_block_size)
        return ML_BLOCK_BAD_FORMAT;
    table_offset = table_lba * disk->logical_block_size;
    if (table_offset > disk->byte_size || table_bytes > disk->byte_size - table_offset)
        return ML_BLOCK_BAD_FORMAT;
    if (table_lba <= 1 || table_lba >= first_usable ||
        (table_bytes + disk->logical_block_size - 1) / disk->logical_block_size > first_usable - table_lba)
        return ML_BLOCK_BAD_FORMAT;

    for (i = 0; i < entry_count; ++i) {
        uint8_t *entry = scratch;
        uint64_t offset = table_offset + i * entry_size;
        uint64_t first_lba, last_lba;
        int type_empty = 1;
        size_t j;
        if (ml_block_read(disk, offset, entry, entry_size) != ML_BLOCK_OK)
            return ML_BLOCK_IO;
        table_crc = crc32_update(table_crc, entry, entry_size);
        for (j = 0; j < 16; ++j) if (entry[j] != 0) { type_empty = 0; break; }
        if (type_empty || !bytes_equal(partition_guid, entry + 16, 16)) continue;
        first_lba = read_le64(entry + 32);
        last_lba = read_le64(entry + 40);
        if (first_lba < first_usable || last_lba > last_usable || first_lba > last_lba)
            return ML_BLOCK_BAD_FORMAT;
        if (found) return ML_BLOCK_AMBIGUOUS;
        found = 1;
        found_first = first_lba;
        found_last = last_lba;
    }
    if (~table_crc != stored_table_crc) return ML_BLOCK_BAD_FORMAT;
    if (!found) return ML_BLOCK_NOT_FOUND;
    for (i = 0; i < 16; ++i) partition->partition_guid[i] = partition_guid[i];
    partition->first_lba = found_first;
    partition->last_lba = found_last;
    return ML_BLOCK_OK;
}
