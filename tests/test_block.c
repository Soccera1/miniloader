/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "ml_block.h"
#include <assert.h>
#include <stdio.h>
#include <stdint.h>

#define SECTOR_SIZE 512u
#define DISK_LBAS 64u

static uint8_t disk_bytes[SECTOR_SIZE * DISK_LBAS];
static const uint8_t target_guid[16] = {
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};

static void copy_bytes(uint8_t *destination, const uint8_t *source, size_t length)
{
    size_t i;
    for (i = 0; i < length; ++i) destination[i] = source[i];
}

static void set_le32(uint8_t *p, uint32_t value)
{
    p[0] = (uint8_t)value;
    p[1] = (uint8_t)(value >> 8);
    p[2] = (uint8_t)(value >> 16);
    p[3] = (uint8_t)(value >> 24);
}

static void set_le64(uint8_t *p, uint64_t value)
{
    set_le32(p, (uint32_t)value);
    set_le32(p + 4, (uint32_t)(value >> 32));
}

static uint32_t crc32(const uint8_t *data, size_t length)
{
    uint32_t crc = 0xffffffffu;
    size_t i;
    for (i = 0; i < length; ++i) {
        unsigned bit;
        crc ^= data[i];
        for (bit = 0; bit < 8; ++bit)
            crc = (crc >> 1) ^ (0xedb88320u & (uint32_t)-(int32_t)(crc & 1));
    }
    return ~crc;
}

static int memory_read(void *context, uint64_t offset, void *buffer, size_t length)
{
    (void)context;
    if (offset > sizeof(disk_bytes) || length > sizeof(disk_bytes) - offset) return -1;
    copy_bytes((uint8_t *)buffer, disk_bytes + offset, length);
    return 0;
}

static void refresh_crcs(void)
{
    uint8_t *header = disk_bytes + SECTOR_SIZE;
    uint8_t *table = disk_bytes + 2 * SECTOR_SIZE;
    set_le32(header + 16, 0);
    set_le32(header + 16, crc32(header, 92));
    set_le32(header + 88, crc32(table, 4 * 128));
    set_le32(header + 16, 0);
    set_le32(header + 16, crc32(header, 92));
}

static void create_disk(void)
{
    uint8_t *header;
    uint8_t *table;
    uint8_t *entry;
    size_t i;
    for (i = 0; i < sizeof(disk_bytes); ++i) disk_bytes[i] = 0;
    header = disk_bytes + SECTOR_SIZE;
    table = disk_bytes + 2 * SECTOR_SIZE;
    header[0] = 'E'; header[1] = 'F'; header[2] = 'I'; header[3] = ' ';
    header[4] = 'P'; header[5] = 'A'; header[6] = 'R'; header[7] = 'T';
    set_le32(header + 8, 0x00010000u);
    set_le32(header + 12, 92);
    set_le64(header + 24, 1);
    set_le64(header + 32, DISK_LBAS - 1);
    set_le64(header + 40, 4);
    set_le64(header + 48, DISK_LBAS - 2);
    set_le64(header + 72, 2);
    set_le32(header + 80, 4);
    set_le32(header + 84, 128);
    entry = table;
    entry[0] = 0xa0;
    copy_bytes(entry + 16, target_guid, sizeof(target_guid));
    set_le64(entry + 32, 8);
    set_le64(entry + 40, 15);
    for (i = 0; i < 8 * SECTOR_SIZE; ++i)
        disk_bytes[8 * SECTOR_SIZE + i] = (uint8_t)(i ^ 0x5a);
    refresh_crcs();
}

static void finds_gpt_partition_and_reads_slice(void)
{
    uint8_t scratch[4096];
    uint8_t output[32];
    ml_gpt_partition partition;
    ml_block_slice slice;
    ml_block_device disk = {NULL, sizeof(disk_bytes), SECTOR_SIZE, memory_read};
    size_t i;

    create_disk();
    assert(ml_gpt_find_partition(&disk, target_guid, scratch, sizeof(scratch), &partition) == ML_BLOCK_OK);
    assert(partition.first_lba == 8 && partition.last_lba == 15);
    assert(ml_block_slice_init(&slice, &disk, partition.first_lba,
                               partition.last_lba - partition.first_lba + 1) == ML_BLOCK_OK);
    assert(ml_block_read(&slice.device, 17, output, sizeof(output)) == ML_BLOCK_OK);
    for (i = 0; i < sizeof(output); ++i) assert(output[i] == (uint8_t)((17 + i) ^ 0x5a));
    assert(ml_block_read(&slice.device, slice.device.byte_size - 4, output, 8) == ML_BLOCK_RANGE);
    assert(ml_block_read(&disk, UINT64_MAX, output, 1) == ML_BLOCK_RANGE);
}

static void rejects_bad_and_ambiguous_metadata(void)
{
    uint8_t scratch[4096];
    uint8_t missing[16];
    uint8_t *header;
    uint8_t *table;
    ml_gpt_partition partition;
    ml_block_device disk = {NULL, sizeof(disk_bytes), SECTOR_SIZE, memory_read};
    size_t i;

    create_disk();
    header = disk_bytes + SECTOR_SIZE;
    table = disk_bytes + 2 * SECTOR_SIZE;
    copy_bytes(missing, target_guid, sizeof(missing));
    missing[0] ^= 0xff;
    assert(ml_gpt_find_partition(&disk, missing, scratch, sizeof(scratch), &partition) == ML_BLOCK_NOT_FOUND);

    table[56] ^= 1;
    assert(ml_gpt_find_partition(&disk, target_guid, scratch, sizeof(scratch), &partition) == ML_BLOCK_BAD_FORMAT);

    create_disk();
    header = disk_bytes + SECTOR_SIZE;
    table = disk_bytes + 2 * SECTOR_SIZE;
    table[128] = 0xa0;
    copy_bytes(table + 128 + 16, target_guid, sizeof(target_guid));
    set_le64(table + 128 + 32, 16);
    set_le64(table + 128 + 40, 23);
    refresh_crcs();
    assert(ml_gpt_find_partition(&disk, target_guid, scratch, sizeof(scratch), &partition) == ML_BLOCK_AMBIGUOUS);

    create_disk();
    header = disk_bytes + SECTOR_SIZE;
    table = disk_bytes + 2 * SECTOR_SIZE;
    set_le64(table + 40, DISK_LBAS + 10);
    refresh_crcs();
    assert(ml_gpt_find_partition(&disk, target_guid, scratch, sizeof(scratch), &partition) == ML_BLOCK_BAD_FORMAT);

    create_disk();
    header = disk_bytes + SECTOR_SIZE;
    header[16] ^= 1;
    assert(ml_gpt_find_partition(&disk, target_guid, scratch, sizeof(scratch), &partition) == ML_BLOCK_BAD_FORMAT);
    for (i = 0; i < sizeof(missing); ++i) assert(missing[i] != 0);
}

int main(void)
{
    finds_gpt_partition_and_reads_slice();
    rejects_bad_and_ambiguous_metadata();
    puts("read-only block and GPT tests passed");
    return 0;
}
