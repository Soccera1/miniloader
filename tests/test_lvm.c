/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "ml_lvm.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PV_BYTES (8u * 1024u * 1024u)
#define SECTOR 512u
#define MDA_OFFSET 4096u
#define MDA_SIZE 65536u
#define PE_START_SECTORS 2048u
#define EXTENT_SECTORS 128u

static uint8_t pv_data[3][PV_BYTES];
static const char raw_uuid[3][33] = {
    "0123456789abcdefghijklmnopqrstuv",
    "ABCDEFGHIJKLMNOPQRSTUVWX01234567",
    "qrstuvwxyz0123456789abcdefghijkl"
};
static const char *const vg_metadata =
    "vgtest {\n"
    " id = \"abcdef-1234-5678-90ab-cdef-1234-567890\"\n"
    " extent_size = 128\n"
    " physical_volumes {\n"
    "  pv0 { id = \"012345-6789-abcd-efgh-ijkl-mnop-qrstuv\" pe_start = 2048 }\n"
    "  pv1 { id = \"ABCDEF-GHIJ-KLMN-OPQR-STUV-WX01-234567\" pe_start = 2048 }\n"
    " }\n"
    " logical_volumes {\n"
    "  root {\n"
    "   status = [ \"READ\", \"WRITE\", \"VISIBLE\" ]\n"
    "   segment_count = 1\n"
    "   segment1 { start_extent = 0 extent_count = 4 type = \"linear\" stripe_count = 1 stripes = [ \"pv0\", 0 ] }\n"
    "  }\n"
    "  stripe {\n"
    "   status = [ \"READ\", \"WRITE\", \"VISIBLE\" ]\n"
    "   segment_count = 1\n"
    "   segment1 { start_extent = 0 extent_count = 4 type = \"striped\" stripe_count = 2 stripe_size = 8 stripes = [ \"pv0\", 4, \"pv1\", 4 ] }\n"
    "  }\n"
    " }\n"
    "}\n";
static const char *const second_vg_metadata =
    "vgother {\n"
    " id = \"ghijkl-7890-abcd-efgh-ijkl-7890-abcdef\"\n"
    " extent_size = 128\n"
    " physical_volumes {\n"
    "  pv2 { id = \"qrstuv-wxyz-0123-4567-89ab-cdef-ghijkl\" pe_start = 2048 }\n"
    " }\n"
    " logical_volumes {\n"
    "  data {\n"
    "   status = [ \"READ\", \"WRITE\", \"VISIBLE\" ]\n"
    "   segment_count = 1\n"
    "   segment1 { start_extent = 0 extent_count = 4 type = \"linear\" stripe_count = 1 stripes = [ \"pv2\", 0 ] }\n"
    "  }\n"
    " }\n"
    "}\n";

typedef struct { uint8_t *bytes; size_t length; } memory_disk;

static void put_le32(uint8_t *p, uint32_t n)
{
    p[0] = (uint8_t)n; p[1] = (uint8_t)(n >> 8);
    p[2] = (uint8_t)(n >> 16); p[3] = (uint8_t)(n >> 24);
}

static void put_le64(uint8_t *p, uint64_t n)
{
    put_le32(p, (uint32_t)n);
    put_le32(p + 4, (uint32_t)(n >> 32));
}

static int memory_read(void *context, uint64_t offset,
                       void *buffer, size_t length)
{
    memory_disk *disk = (memory_disk *)context;
    if (offset > disk->length || length > disk->length - (size_t)offset)
        return -1;
    memcpy(buffer, disk->bytes + (size_t)offset, length);
    return 0;
}

static void put_pv_label(unsigned index, const char *metadata)
{
    uint8_t *label = pv_data[index] + SECTOR;
    uint8_t *pvh;
    uint8_t *mda = pv_data[index] + MDA_OFFSET;
    size_t metadata_length = strlen(metadata);
    size_t i;
    memset(label, 0, SECTOR);
    memcpy(label, "LABELONE", 8);
    put_le64(label + 8, 1);
    put_le32(label + 20, 32);
    memcpy(label + 24, "LVM2 001", 8);
    pvh = label + 32;
    memcpy(pvh, raw_uuid[index], 32);
    put_le64(pvh + 32, PV_BYTES);
    put_le64(pvh + 40, 1024u * 1024u);
    put_le64(pvh + 48, PV_BYTES - 1024u * 1024u);
    put_le64(pvh + 72, MDA_OFFSET);
    put_le64(pvh + 80, MDA_SIZE);

    memset(mda, 0, MDA_SIZE);
    memcpy(mda + 4, " LVM2 x[5A%r0N*>", 16);
    put_le32(mda + 20, 1);
    put_le64(mda + 24, MDA_OFFSET);
    put_le64(mda + 32, MDA_SIZE);
    put_le64(mda + 40, 512);
    put_le64(mda + 48, metadata_length);
    for (i = 0; i < metadata_length; ++i) mda[512 + i] = (uint8_t)metadata[i];
}

static void fill_data(void)
{
    size_t i;
    uint8_t *linear = pv_data[0] + PE_START_SECTORS * SECTOR;
    uint8_t *base0 = pv_data[0] + PE_START_SECTORS * SECTOR +
                     4u * EXTENT_SECTORS * SECTOR;
    uint8_t *base1 = pv_data[1] + PE_START_SECTORS * SECTOR +
                     4u * EXTENT_SECTORS * SECTOR;
    size_t logical = 4u * EXTENT_SECTORS * SECTOR;
    for (i = 0; i < logical; ++i) linear[i] = (uint8_t)((i * 11u + 9u) & 0xffu);
    for (i = 0; i < logical; ++i) {
        unsigned stripe = (unsigned)(i / (8u * SECTOR)) & 1u;
        uint64_t row = (uint64_t)(i / (16u * SECTOR)) * (8u * SECTOR);
        size_t in_stripe = i % (8u * SECTOR);
        uint8_t *base = stripe ? base1 : base0;
        base[row + in_stripe] = (uint8_t)((i * 19u + 3u) & 0xffu);
    }
}

static void scans_linear_and_striped_volumes(void)
{
    memory_disk memory[3] = {
        {pv_data[0], sizeof(pv_data[0])},
        {pv_data[1], sizeof(pv_data[1])},
        {pv_data[2], sizeof(pv_data[2])}
    };
    ml_block_device devices[3] = {
        {&memory[0], PV_BYTES, SECTOR, memory_read},
        {&memory[1], PV_BYTES, SECTOR, memory_read},
        {&memory[2], PV_BYTES, SECTOR, memory_read}
    };
    const ml_block_device *device_list[3] = {&devices[0], &devices[1], &devices[2]};
    ml_lvm_vg *vgs = (ml_lvm_vg *)calloc(2, sizeof(*vgs));
    uint8_t *scratch = (uint8_t *)malloc(ML_LVM_SCRATCH_BYTES);
    const ml_lvm_lv *root, *stripe, *data;
    const char *message = NULL;
    uint8_t actual[600], expected[600];
    size_t i;
    size_t vg_count = 0;
    assert(vgs && scratch);
    memset(pv_data, 0, sizeof(pv_data));
    put_pv_label(0, vg_metadata);
    put_pv_label(1, vg_metadata);
    put_pv_label(2, second_vg_metadata);
    fill_data();
    {
        uint8_t *base = pv_data[2] + PE_START_SECTORS * SECTOR;
        size_t logical = 4u * EXTENT_SECTORS * SECTOR;
        for (i = 0; i < logical; ++i)
            base[i] = (uint8_t)((i * 23u + 5u) & 0xffu);
    }
    {
        ml_lvm_result result = ml_lvm_scan_all(vgs, 2, &vg_count,
            device_list, 3, scratch, ML_LVM_SCRATCH_BYTES, &message);
        if (result != ML_LVM_OK) {
            fprintf(stderr, "LVM scan failed (%d): %s\n", result,
                    message ? message : "no diagnostic");
            abort();
        }
    }
    assert(vg_count == 2);
    root = ml_lvm_find_lv(&vgs[0], "root");
    stripe = ml_lvm_find_lv(&vgs[0], "stripe");
    data = ml_lvm_find_lv(&vgs[1], "data");
    if (!root || !stripe)
        fprintf(stderr, "LVM parsed %u PVs, %u LVs: '%s', '%s'\n",
                vgs[0].pv_count, vgs[0].lv_count,
                vgs[0].lvs[0].name, vgs[0].lvs[1].name);
    assert(root && stripe && data && vgs[0].pv_count == 2);
    assert(vgs[1].pv_count == 1);
    assert(root->device.byte_size == 4u * EXTENT_SECTORS * SECTOR);
    assert(stripe->device.byte_size == root->device.byte_size);
    assert(ml_block_read(&root->device, 123, actual, sizeof(actual)) == ML_BLOCK_OK);
    for (i = 0; i < sizeof(expected); ++i)
        expected[i] = (uint8_t)(((i + 123) * 11u + 9u) & 0xffu);
    assert(memcmp(actual, expected, sizeof(actual)) == 0);
    assert(ml_block_read(&stripe->device, 3900, actual, sizeof(actual)) == ML_BLOCK_OK);
    for (i = 0; i < sizeof(expected); ++i)
        expected[i] = (uint8_t)(((i + 3900) * 19u + 3u) & 0xffu);
    assert(memcmp(actual, expected, sizeof(actual)) == 0);
    assert(ml_block_read(&data->device, 21, actual, sizeof(actual)) == ML_BLOCK_OK);
    for (i = 0; i < sizeof(expected); ++i)
        expected[i] = (uint8_t)(((i + 21) * 23u + 5u) & 0xffu);
    assert(memcmp(actual, expected, sizeof(actual)) == 0);
    assert(ml_lvm_find_lv(&vgs[0], "missing") == NULL);
    assert(ml_block_read(&stripe->device, stripe->device.byte_size - 4,
                         actual, 8) == ML_BLOCK_RANGE);
    free(scratch);
    free(vgs);
}

static ml_lvm_result scan_two_pvs(const char **message)
{
    memory_disk memory[2] = {
        {pv_data[0], sizeof(pv_data[0])},
        {pv_data[1], sizeof(pv_data[1])}
    };
    ml_block_device devices[2] = {
        {&memory[0], PV_BYTES, SECTOR, memory_read},
        {&memory[1], PV_BYTES, SECTOR, memory_read}
    };
    const ml_block_device *device_list[2] = {&devices[0], &devices[1]};
    ml_lvm_vg *vgs = (ml_lvm_vg *)calloc(2, sizeof(*vgs));
    uint8_t *scratch = (uint8_t *)malloc(ML_LVM_SCRATCH_BYTES);
    size_t count = 0;
    ml_lvm_result result;
    assert(vgs && scratch);
    result = ml_lvm_scan_all(vgs, 2, &count, device_list, 2, scratch,
                             ML_LVM_SCRATCH_BYTES, message);
    free(scratch);
    free(vgs);
    return result;
}

static void rejects_malformed_metadata_and_unsupported_segments(void)
{
    const char *message = NULL;
    char unsupported[1024];
    char *linear_type;

    memset(pv_data, 0, sizeof(pv_data));
    put_pv_label(0, vg_metadata);
    put_pv_label(1, vg_metadata);
    pv_data[0][MDA_OFFSET + 4] = 'x';
    pv_data[1][MDA_OFFSET + 4] = 'x';
    assert(scan_two_pvs(&message) == ML_LVM_BAD_FORMAT);
    assert(message != NULL);

    memset(pv_data, 0, sizeof(pv_data));
    memcpy(unsupported, vg_metadata, strlen(vg_metadata) + 1);
    linear_type = strstr(unsupported, "type = \"linear\"");
    assert(linear_type != NULL);
    memcpy(linear_type + sizeof("type = \"") - 1, "raidxx", 6);
    put_pv_label(0, unsupported);
    put_pv_label(1, unsupported);
    message = NULL;
    assert(scan_two_pvs(&message) == ML_LVM_UNSUPPORTED);
    assert(message != NULL);
}

int main(void)
{
    scans_linear_and_striped_volumes();
    rejects_malformed_metadata_and_unsupported_segments();
    puts("read-only LVM linear/striped tests passed");
    return 0;
}
