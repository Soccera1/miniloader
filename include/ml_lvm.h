/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef ML_LVM_H
#define ML_LVM_H

#include "ml_block.h"
#include <stddef.h>
#include <stdint.h>

#define ML_LVM_MAX_PVS 16u
#define ML_LVM_MAX_SCAN_PVS 256u
#define ML_LVM_MAX_VGS 16u
#define ML_LVM_MAX_LVS 32u
#define ML_LVM_MAX_SEGMENTS 32u
#define ML_LVM_MAX_STRIPES 8u
#define ML_LVM_NAME_MAX 128u
#define ML_LVM_ID_MAX 39u
#define ML_LVM_MAX_MDA_BYTES (2u * 1024u * 1024u)
#define ML_LVM_SCAN_SCRATCH_BYTES (32u * 1024u)
#define ML_LVM_SCRATCH_BYTES \
    (2u * ML_LVM_MAX_MDA_BYTES + ML_LVM_SCAN_SCRATCH_BYTES + 1u)

typedef enum {
    ML_LVM_OK = 0,
    ML_LVM_INVALID = -1,
    ML_LVM_NOT_FOUND = -2,
    ML_LVM_BAD_FORMAT = -3,
    ML_LVM_UNSUPPORTED = -4,
    ML_LVM_AMBIGUOUS = -5,
    ML_LVM_IO = -6,
    ML_LVM_RANGE = -7
} ml_lvm_result;

typedef struct {
    char name[ML_LVM_NAME_MAX];
    char uuid[ML_LVM_ID_MAX];
    const ml_block_device *device;
    uint64_t pe_start_sectors;
} ml_lvm_pv;

typedef struct {
    uint64_t start_extent;
    uint64_t extent_count;
    uint64_t stripe_size_bytes;
    uint32_t stripe_count;
    uint8_t pv_index[ML_LVM_MAX_STRIPES];
    uint64_t pv_start_extent[ML_LVM_MAX_STRIPES];
} ml_lvm_segment;

typedef struct ml_lvm_vg ml_lvm_vg;

typedef struct ml_lvm_lv {
    char name[ML_LVM_NAME_MAX];
    uint64_t size_bytes;
    uint64_t extent_size_sectors;
    uint32_t segment_count;
    ml_lvm_segment segments[ML_LVM_MAX_SEGMENTS];
    const ml_lvm_vg *owner;
    ml_block_device device;
} ml_lvm_lv;

struct ml_lvm_vg {
    char name[ML_LVM_NAME_MAX];
    char uuid[ML_LVM_ID_MAX];
    uint64_t extent_size_sectors;
    uint32_t pv_count;
    uint32_t lv_count;
    ml_lvm_pv pvs[ML_LVM_MAX_PVS];
    ml_lvm_lv lvs[ML_LVM_MAX_LVS];
};

/* The caller provides metadata scratch (at least ML_LVM_SCRATCH_BYTES).
 * Input devices are read-only PV candidates; unrelated filesystems are
 * ignored. This version supports one VG per call and linear/striped LVs. */
ml_lvm_result ml_lvm_scan(ml_lvm_vg *vg,
                          const ml_block_device *const *devices,
                          size_t device_count,
                          void *scratch, size_t scratch_size,
                          const char **error_message);
ml_lvm_result ml_lvm_scan_all(ml_lvm_vg *vgs, size_t vg_capacity,
                              size_t *vg_count,
                              const ml_block_device *const *devices,
                              size_t device_count,
                              void *scratch, size_t scratch_size,
                              const char **error_message);
const ml_lvm_lv *ml_lvm_find_lv(const ml_lvm_vg *vg, const char *name);

#endif
