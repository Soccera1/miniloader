/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * Read-only LVM2 label and text-metadata reader. Its on-disk structures and
 * linear/striped mapping model follow GRUB's LVM driver, Copyright (C)
 * 2006-2011 Free Software Foundation, Inc. This implementation is standalone
 * and includes no GRUB runtime or command-interpreter code.
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option)
 * any later version. It is distributed without any warranty; see the GNU
 * General Public License for details.
 */
#include "ml_lvm.h"

#define LVM_SECTOR_BYTES 512u
#define LVM_LABEL_SECTORS 4u
#define LVM_LABEL_MAGIC "LABELONE"
#define LVM_TYPE_MAGIC "LVM2 001"
#define LVM_MDA_MAGIC "\040\114\126\115\062\040\170\133\065\101\045\162\060\116\052\076"
#define LVM_MDA_HEADER_BYTES 512u
#define LVM_PV_RAW_ID_BYTES 32u
#define LVM_DISK_LOCN_BYTES 16u

typedef struct {
    char id[ML_LVM_ID_MAX];
    const ml_block_device *device;
    uint64_t mda_offset;
    uint64_t mda_size;
} lvm_discovered_pv;

typedef struct {
    size_t start;
    size_t name_end;
    size_t body_start;
    size_t body_end;
    size_t next;
    int is_block;
    int is_assignment;
} lvm_item;

static uint32_t lvm_le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t lvm_le64(const uint8_t *p)
{
    return (uint64_t)lvm_le32(p) | ((uint64_t)lvm_le32(p + 4) << 32);
}

static void lvm_copy(char *dst, const char *src, size_t length)
{
    size_t i;
    for (i = 0; i < length; ++i) dst[i] = src[i];
    dst[length] = '\0';
}

static void lvm_copy_bytes(uint8_t *dst, const uint8_t *src, size_t length)
{
    size_t i;
    for (i = 0; i < length; ++i) dst[i] = src[i];
}

static void lvm_zero(void *buffer, size_t length)
{
    uint8_t *bytes = (uint8_t *)buffer;
    size_t i;
    for (i = 0; i < length; ++i) bytes[i] = 0;
}

static int lvm_equal(const char *a, const char *b)
{
    size_t i = 0;
    if (!a || !b) return 0;
    while (a[i] && b[i]) {
        char x = a[i], y = b[i];
        if (x >= 'A' && x <= 'Z') x = (char)(x + ('a' - 'A'));
        if (y >= 'A' && y <= 'Z') y = (char)(y + ('a' - 'A'));
        if (x != y) return 0;
        ++i;
    }
    return a[i] == b[i];
}

static int lvm_id_equal(const char *a, const char *b)
{
    size_t i;
    for (i = 0; i < ML_LVM_ID_MAX; ++i) {
        char x = a[i], y = b[i];
        if (x >= 'A' && x <= 'Z') x = (char)(x + ('a' - 'A'));
        if (y >= 'A' && y <= 'Z') y = (char)(y + ('a' - 'A'));
        if (x != y) return 0;
        if (!x) return 1;
    }
    return 1;
}

static int lvm_valid_text_id(const char *text)
{
    size_t i;
    if (!text) return 0;
    for (i = 0; i < ML_LVM_ID_MAX - 1; ++i) {
        char c = text[i];
        int separator = i == 6 || i == 11 || i == 16 ||
                        i == 21 || i == 26 || i == 31;
        if (separator) {
            if (c != '-') return 0;
        } else if (!((c >= 'A' && c <= 'Z') ||
                     (c >= 'a' && c <= 'z') ||
                     (c >= '0' && c <= '9'))) {
            return 0;
        }
    }
    return text[ML_LVM_ID_MAX - 1] == '\0';
}

static ml_lvm_result lvm_fail(ml_lvm_result result, const char **message,
                              const char *text)
{
    if (message) *message = text;
    return result;
}

static int lvm_mul64(uint64_t a, uint64_t b, uint64_t *result)
{
    if (b && a > UINT64_MAX / b) return 0;
    *result = a * b;
    return 1;
}

static int lvm_uuid_from_raw(const uint8_t raw[LVM_PV_RAW_ID_BYTES], char out[ML_LVM_ID_MAX])
{
    size_t i, p = 0;
    for (i = 0; i < LVM_PV_RAW_ID_BYTES; ++i) {
        if (!((raw[i] >= 'A' && raw[i] <= 'Z') ||
              (raw[i] >= 'a' && raw[i] <= 'z') ||
              (raw[i] >= '0' && raw[i] <= '9'))) return 0;
        out[p++] = (char)raw[i];
        if (i != 1 && i != 29 && (i % 4) == 1) out[p++] = '-';
    }
    out[p] = '\0';
    return p == 38;
}

static int lvm_locate_pv(const ml_block_device *device,
                         lvm_discovered_pv *pv, const char **message)
{
    uint8_t label[LVM_SECTOR_BYTES];
    uint8_t *pvh;
    uint32_t label_offset;
    uint64_t data_offset, data_size, mda_offset = 0, mda_size = 0;
    size_t loc_offset, end;
    unsigned sector, data_count = 0, mda_count = 0, n;

    for (sector = 0; sector < LVM_LABEL_SECTORS; ++sector) {
        if ((uint64_t)sector * LVM_SECTOR_BYTES > device->byte_size ||
            LVM_SECTOR_BYTES > device->byte_size - (uint64_t)sector * LVM_SECTOR_BYTES)
            break;
        if (ml_block_read(device, (uint64_t)sector * LVM_SECTOR_BYTES,
                          label, sizeof(label)) != ML_BLOCK_OK)
            return 0;
        if (label[0] != 'L' || label[1] != 'A' || label[2] != 'B' ||
            label[3] != 'E' || label[4] != 'L' || label[5] != 'O' ||
            label[6] != 'N' || label[7] != 'E')
            continue;
        if (lvm_le64(label + 8) != sector ||
            label[24] != 'L' || label[25] != 'V' || label[26] != 'M' ||
            label[27] != '2' || label[28] != ' ' || label[29] != '0' ||
            label[30] != '0' || label[31] != '1') {
            (void)lvm_fail(ML_LVM_BAD_FORMAT, message,
                           "invalid LVM label header");
            return -1;
        }
        label_offset = lvm_le32(label + 20);
        if (label_offset < 32 || label_offset > sizeof(label) - 64) {
            (void)lvm_fail(ML_LVM_BAD_FORMAT, message,
                           "LVM PV header exceeds its label sector");
            return -1;
        }
        pvh = label + label_offset;
        if (!lvm_uuid_from_raw(pvh, pv->id)) {
            (void)lvm_fail(ML_LVM_BAD_FORMAT, message,
                           "invalid LVM PV identifier");
            return -1;
        }
        loc_offset = (size_t)label_offset + 40;
        end = sizeof(label);
        for (n = 0; n < 8 && loc_offset + LVM_DISK_LOCN_BYTES <= end; ++n) {
            data_offset = lvm_le64(label + loc_offset);
            data_size = lvm_le64(label + loc_offset + 8);
            loc_offset += LVM_DISK_LOCN_BYTES;
            if (!data_offset && !data_size) break;
            if (!data_offset || !data_size || data_offset > device->byte_size ||
                data_size > device->byte_size - data_offset) {
                (void)lvm_fail(ML_LVM_BAD_FORMAT, message,
                               "invalid LVM data area descriptor");
                return -1;
            }
            data_count++;
        }
        if (data_count != 1 || loc_offset + LVM_DISK_LOCN_BYTES > end) {
            (void)lvm_fail(ML_LVM_UNSUPPORTED, message,
                           "LVM PV must have exactly one data area");
            return -1;
        }
        /* The disk area list terminator immediately precedes metadata areas. */
        if (lvm_le64(label + loc_offset - LVM_DISK_LOCN_BYTES) != 0 ||
            lvm_le64(label + loc_offset - LVM_DISK_LOCN_BYTES + 8) != 0) {
            (void)lvm_fail(ML_LVM_BAD_FORMAT, message,
                           "LVM data area list has no terminator");
            return -1;
        }
        for (n = 0; n < 8 && loc_offset + LVM_DISK_LOCN_BYTES <= end; ++n) {
            data_offset = lvm_le64(label + loc_offset);
            data_size = lvm_le64(label + loc_offset + 8);
            loc_offset += LVM_DISK_LOCN_BYTES;
            if (!data_offset && !data_size) break;
            if (!data_offset || !data_size || data_offset > device->byte_size ||
                data_size > device->byte_size - data_offset) {
                (void)lvm_fail(ML_LVM_BAD_FORMAT, message,
                               "invalid LVM metadata area descriptor");
                return -1;
            }
            if (mda_count == 0) { mda_offset = data_offset; mda_size = data_size; }
            mda_count++;
        }
        if (mda_count == 0 || !mda_offset || mda_size < LVM_MDA_HEADER_BYTES) {
            (void)lvm_fail(ML_LVM_BAD_FORMAT, message,
                           "LVM PV has no usable metadata area");
            return -1;
        }
        pv->device = device;
        pv->mda_offset = mda_offset;
        pv->mda_size = mda_size;
        return 1;
    }
    return 0;
}

static int lvm_is_space(char c)
{
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

static void lvm_skip(const char *text, size_t length, size_t *position)
{
    while (*position < length) {
        if (lvm_is_space(text[*position])) { ++*position; continue; }
        if (text[*position] == '#') {
            while (*position < length && text[*position] != '\n') ++*position;
            continue;
        }
        break;
    }
}

static int lvm_name_char(char c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
           (c >= '0' && c <= '9') || c == '_' || c == '-' ||
           c == '+' || c == '.';
}

static int lvm_skip_string(const char *text, size_t length, size_t *position)
{
    if (*position >= length || text[*position] != '"') return 0;
    ++*position;
    while (*position < length) {
        char c = text[(*position)++];
        if (c == '\\') {
            if (*position >= length) return 0;
            ++*position;
        } else if (c == '"') {
            return 1;
        }
    }
    return 0;
}

static int lvm_skip_balanced(const char *text, size_t length, size_t *position,
                             char open, char close)
{
    unsigned depth = 0;
    while (*position < length) {
        char c = text[*position];
        if (c == '#') {
            while (*position < length && text[*position] != '\n') ++*position;
            continue;
        }
        if (c == '"') {
            if (!lvm_skip_string(text, length, position)) return 0;
            continue;
        }
        if (c == open) ++depth;
        else if (c == close) {
            if (depth == 0) return 0;
            --depth;
            ++*position;
            if (depth == 0) return 1;
            continue;
        }
        ++*position;
    }
    return 0;
}

static int lvm_skip_value(const char *text, size_t length, size_t *position)
{
    char first;
    if (*position >= length) return 0;
    first = text[*position];
    if (first == '"') return lvm_skip_string(text, length, position);
    if (first == '[') return lvm_skip_balanced(text, length, position, '[', ']');
    if (first == '{') return lvm_skip_balanced(text, length, position, '{', '}');
    while (*position < length && !lvm_is_space(text[*position]) &&
           text[*position] != ',' && text[*position] != ']' &&
           text[*position] != '}')
        ++*position;
    return 1;
}

static int lvm_next_item(const char *text, size_t length, size_t *position,
                         lvm_item *item)
{
    size_t start, after_name;
    lvm_skip(text, length, position);
    if (*position >= length || text[*position] == '}') return 0;
    start = *position;
    while (*position < length && lvm_name_char(text[*position])) ++*position;
    if (*position == start) return -1;
    item->start = start;
    item->name_end = *position;
    item->body_start = 0;
    item->body_end = 0;
    item->is_block = 0;
    item->is_assignment = 0;
    after_name = *position;
    lvm_skip(text, length, position);
    if (*position < length && text[*position] == '=') {
        item->is_assignment = 1;
        ++*position;
        lvm_skip(text, length, position);
        item->body_start = *position;
        if (!lvm_skip_value(text, length, position)) return -1;
        item->body_end = *position;
        item->next = *position;
        return 1;
    }
    if (*position < length && text[*position] == '{') {
        item->is_block = 1;
        item->body_start = *position + 1;
        if (!lvm_skip_balanced(text, length, position, '{', '}')) return -1;
        item->body_end = *position - 1;
        item->next = *position;
        return 1;
    }
    *position = after_name;
    return -1;
}

static int lvm_item_name_equal(const char *text, const lvm_item *item,
                               const char *name)
{
    size_t i = 0;
    while (name[i] && item->start + i < item->name_end &&
           text[item->start + i] == name[i]) ++i;
    return !name[i] && item->start + i == item->name_end;
}

static int lvm_find_block(const char *text, size_t length,
                          size_t start, size_t end, const char *name,
                          size_t *body_start, size_t *body_end)
{
    size_t position = start;
    (void)length;
    while (position < end) {
        size_t item_start = position;
        lvm_item item;
        int result = lvm_next_item(text, end, &position, &item);
        if (result == 0) return 0;
        if (result < 0 || position > end) return -1;
        if (item.is_block && lvm_item_name_equal(text, &item, name)) {
            *body_start = item.body_start;
            *body_end = item.body_end;
            return 1;
        }
        if (position <= item_start) return -1;
    }
    return 0;
}

static int lvm_find_field(const char *text, size_t length,
                          size_t start, size_t end, const char *name,
                          size_t *value_start, size_t *value_end)
{
    size_t position = start;
    (void)length;
    while (position < end) {
        size_t item_start = position;
        lvm_item item;
        int result = lvm_next_item(text, end, &position, &item);
        if (result == 0) return 0;
        if (result < 0 || position > end) return -1;
        if (item.is_assignment && lvm_item_name_equal(text, &item, name)) {
            *value_start = item.body_start;
            *value_end = item.body_end;
            return 1;
        }
        if (position <= item_start) return -1;
    }
    return 0;
}

static int lvm_parse_uint(const char *text, size_t start, size_t end,
                          uint64_t *value)
{
    size_t p = start;
    uint64_t result = 0;
    if (p >= end) return 0;
    while (p < end && text[p] >= '0' && text[p] <= '9') {
        unsigned digit = (unsigned)(text[p++] - '0');
        if (result > (UINT64_MAX - digit) / 10) return 0;
        result = result * 10 + digit;
    }
    if (p != end) return 0;
    *value = result;
    return 1;
}

static int lvm_get_uint(const char *text, size_t length,
                        size_t start, size_t end, const char *name,
                        uint64_t *value)
{
    size_t value_start, value_end;
    int result = lvm_find_field(text, length, start, end, name,
                                &value_start, &value_end);
    if (result <= 0) return result;
    return lvm_parse_uint(text, value_start, value_end, value) ? 1 : -1;
}

static int lvm_get_string(const char *text, size_t length,
                          size_t start, size_t end, const char *name,
                          char *out, size_t capacity)
{
    size_t value_start, value_end, i, n;
    int result = lvm_find_field(text, length, start, end, name,
                                &value_start, &value_end);
    if (result <= 0) return result;
    if (value_end - value_start < 2 || text[value_start] != '"' ||
        text[value_end - 1] != '"') return -1;
    n = value_end - value_start - 2;
    if (n == 0 || n >= capacity) return -1;
    for (i = 0; i < n; ++i)
        if (text[value_start + 1 + i] == '\\' || text[value_start + 1 + i] == '"')
            return -1;
    lvm_copy(out, text + value_start + 1, n);
    return 1;
}

static int lvm_array_has(const char *text, size_t start, size_t end,
                         const char *wanted)
{
    size_t p = start;
    size_t wanted_length = 0;
    while (wanted[wanted_length]) ++wanted_length;
    if (p >= end || text[p] != '[' || text[end - 1] != ']') return -1;
    ++p;
    while (p + 1 < end) {
        size_t begin, n, q;
        lvm_skip(text, end, &p);
        if (p >= end - 1) return 0;
        if (text[p] == ',') { ++p; continue; }
        if (text[p] != '"') return -1;
        begin = ++p;
        q = p;
        while (q < end && text[q] != '"') {
            if (text[q] == '\\') return -1;
            ++q;
        }
        if (q >= end) return -1;
        n = q - begin;
        if (n == 0 && wanted[0] == '\0') return 1;
        if (n == wanted_length && n != 0 && text[begin] == wanted[0]) {
            size_t i;
            for (i = 0; i < n && text[begin + i] == wanted[i]; ++i) {}
            if (i == n && wanted[n] == '\0') return 1;
        }
        p = q + 1;
    }
    return 0;
}

static int lvm_find_pv(const ml_lvm_vg *vg, const char *name)
{
    uint32_t i;
    for (i = 0; i < vg->pv_count; ++i)
        if (lvm_equal(vg->pvs[i].name, name)) return (int)i;
    return -1;
}

static int lvm_find_discovered(const lvm_discovered_pv *pvs, size_t count,
                               const char *id)
{
    size_t i;
    for (i = 0; i < count; ++i)
        if (lvm_id_equal(pvs[i].id, id)) return (int)i;
    return -1;
}

static int lvm_parse_stripes(const char *text, size_t start, size_t end,
                            char names[ML_LVM_MAX_STRIPES][ML_LVM_NAME_MAX],
                            uint64_t starts[ML_LVM_MAX_STRIPES],
                            uint32_t expected_count)
{
    size_t p = start;
    uint32_t i;
    if (p >= end || text[p] != '[' || text[end - 1] != ']') return 0;
    ++p;
    for (i = 0; i < expected_count; ++i) {
        size_t name_start, name_end, name_length;
        uint64_t value;
        lvm_skip(text, end, &p);
        if (p < end && text[p] == ',') { ++p; lvm_skip(text, end, &p); }
        if (p >= end || text[p++] != '"') return 0;
        name_start = p;
        while (p < end && text[p] != '"') {
            if (text[p] == '\\') return 0;
            ++p;
        }
        if (p >= end) return 0;
        name_end = p++;
        name_length = name_end - name_start;
        if (name_length == 0 || name_length >= ML_LVM_NAME_MAX) return 0;
        lvm_copy(names[i], text + name_start, name_length);
        lvm_skip(text, end, &p);
        if (p < end && text[p] == ',') { ++p; lvm_skip(text, end, &p); }
        {
            size_t nstart = p;
            while (p < end && text[p] >= '0' && text[p] <= '9') ++p;
            if (!lvm_parse_uint(text, nstart, p, &value)) return 0;
        }
        starts[i] = value;
        lvm_skip(text, end, &p);
        if (i + 1 < expected_count) {
            if (p >= end || text[p++] != ',') return 0;
        }
    }
    lvm_skip(text, end, &p);
    if (p < end && text[p] == ',') { ++p; lvm_skip(text, end, &p); }
    return p + 1 == end && text[p] == ']';
}

static int lvm_parse_pvs(ml_lvm_vg *vg, const lvm_discovered_pv *sources,
                         size_t source_count, const char *text, size_t length,
                         size_t vg_start, size_t vg_end)
{
    size_t section_start, section_end, position;
    int result = lvm_find_block(text, length, vg_start, vg_end,
                                "physical_volumes", &section_start, &section_end);
    if (result != 1) return 0;
    position = section_start;
    while (position < section_end) {
        size_t item_start = position;
        lvm_item item;
        char id[ML_LVM_ID_MAX], name[ML_LVM_NAME_MAX];
        uint64_t pe_start;
        int item_result = lvm_next_item(text, section_end, &position, &item);
        if (item_result == 0) break;
        if (item_result < 0) return 0;
        if (!item.is_block) continue;
        if (vg->pv_count == ML_LVM_MAX_PVS ||
            item.name_end - item.start >= ML_LVM_NAME_MAX)
            return 0;
        lvm_copy(name, text + item.start, item.name_end - item.start);
        if (lvm_get_string(text, length, item.body_start, item.body_end,
                           "id", id, sizeof(id)) != 1 ||
            lvm_get_uint(text, length, item.body_start, item.body_end,
                         "pe_start", &pe_start) != 1 ||
            !lvm_valid_text_id(id))
            return 0;
        if (lvm_find_pv(vg, name) >= 0) return 0;
        lvm_copy(vg->pvs[vg->pv_count].name, name, item.name_end - item.start);
        lvm_copy(vg->pvs[vg->pv_count].uuid, id, sizeof(id) - 1);
        vg->pvs[vg->pv_count].pe_start_sectors = pe_start;
        {
            int source = lvm_find_discovered(sources, source_count, id);
            vg->pvs[vg->pv_count].device = source >= 0 ? sources[source].device : NULL;
        }
        vg->pv_count++;
        if (position <= item_start) return 0;
    }
    return vg->pv_count != 0;
}

static ml_lvm_result lvm_parse_lv(ml_lvm_vg *vg, const char *text, size_t length,
                                  const char *name, size_t start, size_t end,
                                  const char **message)
{
    ml_lvm_lv *lv;
    uint64_t segments, expected_start = 0, extent_bytes;
    size_t status_start, status_end, segment_start, segment_end;
    uint32_t i;
    int result;
    result = lvm_find_field(text, length, start, end, "status",
                            &status_start, &status_end);
    if (result != 1) return lvm_fail(ML_LVM_BAD_FORMAT, message,
                                     "LVM LV has no status list");
    result = lvm_array_has(text, status_start, status_end, "VISIBLE");
    if (result < 0) return lvm_fail(ML_LVM_BAD_FORMAT, message,
                                    "invalid LVM LV status list");
    if (!result) return ML_LVM_OK;
    if (vg->lv_count == ML_LVM_MAX_LVS || name[0] == '\0')
        return lvm_fail(ML_LVM_UNSUPPORTED, message,
                        "LVM group has too many logical volumes");
    for (i = 0; i < vg->lv_count; ++i)
        if (lvm_equal(vg->lvs[i].name, name))
            return lvm_fail(ML_LVM_BAD_FORMAT, message,
                            "duplicate LVM logical volume name");
    lv = &vg->lvs[vg->lv_count];
    {
        size_t n = 0;
        while (name[n] && n + 1 < sizeof(lv->name)) { lv->name[n] = name[n]; ++n; }
        if (name[n]) return lvm_fail(ML_LVM_UNSUPPORTED, message,
                                     "LVM logical volume name is too long");
        lv->name[n] = '\0';
    }
    result = lvm_get_uint(text, length, start, end, "segment_count", &segments);
    if (result != 1 || segments == 0 || segments > ML_LVM_MAX_SEGMENTS)
        return lvm_fail(ML_LVM_UNSUPPORTED, message,
                        "unsupported LVM logical volume segment count");
    if (!lvm_mul64(vg->extent_size_sectors, LVM_SECTOR_BYTES, &extent_bytes))
        return lvm_fail(ML_LVM_BAD_FORMAT, message, "LVM extent size overflow");
    lv->extent_size_sectors = vg->extent_size_sectors;
    lv->owner = vg;
    for (i = 0; i < (uint32_t)segments; ++i) {
        char segment_name[24];
        size_t p = 0;
        uint32_t x = i + 1, digits = 0, j;
        uint64_t start_extent, extent_count, stripe_count = 1, stripe_size = 0;
        uint64_t segment_size_bytes;
        char type[32], stripe_names[ML_LVM_MAX_STRIPES][ML_LVM_NAME_MAX];
        uint64_t stripe_starts[ML_LVM_MAX_STRIPES];
        size_t stripe_field_start, stripe_field_end;
        ml_lvm_segment *segment = &lv->segments[i];
        while (x) { digits++; x /= 10; }
        x = i + 1;
        for (j = 0; j < digits; ++j) { segment_name[digits - j - 1] = (char)('0' + x % 10); x /= 10; }
        p = digits;
        segment_name[p] = '\0';
        {
            char full_name[24];
            size_t k = 0;
            full_name[k++] = 's'; full_name[k++] = 'e'; full_name[k++] = 'g';
            full_name[k++] = 'm'; full_name[k++] = 'e'; full_name[k++] = 'n';
            full_name[k++] = 't';
            for (j = 0; j < digits; ++j) full_name[k++] = segment_name[j];
            full_name[k] = '\0';
            result = lvm_find_block(text, length, start, end, full_name,
                                    &segment_start, &segment_end);
        }
        if (result != 1)
            return lvm_fail(ML_LVM_BAD_FORMAT, message,
                            "LVM segment metadata is missing");
        if (lvm_get_uint(text, length, segment_start, segment_end,
                         "start_extent", &start_extent) != 1 ||
            lvm_get_uint(text, length, segment_start, segment_end,
                         "extent_count", &extent_count) != 1 ||
            lvm_get_string(text, length, segment_start, segment_end,
                           "type", type, sizeof(type)) != 1 ||
            extent_count == 0 || start_extent != expected_start)
            return lvm_fail(ML_LVM_BAD_FORMAT, message,
                            "invalid LVM segment extent range");
        if (!lvm_equal(type, "striped") && !lvm_equal(type, "linear"))
            return lvm_fail(ML_LVM_UNSUPPORTED, message,
                            "LVM logical volume uses a non-linear/non-striped segment");
        if (lvm_equal(type, "striped")) {
            if (lvm_get_uint(text, length, segment_start, segment_end,
                             "stripe_count", &stripe_count) != 1 ||
                stripe_count == 0 || stripe_count > ML_LVM_MAX_STRIPES)
                return lvm_fail(ML_LVM_UNSUPPORTED, message,
                                "unsupported LVM stripe count");
        }
        if (stripe_count > 1 &&
            (lvm_get_uint(text, length, segment_start, segment_end,
                          "stripe_size", &stripe_size) != 1 || stripe_size == 0 ||
             stripe_size > vg->extent_size_sectors))
            return lvm_fail(ML_LVM_UNSUPPORTED, message,
                            "invalid LVM stripe size");
        if (lvm_find_field(text, length, segment_start, segment_end, "stripes",
                           &stripe_field_start, &stripe_field_end) != 1 ||
            !lvm_parse_stripes(text, stripe_field_start, stripe_field_end,
                               stripe_names, stripe_starts, (uint32_t)stripe_count))
            return lvm_fail(ML_LVM_BAD_FORMAT, message,
                            "invalid LVM stripe map");
        if (!lvm_mul64(extent_count, extent_bytes, &segment_size_bytes))
            return lvm_fail(ML_LVM_BAD_FORMAT, message,
                            "LVM segment size overflow");
        if (start_extent > UINT64_MAX - extent_count ||
            expected_start > UINT64_MAX - extent_count ||
            lv->size_bytes > UINT64_MAX - segment_size_bytes)
            return lvm_fail(ML_LVM_BAD_FORMAT, message,
                            "LVM logical volume size overflow");
        segment->start_extent = start_extent;
        segment->extent_count = extent_count;
        segment->stripe_count = (uint32_t)stripe_count;
        if (!lvm_mul64(stripe_size, LVM_SECTOR_BYTES, &segment->stripe_size_bytes))
            return lvm_fail(ML_LVM_BAD_FORMAT, message,
                            "LVM stripe size overflow");
        for (j = 0; j < segment->stripe_count; ++j) {
            int pv_index = lvm_find_pv(vg, stripe_names[j]);
            if (pv_index < 0 || !vg->pvs[pv_index].device)
                return lvm_fail(ML_LVM_NOT_FOUND, message,
                                "an LVM stripe references an unavailable physical volume");
            segment->pv_index[j] = (uint8_t)pv_index;
            segment->pv_start_extent[j] = stripe_starts[j];
        }
        lv->size_bytes += segment_size_bytes;
        expected_start += extent_count;
    }
    lv->segment_count = (uint32_t)segments;
    vg->lv_count++;
    return ML_LVM_OK;
}

static int lvm_parse_metadata(ml_lvm_vg *vg, const lvm_discovered_pv *sources,
                              size_t source_count, char *text, size_t length,
                              const char **message)
{
    size_t position = 0, root_start = 0, root_end = 0;
    lvm_item root;
    int result;
    result = lvm_next_item(text, length, &position, &root);
    if (result != 1 || !root.is_block)
        return (int)lvm_fail(ML_LVM_BAD_FORMAT, message,
                             "invalid LVM metadata root");
    if (root.name_end - root.start >= sizeof(vg->name))
        return (int)lvm_fail(ML_LVM_UNSUPPORTED, message,
                             "LVM volume group name is too long");
    lvm_copy(vg->name, text + root.start, root.name_end - root.start);
    root_start = root.body_start;
    root_end = root.body_end;
    result = lvm_get_string(text, length, root_start, root_end, "id",
                            vg->uuid, sizeof(vg->uuid));
    if (result != 1 || !lvm_valid_text_id(vg->uuid))
        return (int)lvm_fail(ML_LVM_BAD_FORMAT, message,
                             "invalid LVM volume group identifier");
    result = lvm_get_uint(text, length, root_start, root_end, "extent_size",
                          &vg->extent_size_sectors);
    if (result != 1 || vg->extent_size_sectors == 0)
        return (int)lvm_fail(ML_LVM_BAD_FORMAT, message,
                             "invalid LVM volume group extent size");
    if (!lvm_parse_pvs(vg, sources, source_count, text, length,
                       root_start, root_end))
        return (int)lvm_fail(ML_LVM_BAD_FORMAT, message,
                             "invalid LVM physical volume metadata");
    {
        size_t lvs_start, lvs_end, p = 0;
        result = lvm_find_block(text, length, root_start, root_end,
                                "logical_volumes", &lvs_start, &lvs_end);
        if (result != 1)
            return (int)lvm_fail(ML_LVM_BAD_FORMAT, message,
                                 "LVM logical volume metadata is missing");
        while (p < lvs_end) {
            size_t before = lvs_start + p;
            size_t current = before;
            lvm_item item;
            int item_result = lvm_next_item(text, lvs_end, &current, &item);
            if (item_result == 0) break;
            if (item_result < 0)
                return (int)lvm_fail(ML_LVM_BAD_FORMAT, message,
                                     "invalid LVM logical volume section");
            if (item.is_block) {
                char lv_name[ML_LVM_NAME_MAX];
                size_t n = item.name_end - item.start;
                ml_lvm_result lv_result;
                if (n == 0 || n >= sizeof(lv_name))
                    return (int)lvm_fail(ML_LVM_UNSUPPORTED, message,
                                         "LVM logical volume name is too long");
                lvm_copy(lv_name, text + item.start, n);
                lv_result = lvm_parse_lv(vg, text, length, lv_name,
                                         item.body_start, item.body_end, message);
                if (lv_result != ML_LVM_OK) return (int)lv_result;
            }
            p = current - lvs_start;
            if (current <= before)
                return (int)lvm_fail(ML_LVM_BAD_FORMAT, message,
                                     "invalid LVM logical volume layout");
        }
    }
    return vg->lv_count != 0;
}

static int lvm_read_metadata(const lvm_discovered_pv *pv, void *scratch,
                             size_t scratch_size, char **metadata,
                             size_t *metadata_size, const char **message)
{
    uint8_t *area = (uint8_t *)scratch;
    uint8_t header[LVM_MDA_HEADER_BYTES];
    uint64_t area_size = pv->mda_size, text_offset, text_size;
    size_t header_read = sizeof(header), first_size, rest_size;
    char *out;
    if (area_size > ML_LVM_MAX_MDA_BYTES || area_size > scratch_size / 2 ||
        area_size < LVM_MDA_HEADER_BYTES)
        return (int)lvm_fail(ML_LVM_UNSUPPORTED, message,
                             "LVM metadata area exceeds the configured limit");
    if (ml_block_read(pv->device, pv->mda_offset, header, header_read) != ML_BLOCK_OK)
        return (int)lvm_fail(ML_LVM_IO, message, "cannot read LVM metadata header");
    if (lvm_le32(header + 20) != 1 || lvm_le64(header + 24) != pv->mda_offset ||
        lvm_le64(header + 32) != area_size ||
        header[4] != LVM_MDA_MAGIC[0] || header[5] != LVM_MDA_MAGIC[1] ||
        header[6] != LVM_MDA_MAGIC[2] || header[7] != LVM_MDA_MAGIC[3] ||
        header[8] != LVM_MDA_MAGIC[4] || header[9] != LVM_MDA_MAGIC[5] ||
        header[10] != LVM_MDA_MAGIC[6] || header[11] != LVM_MDA_MAGIC[7] ||
        header[12] != LVM_MDA_MAGIC[8] || header[13] != LVM_MDA_MAGIC[9] ||
        header[14] != LVM_MDA_MAGIC[10] || header[15] != LVM_MDA_MAGIC[11] ||
        header[16] != LVM_MDA_MAGIC[12] || header[17] != LVM_MDA_MAGIC[13] ||
        header[18] != LVM_MDA_MAGIC[14] || header[19] != LVM_MDA_MAGIC[15])
        return (int)lvm_fail(ML_LVM_BAD_FORMAT, message,
                             "invalid LVM metadata area header");
    text_offset = lvm_le64(header + 40);
    text_size = lvm_le64(header + 48);
    if (text_offset < LVM_MDA_HEADER_BYTES || text_offset >= area_size ||
        text_size == 0 || text_size > area_size ||
        text_size > UINT64_MAX - text_offset ||
        text_size > scratch_size - (size_t)area_size -
                    ML_LVM_SCAN_SCRATCH_BYTES - 1)
        return (int)lvm_fail(ML_LVM_BAD_FORMAT, message,
                             "invalid LVM metadata text range");
    if (ml_block_read(pv->device, pv->mda_offset, area,
                      (size_t)area_size) != ML_BLOCK_OK)
        return (int)lvm_fail(ML_LVM_IO, message,
                             "cannot read LVM metadata area");
    out = (char *)(area + area_size);
    if (text_offset + text_size <= area_size) {
        first_size = (size_t)text_size;
        lvm_copy_bytes((uint8_t *)out, area + (size_t)text_offset, first_size);
    } else {
        first_size = (size_t)(area_size - text_offset);
        rest_size = (size_t)text_size - first_size;
        if (rest_size > area_size - LVM_MDA_HEADER_BYTES)
            return (int)lvm_fail(ML_LVM_BAD_FORMAT, message,
                                 "LVM circular metadata range is invalid");
        lvm_copy_bytes((uint8_t *)out, area + (size_t)text_offset, first_size);
        lvm_copy_bytes((uint8_t *)out + first_size,
                       area + LVM_MDA_HEADER_BYTES, rest_size);
    }
    if (text_size > SIZE_MAX - 1 || (uint64_t)pv->mda_offset > UINT64_MAX - text_offset)
        return (int)lvm_fail(ML_LVM_BAD_FORMAT, message,
                             "LVM metadata size overflow");
    out[(size_t)text_size] = '\0';
    *metadata = out;
    *metadata_size = (size_t)text_size;
    return 1;
}

static int lvm_map_read(void *context, uint64_t offset,
                        void *buffer, size_t length)
{
    ml_lvm_lv *lv = (ml_lvm_lv *)context;
    uint8_t *out = (uint8_t *)buffer;
    size_t done = 0;
    uint64_t extent_bytes;
    const ml_lvm_vg *vg;
    if (!lv || !lv->owner || (!buffer && length != 0) ||
        !lvm_mul64(lv->extent_size_sectors, LVM_SECTOR_BYTES, &extent_bytes))
        return -1;
    vg = lv->owner;
    while (done < length) {
        uint64_t at = offset + done;
        uint64_t segment_start = 0, segment_size = 0, local;
        uint32_t i;
        const ml_lvm_segment *segment = NULL;
        uint32_t stripe;
        uint64_t stripe_row = 0, stripe_offset = 0, physical, pe_start_bytes;
        size_t amount;
        const ml_lvm_pv *pv;
        if (at < offset) return -1;
        for (i = 0; i < lv->segment_count; ++i) {
            if (!lvm_mul64(lv->segments[i].start_extent, extent_bytes,
                           &segment_start) ||
                !lvm_mul64(lv->segments[i].extent_count, extent_bytes,
                           &segment_size))
                return -1;
            if (at >= segment_start && at - segment_start < segment_size) {
                segment = &lv->segments[i];
                break;
            }
        }
        if (!segment) return -1;
        local = at - segment_start;
        stripe = 0;
        if (segment->stripe_count == 0 || segment->stripe_count > ML_LVM_MAX_STRIPES)
            return -1;
        if (segment->stripe_count == 1) {
            amount = length - done;
            if ((uint64_t)amount > segment_size - local)
                amount = (size_t)(segment_size - local);
        } else {
            uint64_t stripe_group;
            uint64_t stripe_remaining;
            if (segment->stripe_size_bytes == 0 ||
                !lvm_mul64(segment->stripe_size_bytes, segment->stripe_count,
                           &stripe_group))
                return -1;
            stripe = (uint32_t)((local / segment->stripe_size_bytes) %
                                segment->stripe_count);
            stripe_row = (local / stripe_group) * segment->stripe_size_bytes;
            stripe_offset = local % segment->stripe_size_bytes;
            stripe_remaining = segment->stripe_size_bytes - stripe_offset;
            amount = stripe_remaining > length - done
                ? length - done : (size_t)stripe_remaining;
            if ((uint64_t)amount > segment_size - local)
                amount = (size_t)(segment_size - local);
        }
        if (segment->pv_index[stripe] >= vg->pv_count) return -1;
        pv = &vg->pvs[segment->pv_index[stripe]];
        if (!pv->device ||
            !lvm_mul64(pv->pe_start_sectors, LVM_SECTOR_BYTES, &pe_start_bytes))
            return -1;
        if (!lvm_mul64(segment->pv_start_extent[stripe], extent_bytes,
                       &physical) || physical > UINT64_MAX - pe_start_bytes)
            return -1;
        physical += pe_start_bytes;
        if (segment->stripe_count == 1) {
            if (physical > UINT64_MAX - local) return -1;
            physical += local;
        } else {
            if (physical > UINT64_MAX - stripe_row ||
                physical + stripe_row > UINT64_MAX - stripe_offset)
                return -1;
            physical += stripe_row + stripe_offset;
        }
        if (ml_block_read(pv->device, physical, out + done, amount) != ML_BLOCK_OK)
            return -1;
        done += amount;
    }
    return 0;
}

ml_lvm_result ml_lvm_scan_all(ml_lvm_vg *vgs, size_t vg_capacity,
                              size_t *vg_count,
                              const ml_block_device *const *devices,
                              size_t device_count,
                              void *scratch, size_t scratch_size,
                              const char **message)
{
    lvm_discovered_pv *sources;
    uint8_t *visited;
    size_t source_count = 0, i;
    size_t count = 0;
    const char *first_error = NULL;
    ml_lvm_result first_failure = ML_LVM_BAD_FORMAT;
    uint8_t *scratch_bytes = (uint8_t *)scratch;
    if (message) *message = NULL;
    if (vg_count) *vg_count = 0;
    if (!vgs || vg_capacity == 0 ||
        vg_capacity > SIZE_MAX / sizeof(*vgs) || !vg_count ||
        (!devices && device_count) || !scratch)
        return lvm_fail(ML_LVM_INVALID, message, "invalid LVM scan arguments");
    if (scratch_size < ML_LVM_SCRATCH_BYTES)
        return lvm_fail(ML_LVM_RANGE, message,
                        "LVM metadata scratch buffer is too small");
    sources = (lvm_discovered_pv *)(scratch_bytes +
                                    2u * ML_LVM_MAX_MDA_BYTES + 8u);
    visited = (uint8_t *)(sources + ML_LVM_MAX_SCAN_PVS);
    if ((size_t)((uint8_t *)visited - scratch_bytes) +
        ML_LVM_MAX_SCAN_PVS > scratch_size)
        return lvm_fail(ML_LVM_RANGE, message,
                        "LVM scan scratch buffer is too small");
    lvm_zero(vgs, vg_capacity * sizeof(*vgs));
    lvm_zero(sources, ML_LVM_MAX_SCAN_PVS * sizeof(*sources));
    lvm_zero(visited, ML_LVM_MAX_SCAN_PVS);
    for (i = 0; i < device_count; ++i) {
        lvm_discovered_pv discovered;
        int result;
        if (!devices[i] || !devices[i]->read_at) continue;
        result = lvm_locate_pv(devices[i], &discovered, message);
        if (result < 0) return ML_LVM_BAD_FORMAT;
        if (result == 0) continue;
        if (source_count == ML_LVM_MAX_SCAN_PVS)
            return lvm_fail(ML_LVM_UNSUPPORTED, message,
                            "too many LVM physical volume devices to scan");
        {
            int duplicate = lvm_find_discovered(sources, source_count,
                                                discovered.id);
            if (duplicate >= 0) {
                if (sources[duplicate].device != discovered.device)
                    return lvm_fail(ML_LVM_AMBIGUOUS, message,
                                    "duplicate LVM PV identifiers were found");
                continue;
            }
        }
        sources[source_count] = discovered;
        source_count++;
    }
    if (source_count == 0)
        return lvm_fail(ML_LVM_NOT_FOUND, message, "no LVM2 physical volumes found");
    for (i = 0; i < source_count; ++i) {
        char *metadata = NULL;
        size_t metadata_size = 0;
        int read_result;
        int parse_result;
        size_t j;
        if (visited[i]) continue;
        read_result = lvm_read_metadata(&sources[i], scratch, scratch_size,
                                       &metadata, &metadata_size, message);
        if (read_result < 0) {
            if (!first_error) {
                if (message) first_error = *message;
                first_failure = (ml_lvm_result)read_result;
            }
            continue;
        }
        if (read_result == 0) continue;
        if (count >= vg_capacity)
            return lvm_fail(ML_LVM_UNSUPPORTED, message,
                            "too many LVM volume groups");
        parse_result = lvm_parse_metadata(&vgs[count], sources, source_count,
                                          metadata, metadata_size, message);
        if (parse_result <= 0) {
            if (!first_error) {
                if (message) first_error = *message;
                first_failure = parse_result < 0
                    ? (ml_lvm_result)parse_result : ML_LVM_BAD_FORMAT;
            }
            lvm_zero(&vgs[count], sizeof(vgs[count]));
            visited[i] = 1;
            continue;
        }
        visited[i] = 1;
        for (j = 0; j < vgs[count].pv_count; ++j) {
            int source = lvm_find_discovered(sources, source_count,
                                             vgs[count].pvs[j].uuid);
            if (source >= 0) visited[source] = 1;
        }
        for (j = 0; j < vgs[count].lv_count; ++j) {
            vgs[count].lvs[j].owner = &vgs[count];
            vgs[count].lvs[j].device.read_at = lvm_map_read;
            vgs[count].lvs[j].device.context = &vgs[count].lvs[j];
            vgs[count].lvs[j].device.byte_size = vgs[count].lvs[j].size_bytes;
            vgs[count].lvs[j].device.logical_block_size = LVM_SECTOR_BYTES;
        }
        count++;
    }
    *vg_count = count;
    if (count == 0)
        return lvm_fail(first_failure, message,
                        first_error ? first_error : "no valid LVM metadata area found");
    if (message) *message = NULL;
    return ML_LVM_OK;
}

ml_lvm_result ml_lvm_scan(ml_lvm_vg *vg,
                          const ml_block_device *const *devices,
                          size_t device_count,
                          void *scratch, size_t scratch_size,
                          const char **message)
{
    size_t count = 0;
    ml_lvm_result result = ml_lvm_scan_all(vg, 1, &count, devices, device_count,
                                           scratch, scratch_size, message);
    if (result != ML_LVM_OK) return result;
    return count == 1 ? ML_LVM_OK
        : lvm_fail(ML_LVM_UNSUPPORTED, message,
                   "multiple LVM volume groups need the scan_all interface");
}

const ml_lvm_lv *ml_lvm_find_lv(const ml_lvm_vg *vg, const char *name)
{
    uint32_t i, matches = 0;
    const ml_lvm_lv *match = NULL;
    if (!vg || !name) return NULL;
    for (i = 0; i < vg->lv_count; ++i) {
        if (lvm_equal(vg->lvs[i].name, name)) {
            match = &vg->lvs[i];
            matches++;
        }
    }
    return matches == 1 ? match : NULL;
}
