/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef ML_CONFIG_H
#define ML_CONFIG_H

#include <stddef.h>
#include <stdint.h>

#define ML_MAX_ENTRIES 32
#define ML_NAME_MAX 64
#define ML_VALUE_MAX 512
#define ML_UUID_MAX 64
#define ML_CONFIG_MAX_BYTES (64u * 1024u)

typedef enum {
    ML_ENTRY_LINUX = 1,
    ML_ENTRY_EFI = 2
} ml_entry_type;

typedef struct {
    char name[ML_NAME_MAX];
    char fs_uuid[ML_UUID_MAX];
    char kernel[ML_VALUE_MAX];
    char initrd[ML_VALUE_MAX];
    char cmdline[ML_VALUE_MAX];
    char path[ML_VALUE_MAX];
    ml_entry_type type;
    uint32_t present;
} ml_entry;

typedef struct {
    uint32_t timeout_seconds;
    int default_index;
    size_t entry_count;
    ml_entry entries[ML_MAX_ENTRIES];
} ml_config;

typedef struct {
    size_t line;
    char message[128];
} ml_config_error;

int ml_config_parse(const char *data, size_t length, ml_config *out,
                    ml_config_error *error);

#endif
