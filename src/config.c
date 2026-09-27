/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "ml_config.h"

#define GLOBAL_TIMEOUT 0x01u
#define GLOBAL_DEFAULT 0x02u
#define FIELD_TYPE 0x01u
#define FIELD_FS_UUID 0x02u
#define FIELD_KERNEL 0x04u
#define FIELD_INITRD 0x08u
#define FIELD_CMDLINE 0x10u
#define FIELD_PATH 0x20u
#define LINE_MAX 1024u

static size_t s_len(const char *s)
{
    size_t n = 0;
    while (s[n] != '\0') n++;
    return n;
}

static int s_eq(const char *a, const char *b)
{
    size_t i = 0;
    while (a[i] && b[i] && a[i] == b[i]) i++;
    return a[i] == b[i];
}

static void s_copy(char *dst, size_t capacity, const char *src, size_t n)
{
    size_t i;
    if (capacity == 0) return;
    if (n >= capacity) n = capacity - 1;
    for (i = 0; i < n; ++i) dst[i] = src[i];
    dst[n] = '\0';
}

static void zero_bytes(void *ptr, size_t n)
{
    unsigned char *p = (unsigned char *)ptr;
    while (n--) *p++ = 0;
}

static char *trim(char *s)
{
    char *end;
    while (*s == ' ' || *s == '\t') s++;
    end = s + s_len(s);
    while (end > s && (end[-1] == ' ' || end[-1] == '\t')) end--;
    *end = '\0';
    return s;
}

static int set_error(ml_config_error *error, size_t line, const char *message)
{
    if (error) {
        error->line = line;
        s_copy(error->message, sizeof(error->message), message, s_len(message));
    }
    return 0;
}

static int parse_u32(const char *s, uint32_t *result)
{
    uint32_t n = 0;
    size_t i;
    if (!*s) return 0;
    for (i = 0; s[i]; ++i) {
        uint32_t digit;
        if (s[i] < '0' || s[i] > '9') return 0;
        digit = (uint32_t)(s[i] - '0');
        if (n > (UINT32_MAX - digit) / 10) return 0;
        n = n * 10 + digit;
    }
    *result = n;
    return 1;
}

static int set_value(char *dst, size_t capacity, const char *value)
{
    size_t n = s_len(value);
    if (n == 0 || n >= capacity) return 0;
    s_copy(dst, capacity, value, n);
    return 1;
}

static int find_entry(const ml_config *config, const char *name)
{
    size_t i;
    for (i = 0; i < config->entry_count; ++i)
        if (s_eq(config->entries[i].name, name)) return (int)i;
    return -1;
}

int ml_config_parse(const char *data, size_t length, ml_config *out,
                    ml_config_error *error)
{
    size_t offset = 0, line_no = 0;
    size_t input_index;
    uint32_t global_present = 0;
    char default_name[ML_NAME_MAX] = {0};
    int current = -1;

    if (error) { error->line = 0; error->message[0] = '\0'; }
    if (!data || !out) return set_error(error, 0, "invalid parser arguments");
    if (length > ML_CONFIG_MAX_BYTES) return set_error(error, 0, "configuration exceeds 64 KiB");
    for (input_index = 0; input_index < length; ++input_index) {
        unsigned char byte = (unsigned char)data[input_index];
        if (byte == 0 || byte > 0x7f)
            return set_error(error, 0, "configuration must be ASCII without NUL bytes");
    }
    zero_bytes(out, sizeof(*out));
    out->timeout_seconds = 5;
    out->default_index = -1;

    while (offset < length) {
        char line[LINE_MAX + 1];
        size_t line_length = 0;
        char *text, *equals;

        line_no++;
        while (offset < length && data[offset] != '\n') {
            if (line_length == LINE_MAX) return set_error(error, line_no, "line exceeds 1024 bytes");
            line[line_length++] = data[offset++];
        }
        if (offset < length && data[offset] == '\n') offset++;
        if (line_length && line[line_length - 1] == '\r') line_length--;
        line[line_length] = '\0';
        text = trim(line);
        if (*text == '\0' || *text == '#' || *text == ';') continue;

        if (*text == '[') {
            char *close = text + s_len(text) - 1;
            char *name;
            if (*close != ']') return set_error(error, line_no, "section header must end with ']'");
            *close = '\0';
            name = trim(text + 1);
            if (*name == '\0' || s_len(name) >= ML_NAME_MAX)
                return set_error(error, line_no, "entry name is empty or too long");
            if (out->entry_count == ML_MAX_ENTRIES)
                return set_error(error, line_no, "too many entries (maximum 32)");
            if (find_entry(out, name) >= 0)
                return set_error(error, line_no, "duplicate entry name");
            current = (int)out->entry_count++;
            s_copy(out->entries[current].name, sizeof(out->entries[current].name), name, s_len(name));
            continue;
        }

        equals = text;
        while (*equals && *equals != '=') equals++;
        if (*equals != '=') return set_error(error, line_no, "expected key=value");
        *equals = '\0';
        {
            char *key = trim(text);
            char *value = trim(equals + 1);
            if (*key == '\0' || *value == '\0') return set_error(error, line_no, "key and value must not be empty");

            if (current < 0) {
                if (s_eq(key, "timeout")) {
                    uint32_t timeout;
                    if (global_present & GLOBAL_TIMEOUT) return set_error(error, line_no, "duplicate timeout");
                    if (!parse_u32(value, &timeout) || timeout > 3600)
                        return set_error(error, line_no, "timeout must be between 0 and 3600 seconds");
                    out->timeout_seconds = timeout;
                    global_present |= GLOBAL_TIMEOUT;
                } else if (s_eq(key, "default")) {
                    if (global_present & GLOBAL_DEFAULT) return set_error(error, line_no, "duplicate default");
                    if (s_len(value) >= sizeof(default_name)) return set_error(error, line_no, "default entry name is too long");
                    s_copy(default_name, sizeof(default_name), value, s_len(value));
                    global_present |= GLOBAL_DEFAULT;
                } else {
                    return set_error(error, line_no, "unknown global key");
                }
            } else {
                ml_entry *entry = &out->entries[current];
                uint32_t field;
                char *dst;
                size_t capacity;
                if (s_eq(key, "type")) {
                    field = FIELD_TYPE;
                    dst = NULL; capacity = 0;
                    if (s_eq(value, "linux")) entry->type = ML_ENTRY_LINUX;
                    else if (s_eq(value, "efi")) entry->type = ML_ENTRY_EFI;
                    else return set_error(error, line_no, "type must be linux or efi");
                } else if (s_eq(key, "fs_uuid")) {
                    field = FIELD_FS_UUID; dst = entry->fs_uuid; capacity = sizeof(entry->fs_uuid);
                } else if (s_eq(key, "kernel")) {
                    field = FIELD_KERNEL; dst = entry->kernel; capacity = sizeof(entry->kernel);
                } else if (s_eq(key, "initrd")) {
                    field = FIELD_INITRD; dst = entry->initrd; capacity = sizeof(entry->initrd);
                } else if (s_eq(key, "cmdline")) {
                    field = FIELD_CMDLINE; dst = entry->cmdline; capacity = sizeof(entry->cmdline);
                } else if (s_eq(key, "path")) {
                    field = FIELD_PATH; dst = entry->path; capacity = sizeof(entry->path);
                } else {
                    return set_error(error, line_no, "unknown entry key");
                }
                if (entry->present & field) return set_error(error, line_no, "duplicate entry key");
                if (dst && !set_value(dst, capacity, value))
                    return set_error(error, line_no, "value is too long");
                entry->present |= field;
            }
        }
    }

    if (out->entry_count == 0) return set_error(error, line_no, "configuration has no entries");
    {
        size_t i;
        for (i = 0; i < out->entry_count; ++i) {
            const ml_entry *entry = &out->entries[i];
            if (!(entry->present & FIELD_TYPE) || !(entry->present & FIELD_FS_UUID))
                return set_error(error, line_no, "each entry needs type and fs_uuid");
            if (entry->type == ML_ENTRY_LINUX) {
                if (!(entry->present & FIELD_KERNEL) || !(entry->present & FIELD_INITRD) ||
                    !(entry->present & FIELD_CMDLINE))
                    return set_error(error, line_no, "linux entries need kernel, initrd, and cmdline");
                if (entry->present & FIELD_PATH)
                    return set_error(error, line_no, "linux entries cannot set path");
            } else {
                if (!(entry->present & FIELD_PATH)) return set_error(error, line_no, "efi entries need path");
                if (entry->present & (FIELD_KERNEL | FIELD_INITRD | FIELD_CMDLINE))
                    return set_error(error, line_no, "efi entries only accept path and fs_uuid");
            }
        }
    }
    if (global_present & GLOBAL_DEFAULT) {
        out->default_index = find_entry(out, default_name);
        if (out->default_index < 0) return set_error(error, line_no, "default does not name an entry");
    } else {
        out->default_index = 0;
    }
    return 1;
}
