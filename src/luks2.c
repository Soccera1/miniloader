/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * Bounded read-only LUKS2 reader. The parser accepts LUKS2 metadata with
 * PBKDF2 keyslots, LUKS1 AF stripes, raw XTS key areas, AES-XTS or
 * AES-CBC-ESSIV data segments, and SHA-256 binary-header checksums. It does
 * not modify metadata.
 */
#include "ml_luks2.h"
#include "ml_crypto.h"

#ifndef ML_ENABLE_KDF_PBKDF2
#define ML_ENABLE_KDF_PBKDF2 0
#endif
#ifndef ML_ENABLE_CIPHER_AES_XTS
#define ML_ENABLE_CIPHER_AES_XTS 0
#endif
#ifndef ML_ENABLE_CIPHER_AES_CBC_ESSIV
#define ML_ENABLE_CIPHER_AES_CBC_ESSIV 0
#endif
#ifndef ML_ENABLE_CIPHER_SERPENT_XTS
#define ML_ENABLE_CIPHER_SERPENT_XTS 0
#endif
#ifndef ML_ENABLE_CIPHER_TWOFISH_XTS
#define ML_ENABLE_CIPHER_TWOFISH_XTS 0
#endif
#ifndef ML_ENABLE_KDF_ARGON2ID
#define ML_ENABLE_KDF_ARGON2ID 0
#endif
#ifndef ML_ENABLE_TPM2
#define ML_ENABLE_TPM2 0
#endif

#define LUKS2_HEADER_BYTES 4096u
#define LUKS2_CHECKSUM_OFFSET 448u
#define LUKS2_CHECKSUM_BYTES 32u
#define LUKS2_MAX_ITERATIONS 10000000u
#define LUKS2_MAX_STRIPES 4000u
#define LUKS2_MAX_SLOTS 32u
#define LUKS2_MAX_TOKENS 4096u
#define LUKS2_MAX_ARGON2_MEMORY_KIB 1048576u
#define LUKS2_MAX_ARGON2_TIME 100u
#define LUKS2_MAX_ARGON2_LANES 32u

enum { LUKS2_KDF_PBKDF2 = 1, LUKS2_KDF_ARGON2ID = 2 };

typedef enum {
    JSON_OBJECT = 1,
    JSON_ARRAY,
    JSON_STRING,
    JSON_NUMBER,
    JSON_TRUE,
    JSON_FALSE,
    JSON_NULL
} json_type;

typedef struct {
    uint32_t start;
    uint32_t end;
    uint32_t next;
    uint16_t parent;
    uint8_t type;
} json_token;

typedef struct {
    const uint8_t *text;
    size_t length;
    size_t position;
    json_token *tokens;
    size_t token_capacity;
    size_t token_count;
} json_parser;

typedef struct {
    uint32_t id;
    uint32_t key_bytes;
    uint32_t area_key_bytes;
    uint32_t stripes;
    uint32_t iterations;
    uint32_t argon_time;
    uint32_t argon_memory_kib;
    uint32_t argon_lanes;
    uint64_t area_offset;
    uint64_t area_size;
    ml_hash_algorithm af_hash;
    ml_hash_algorithm kdf_hash;
    uint8_t kdf_type;
    uint8_t salt[64];
    size_t salt_size;
    ml_xts_cipher cipher;
    uint8_t aes_cbc_essiv;
    uint8_t supported;
    uint8_t unsupported_kdf;
} luks2_slot;

typedef struct {
    uint32_t iterations;
    ml_hash_algorithm hash;
    uint8_t salt[64];
    size_t salt_size;
    uint8_t digest[64];
    size_t digest_size;
} luks2_digest;

typedef struct {
    uint64_t offset;
    uint64_t size;
    uint64_t iv_tweak;
    uint32_t sector_size;
    ml_xts_cipher cipher;
    uint8_t aes_cbc_essiv;
} luks2_segment;

static uint16_t be16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static uint64_t be64(const uint8_t *p)
{
    uint64_t value = 0;
    unsigned i;
    for (i = 0; i < 8; ++i) value = (value << 8) | p[i];
    return value;
}

static void secure_zero(void *buffer, size_t size)
{
    volatile uint8_t *p = (volatile uint8_t *)buffer;
    while (size--) *p++ = 0;
}

static int bytes_equal(const uint8_t *a, const uint8_t *b, size_t size)
{
    uint8_t difference = 0;
    size_t i;
    for (i = 0; i < size; ++i) difference |= (uint8_t)(a[i] ^ b[i]);
    return difference == 0;
}

static void skip_space(json_parser *parser)
{
    while (parser->position < parser->length) {
        uint8_t c = parser->text[parser->position];
        if (c != ' ' && c != '\t' && c != '\r' && c != '\n') break;
        ++parser->position;
    }
}

static int hex_digit(uint8_t c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int add_token(json_parser *parser, json_type type, uint32_t start,
                     uint32_t end, uint16_t parent, uint32_t *index)
{
    json_token *token;
    if (parser->token_count >= parser->token_capacity ||
        parser->token_count >= UINT16_MAX)
        return 0;
    *index = (uint32_t)parser->token_count++;
    token = &parser->tokens[*index];
    token->start = start;
    token->end = end;
    token->next = *index + 1;
    token->parent = parent;
    token->type = (uint8_t)type;
    return 1;
}

static int parse_string_token(json_parser *parser, uint16_t parent,
                              uint32_t *index)
{
    size_t start;
    if (parser->position >= parser->length ||
        parser->text[parser->position] != '"') return 0;
    ++parser->position;
    start = parser->position;
    while (parser->position < parser->length) {
        uint8_t c = parser->text[parser->position++];
        if (c == '"') {
            if (start > UINT32_MAX || parser->position - 1 > UINT32_MAX ||
                !add_token(parser, JSON_STRING, (uint32_t)start,
                           (uint32_t)(parser->position - 1), parent, index))
                return 0;
            return 1;
        }
        if (c < 0x20) return 0;
        if (c == '\\') {
            uint8_t escape;
            unsigned j;
            if (parser->position >= parser->length) return 0;
            escape = parser->text[parser->position++];
            if (escape == '"' || escape == '\\' || escape == '/' ||
                escape == 'b' || escape == 'f' || escape == 'n' ||
                escape == 'r' || escape == 't') continue;
            if (escape != 'u' || parser->length - parser->position < 4)
                return 0;
            for (j = 0; j < 4; ++j)
                if (hex_digit(parser->text[parser->position++]) < 0) return 0;
        }
    }
    return 0;
}

static int parse_value(json_parser *parser, uint16_t parent, unsigned depth,
                       uint32_t *index)
{
    size_t start;
    uint32_t current;
    if (depth > 16) return 0;
    skip_space(parser);
    if (parser->position >= parser->length) return 0;
    if (parser->text[parser->position] == '"')
        return parse_string_token(parser, parent, index);

    start = parser->position;
    if (parser->text[start] == '{' || parser->text[start] == '[') {
        uint8_t open = parser->text[start];
        uint8_t close = open == '{' ? '}' : ']';
        json_type type = open == '{' ? JSON_OBJECT : JSON_ARRAY;
        if (start > UINT32_MAX ||
            !add_token(parser, type, (uint32_t)start, 0, parent, &current))
            return 0;
        *index = current;
        ++parser->position;
        skip_space(parser);
        if (parser->position < parser->length &&
            parser->text[parser->position] == close) {
            ++parser->position;
        } else {
            for (;;) {
                uint32_t child;
                if (type == JSON_OBJECT) {
                    if (!parse_string_token(parser, (uint16_t)current, &child))
                        return 0;
                    skip_space(parser);
                    if (parser->position >= parser->length ||
                        parser->text[parser->position++] != ':') return 0;
                    if (!parse_value(parser, (uint16_t)current, depth + 1,
                                     &child)) return 0;
                } else if (!parse_value(parser, (uint16_t)current,
                                        depth + 1, &child)) {
                    return 0;
                }
                skip_space(parser);
                if (parser->position >= parser->length) return 0;
                if (parser->text[parser->position] == close) {
                    ++parser->position;
                    break;
                }
                if (parser->text[parser->position++] != ',') return 0;
                skip_space(parser);
            }
        }
        if (parser->position > UINT32_MAX) return 0;
        parser->tokens[current].end = (uint32_t)parser->position;
        parser->tokens[current].next = (uint32_t)parser->token_count;
        return 1;
    }

    while (parser->position < parser->length) {
        uint8_t c = parser->text[parser->position];
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n' ||
            c == ',' || c == ']' || c == '}') break;
        ++parser->position;
    }
    if (parser->position == start || parser->position > UINT32_MAX) return 0;
    {
        size_t n = parser->position - start;
        const uint8_t *p = parser->text + start;
        json_type type;
        size_t i = 0;
        if (n == 4 && p[0] == 't' && p[1] == 'r' && p[2] == 'u' && p[3] == 'e')
            type = JSON_TRUE;
        else if (n == 5 && p[0] == 'f' && p[1] == 'a' && p[2] == 'l' &&
                 p[3] == 's' && p[4] == 'e')
            type = JSON_FALSE;
        else if (n == 4 && p[0] == 'n' && p[1] == 'u' && p[2] == 'l' && p[3] == 'l')
            type = JSON_NULL;
        else {
            type = JSON_NUMBER;
            if (p[i] == '-') ++i;
            if (i == n) return 0;
            if (p[i] == '0') ++i;
            else {
                if (p[i] < '1' || p[i] > '9') return 0;
                while (i < n && p[i] >= '0' && p[i] <= '9') ++i;
            }
            if (i < n && p[i] == '.') {
                ++i;
                if (i == n || p[i] < '0' || p[i] > '9') return 0;
                while (i < n && p[i] >= '0' && p[i] <= '9') ++i;
            }
            if (i < n && (p[i] == 'e' || p[i] == 'E')) {
                ++i;
                if (i < n && (p[i] == '+' || p[i] == '-')) ++i;
                if (i == n || p[i] < '0' || p[i] > '9') return 0;
                while (i < n && p[i] >= '0' && p[i] <= '9') ++i;
            }
            if (i != n) return 0;
        }
        if (!add_token(parser, type, (uint32_t)start,
                       (uint32_t)parser->position, parent, index)) return 0;
    }
    return 1;
}

static int parse_json(json_parser *parser, const uint8_t *text, size_t length,
                      json_token *tokens, size_t token_capacity,
                      uint32_t *root)
{
    uint32_t value;
    parser->text = text;
    parser->length = length;
    parser->position = 0;
    parser->tokens = tokens;
    parser->token_capacity = token_capacity;
    parser->token_count = 0;
    if (!parse_value(parser, UINT16_MAX, 0, &value) ||
        parser->tokens[value].type != JSON_OBJECT) return 0;
    skip_space(parser);
    if (parser->position != parser->length) return 0;
    *root = value;
    return 1;
}

static int token_string_equals(const json_parser *parser, uint32_t index,
                               const char *value)
{
    const json_token *token;
    size_t length = 0, i;
    while (value[length]) ++length;
    if (index >= parser->token_count) return 0;
    token = &parser->tokens[index];
    if (token->type != JSON_STRING || token->end - token->start != length)
        return 0;
    for (i = 0; i < length; ++i)
        if (parser->text[token->start + i] != (uint8_t)value[i]) return 0;
    return 1;
}

static int object_field(const json_parser *parser, uint32_t object,
                        const char *name)
{
    uint32_t cursor, found = UINT32_MAX;
    const json_token *container;
    if (object >= parser->token_count ||
        parser->tokens[object].type != JSON_OBJECT) return -1;
    container = &parser->tokens[object];
    cursor = object + 1;
    while (cursor < container->next) {
        uint32_t key = cursor;
        uint32_t value = parser->tokens[key].next;
        if (value >= container->next ||
            parser->tokens[key].parent != object ||
            parser->tokens[value].parent != object) return -1;
        if (token_string_equals(parser, key, name)) {
            if (found != UINT32_MAX) return -2;
            found = value;
        }
        cursor = parser->tokens[value].next;
    }
    return found == UINT32_MAX ? -1 : (int)found;
}

static size_t object_size(const json_parser *parser, uint32_t object)
{
    size_t count = 0;
    uint32_t cursor;
    if (object >= parser->token_count ||
        parser->tokens[object].type != JSON_OBJECT) return SIZE_MAX;
    cursor = object + 1;
    while (cursor < parser->tokens[object].next) {
        uint32_t value = parser->tokens[cursor].next;
        if (value >= parser->tokens[object].next) return SIZE_MAX;
        cursor = parser->tokens[value].next;
        ++count;
    }
    return count;
}

static int parse_u64(const json_parser *parser, uint32_t index,
                     uint64_t *value)
{
    const json_token *token;
    uint64_t result = 0;
    uint32_t i;
    if (index >= parser->token_count) return 0;
    token = &parser->tokens[index];
    if (token->type != JSON_STRING && token->type != JSON_NUMBER) return 0;
    if (token->start == token->end) return 0;
    for (i = token->start; i < token->end; ++i) {
        uint8_t c = parser->text[i];
        if (c < '0' || c > '9' || result > (UINT64_MAX - (c - '0')) / 10u)
            return 0;
        result = result * 10u + (c - '0');
    }
    *value = result;
    return 1;
}

static int parse_hash_name(const json_parser *parser, uint32_t index,
                           ml_hash_algorithm *hash)
{
    if (token_string_equals(parser, index, "sha1")) *hash = ML_HASH_SHA1;
    else if (token_string_equals(parser, index, "sha256")) *hash = ML_HASH_SHA256;
    else if (token_string_equals(parser, index, "sha512")) *hash = ML_HASH_SHA512;
    else if (token_string_equals(parser, index, "ripemd160")) *hash = ML_HASH_RIPEMD160;
    else if (token_string_equals(parser, index, "whirlpool")) *hash = ML_HASH_WHIRLPOOL;
    else return 0;
    return 1;
}

static int base64_value(uint8_t c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static int decode_base64(const json_parser *parser, uint32_t index,
                         uint8_t *output, size_t capacity, size_t *output_size)
{
    const json_token *token;
    size_t input_size, produced = 0, i;
    if (index >= parser->token_count) return 0;
    token = &parser->tokens[index];
    if (token->type != JSON_STRING) return 0;
    input_size = token->end - token->start;
    if (!input_size || (input_size & 3u)) return 0;
    for (i = 0; i < input_size; i += 4) {
        uint8_t c0 = parser->text[token->start + i];
        uint8_t c1 = parser->text[token->start + i + 1];
        uint8_t c2 = parser->text[token->start + i + 2];
        uint8_t c3 = parser->text[token->start + i + 3];
        int a = base64_value(c0), b = base64_value(c1);
        int c = c2 == '=' ? 0 : base64_value(c2);
        int d = c3 == '=' ? 0 : base64_value(c3);
        size_t bytes = i + 4 == input_size ?
            (c3 == '=' ? (c2 == '=' ? 1u : 2u) : 3u) : 3u;
        if (a < 0 || b < 0 || c < 0 || d < 0 ||
            (c2 == '=' && c3 != '=') ||
            ((c2 == '=' || c3 == '=') && i + 4 != input_size) ||
            produced + bytes > capacity) return 0;
        output[produced++] = (uint8_t)((a << 2) | (b >> 4));
        if (bytes > 1)
            output[produced++] = (uint8_t)((b << 4) | (c >> 2));
        if (bytes > 2)
            output[produced++] = (uint8_t)((c << 6) | d);
    }
    *output_size = produced;
    return 1;
}

static int parse_array_has(const json_parser *parser, uint32_t array,
                           const char *value)
{
    uint32_t cursor;
    if (array >= parser->token_count ||
        parser->tokens[array].type != JSON_ARRAY) return 0;
    cursor = array + 1;
    while (cursor < parser->tokens[array].next) {
        if (token_string_equals(parser, cursor, value)) return 1;
        cursor = parser->tokens[cursor].next;
    }
    return 0;
}

static int token_to_slot_id(const json_parser *parser, uint32_t index,
                            uint32_t *id)
{
    uint64_t value;
    if (!parse_u64(parser, index, &value) || value >= LUKS2_MAX_SLOTS)
        return 0;
    *id = (uint32_t)value;
    return 1;
}

/* 1: header is valid, 0: unsupported checksum, -1: malformed or unreadable. */
static int read_header_copy(const ml_block_device *device, uint64_t offset,
                            uint8_t *metadata, size_t *metadata_size,
                            size_t *json_size)
{
    uint64_t header_size64, header_offset;
    uint8_t expected[LUKS2_CHECKSUM_BYTES], actual[64];
    size_t header_size, i, json_length;
    if (offset > device->byte_size ||
        LUKS2_HEADER_BYTES > device->byte_size - offset ||
        ml_block_read(device, offset, metadata, LUKS2_HEADER_BYTES) != ML_BLOCK_OK)
        return -1;
    if (metadata[0] != 'L' || metadata[1] != 'U' || metadata[2] != 'K' ||
        metadata[3] != 'S' || metadata[4] != 0xba || metadata[5] != 0xbe ||
        be16(metadata + 6) != 2) return -1;
    header_size64 = be64(metadata + 8);
    header_offset = be64(metadata + 256);
    if (header_size64 < 16384u ||
        header_size64 > ML_LUKS2_METADATA_MAX_BYTES ||
        (header_size64 & 4095u) || header_offset != offset)
        return -1;
    header_size = (size_t)header_size64;
    if (offset > device->byte_size ||
        header_size > device->byte_size - offset) return -1;
    if (metadata[72] != 's' || metadata[73] != 'h' || metadata[74] != 'a' ||
        metadata[75] != '2' || metadata[76] != '5' || metadata[77] != '6' ||
        metadata[78] != 0) return 0;
    if (ml_block_read(device, offset, metadata, header_size) != ML_BLOCK_OK)
        return -1;
    for (i = 0; i < LUKS2_CHECKSUM_BYTES; ++i)
        expected[i] = metadata[LUKS2_CHECKSUM_OFFSET + i];
    for (i = 0; i < LUKS2_CHECKSUM_BYTES; ++i)
        metadata[LUKS2_CHECKSUM_OFFSET + i] = 0;
    if (!ml_hash_data(ML_HASH_SHA256, metadata, header_size, actual)) {
        for (i = 0; i < LUKS2_CHECKSUM_BYTES; ++i)
            metadata[LUKS2_CHECKSUM_OFFSET + i] = expected[i];
        secure_zero(expected, sizeof(expected));
        secure_zero(actual, sizeof(actual));
        return 0;
    }
    for (i = 0; i < LUKS2_CHECKSUM_BYTES; ++i)
        metadata[LUKS2_CHECKSUM_OFFSET + i] = expected[i];
    if (!bytes_equal(expected, actual, LUKS2_CHECKSUM_BYTES)) {
        secure_zero(expected, sizeof(expected));
        secure_zero(actual, sizeof(actual));
        return -1;
    }
    secure_zero(expected, sizeof(expected));
    secure_zero(actual, sizeof(actual));
    json_length = header_size - LUKS2_HEADER_BYTES;
    for (i = 0; i < json_length; ++i)
        if (metadata[LUKS2_HEADER_BYTES + i] == 0) {
            json_length = i;
            for (++i; i < header_size - LUKS2_HEADER_BYTES; ++i) {
                if (metadata[LUKS2_HEADER_BYTES + i] != 0) return -1;
            }
            break;
        }
    *metadata_size = header_size;
    *json_size = json_length;
    return 1;
}

static int read_valid_metadata(const ml_block_device *device,
                               uint8_t *metadata, size_t *metadata_size,
                               size_t *json_size, uint64_t *copy_offset)
{
    static const uint64_t candidate_copies[] = { 16384u, 32768u, 65536u };
    uint64_t primary_size = 0;
    int result;
    size_t i;
    if (device->byte_size < LUKS2_HEADER_BYTES ||
        ml_block_read(device, 0, metadata, LUKS2_HEADER_BYTES) != ML_BLOCK_OK)
        return -1;
    if (metadata[0] != 'L' || metadata[1] != 'U' || metadata[2] != 'K' ||
        metadata[3] != 'S' || metadata[4] != 0xba || metadata[5] != 0xbe)
        return -2;
    if (be16(metadata + 6) != 2) return 0;
    primary_size = be64(metadata + 8);
    result = read_header_copy(device, 0, metadata, metadata_size, json_size);
    if (result == 1) {
        uint64_t primary_sequence = be64(metadata + 16);
        size_t primary_metadata_size = *metadata_size;
        int secondary_result = read_header_copy(device, primary_size, metadata,
            metadata_size, json_size);
        if (secondary_result == 1 && *metadata_size == primary_metadata_size &&
            be64(metadata + 16) > primary_sequence) {
            *copy_offset = primary_size;
            return 1;
        }
        result = read_header_copy(device, 0, metadata, metadata_size, json_size);
        if (result == 1) {
            *copy_offset = 0;
            return 1;
        }
        return -1;
    }
    if (result == 0) return 0;
    for (i = 0; i < sizeof(candidate_copies) / sizeof(candidate_copies[0]); ++i) {
        uint64_t offset = candidate_copies[i];
        if (primary_size >= LUKS2_HEADER_BYTES &&
            primary_size <= ML_LUKS2_METADATA_MAX_BYTES &&
            (primary_size & 4095u) == 0 && offset != primary_size) continue;
        result = read_header_copy(device, offset, metadata,
                                  metadata_size, json_size);
        if (result == 1) {
            *copy_offset = offset;
            return 1;
        }
        if (result == 0) return 0;
    }
    return -1;
}

static int field_equals(const json_parser *parser, uint32_t object,
                        const char *field, const char *value)
{
    int index = object_field(parser, object, field);
    return index >= 0 && token_string_equals(parser, (uint32_t)index, value);
}

static int field_u64(const json_parser *parser, uint32_t object,
                     const char *field, uint64_t *value)
{
    int index = object_field(parser, object, field);
    return index >= 0 && parse_u64(parser, (uint32_t)index, value);
}

static int field_xts_cipher(const json_parser *parser, uint32_t object,
                            const char *field, ml_xts_cipher *cipher)
{
    int token = object_field(parser, object, field);
    if (token < 0) return -1;
    if (token_string_equals(parser, (uint32_t)token, "aes-xts-plain64")) {
#if ML_ENABLE_CIPHER_AES_XTS
        *cipher = ML_XTS_AES;
        return 1;
#else
        return 0;
#endif
    }
    if (token_string_equals(parser, (uint32_t)token, "serpent-xts-plain64")) {
#if ML_ENABLE_CIPHER_SERPENT_XTS
        *cipher = ML_XTS_SERPENT;
        return 1;
#else
        return 0;
#endif
    }
    if (token_string_equals(parser, (uint32_t)token, "twofish-xts-plain64")) {
#if ML_ENABLE_CIPHER_TWOFISH_XTS
        *cipher = ML_XTS_TWOFISH;
        return 1;
#else
        return 0;
#endif
    }
    return 0;
}

static int field_segment_cipher(const json_parser *parser, uint32_t object,
                                const char *field, ml_xts_cipher *cipher,
                                uint8_t *aes_cbc_essiv)
{
    int token = object_field(parser, object, field);
    if (token < 0 || !aes_cbc_essiv) return -1;
    *aes_cbc_essiv = 0;
    if (token_string_equals(parser, (uint32_t)token,
                            "aes-cbc-essiv:sha256")) {
#if ML_ENABLE_CIPHER_AES_CBC_ESSIV
        *cipher = ML_XTS_AES;
        *aes_cbc_essiv = 1;
        return 1;
#else
        return 0;
#endif
    }
    return field_xts_cipher(parser, object, field, cipher);
}

/* 1: supported profile, 0: valid but unsupported profile, -1: malformed. */
static int parse_keyslot(const json_parser *parser, uint32_t id,
                         uint32_t object, uint64_t keyslots_start,
                         uint64_t keyslots_end, luks2_slot *slot)
{
    int type, af, area, kdf, hash, cipher_result;
    uint64_t value;
    size_t key_bytes;
    if (object >= parser->token_count ||
        parser->tokens[object].type != JSON_OBJECT) return -1;
    secure_zero(slot, sizeof(*slot));
    slot->id = id;
    type = object_field(parser, object, "type");
    if (type < 0) return -1;
    if (!token_string_equals(parser, (uint32_t)type, "luks2")) return 0;
    af = object_field(parser, object, "af");
    area = object_field(parser, object, "area");
    kdf = object_field(parser, object, "kdf");
    if (af < 0 || area < 0 || kdf < 0 ||
        parser->tokens[af].type != JSON_OBJECT ||
        parser->tokens[area].type != JSON_OBJECT ||
        parser->tokens[kdf].type != JSON_OBJECT) return -1;
    if (!field_equals(parser, (uint32_t)af, "type", "luks1") ||
        !field_equals(parser, (uint32_t)area, "type", "raw"))
        return 0;
    cipher_result = field_segment_cipher(parser, (uint32_t)area,
        "encryption", &slot->cipher, &slot->aes_cbc_essiv);
    if (cipher_result <= 0) return cipher_result;
    if (!field_u64(parser, object, "key_size", &value) ||
        (value != 32 && value != 64)) return -1;
    slot->key_bytes = (uint32_t)value;
    if (!field_u64(parser, (uint32_t)area, "key_size", &value) ||
        (slot->aes_cbc_essiv
            ? (value != 16 && value != 24 && value != 32)
            : (value != 32 && value != 64))) return -1;
    slot->area_key_bytes = (uint32_t)value;
    if (!field_u64(parser, (uint32_t)af, "stripes", &value) ||
        value == 0 || value > LUKS2_MAX_STRIPES) return -1;
    slot->stripes = (uint32_t)value;
    hash = object_field(parser, (uint32_t)af, "hash");
    if (hash < 0) return -1;
    if (!parse_hash_name(parser, (uint32_t)hash, &slot->af_hash)) return 0;
    if (field_equals(parser, (uint32_t)kdf, "type", "pbkdf2")) {
#if !ML_ENABLE_KDF_PBKDF2
        slot->unsupported_kdf = 1;
        return 0;
#else
        slot->kdf_type = LUKS2_KDF_PBKDF2;
        hash = object_field(parser, (uint32_t)kdf, "hash");
        if (hash < 0) return -1;
        if (!parse_hash_name(parser, (uint32_t)hash, &slot->kdf_hash)) return 0;
        if (!field_u64(parser, (uint32_t)kdf, "iterations", &value) ||
            value == 0 || value > LUKS2_MAX_ITERATIONS) {
            slot->unsupported_kdf = 1;
            return 0;
        }
        slot->iterations = (uint32_t)value;
#endif
    } else if (field_equals(parser, (uint32_t)kdf, "type", "argon2id")) {
#if !ML_ENABLE_KDF_ARGON2ID
        slot->unsupported_kdf = 1;
        return 0;
#else
        slot->kdf_type = LUKS2_KDF_ARGON2ID;
        if (!field_u64(parser, (uint32_t)kdf, "time", &value) ||
            value == 0 || value > LUKS2_MAX_ARGON2_TIME) {
            slot->unsupported_kdf = 1;
            return 0;
        }
        slot->argon_time = (uint32_t)value;
        if (!field_u64(parser, (uint32_t)kdf, "memory", &value) ||
            value < 8 || value > LUKS2_MAX_ARGON2_MEMORY_KIB) {
            slot->unsupported_kdf = 1;
            return 0;
        }
        slot->argon_memory_kib = (uint32_t)value;
        if (!field_u64(parser, (uint32_t)kdf, "cpus", &value) ||
            value == 0 || value > LUKS2_MAX_ARGON2_LANES ||
            slot->argon_memory_kib < 8u * value) {
            slot->unsupported_kdf = 1;
            return 0;
        }
        slot->argon_lanes = (uint32_t)value;
#endif
    } else {
        return 0;
    }
    hash = object_field(parser, (uint32_t)kdf, "salt");
    if (hash < 0 || !decode_base64(parser, (uint32_t)hash, slot->salt,
                                   sizeof(slot->salt), &slot->salt_size) ||
        !slot->salt_size) return -1;
    if (!field_u64(parser, (uint32_t)area, "offset", &slot->area_offset) ||
        !field_u64(parser, (uint32_t)area, "size", &slot->area_size)) return -1;
    key_bytes = (size_t)slot->key_bytes * slot->stripes;
    if (key_bytes > ML_LUKS2_MAX_AF_BYTES ||
        slot->area_size < key_bytes ||
        slot->area_size > ML_LUKS2_MAX_AREA_BYTES ||
        (slot->area_size & 511u) ||
        slot->area_offset < keyslots_start ||
        slot->area_offset > keyslots_end ||
        slot->area_size > keyslots_end - slot->area_offset)
        return -1;
    slot->supported = 1;
    return 1;
}

/* 1: matching digest, 0: none/unsupported, -1: malformed. */
static int find_digest(const json_parser *parser, uint32_t digests_object,
                       uint32_t slot_id, luks2_digest *digest)
{
    uint32_t cursor;
    size_t matches = 0;
    if (digests_object >= parser->token_count ||
        parser->tokens[digests_object].type != JSON_OBJECT) return -1;
    cursor = digests_object + 1;
    while (cursor < parser->tokens[digests_object].next) {
        uint32_t value_index = parser->tokens[cursor].next;
        uint32_t keyslots, segments;
        int keyslots_index, segments_index;
        int type, hash, salt, digest_value;
        uint64_t iterations;
        luks2_digest candidate;
        if (value_index >= parser->tokens[digests_object].next ||
            parser->tokens[value_index].type != JSON_OBJECT) return -1;
        cursor = parser->tokens[value_index].next;
        type = object_field(parser, value_index, "type");
        keyslots_index = object_field(parser, value_index, "keyslots");
        segments_index = object_field(parser, value_index, "segments");
        if (type < 0 || keyslots_index < 0 || segments_index < 0)
            return -1;
        keyslots = (uint32_t)keyslots_index;
        segments = (uint32_t)segments_index;
        if (!token_string_equals(parser, (uint32_t)type, "pbkdf2") ||
            !parse_array_has(parser, segments, "0")) continue;
        /* Keyslot references are decimal strings; test nonzero slots too. */
        {
            char slot_text[4];
            size_t n = 0;
            uint32_t v = slot_id;
            char reverse[4];
            do { reverse[n++] = (char)('0' + (v % 10u)); v /= 10u; } while (v && n < sizeof(reverse));
            for (size_t j = 0; j < n; ++j) slot_text[j] = reverse[n - j - 1];
            slot_text[n] = '\0';
            if (!parse_array_has(parser, keyslots, slot_text)) continue;
        }
        if (object_field(parser, value_index, "hash") < 0 ||
            !field_u64(parser, value_index, "iterations", &iterations) ||
            iterations == 0 || iterations > LUKS2_MAX_ITERATIONS)
            return -1;
        hash = object_field(parser, value_index, "hash");
        if (!parse_hash_name(parser, (uint32_t)hash, &candidate.hash)) continue;
        candidate.iterations = (uint32_t)iterations;
        salt = object_field(parser, value_index, "salt");
        digest_value = object_field(parser, value_index, "digest");
        if (salt < 0 || digest_value < 0 ||
            !decode_base64(parser, (uint32_t)salt, candidate.salt,
                           sizeof(candidate.salt), &candidate.salt_size) ||
            !decode_base64(parser, (uint32_t)digest_value, candidate.digest,
                           sizeof(candidate.digest), &candidate.digest_size) ||
            !candidate.salt_size ||
            candidate.digest_size != ml_hash_digest_size(candidate.hash))
            return -1;
        *digest = candidate;
        ++matches;
    }
    return matches == 1 ? 1 : (matches == 0 ? 0 : -1);
}

static int parse_segment(const json_parser *parser, uint32_t segments_object,
                         const ml_block_device *device, uint64_t keys_end,
                         luks2_segment *segment)
{
    int selected, size_index;
    uint64_t size;
    uint32_t object;
    if (object_size(parser, segments_object) != 1) return 0;
    selected = object_field(parser, segments_object, "0");
    if (selected < 0) return -1;
    object = (uint32_t)selected;
    if (parser->tokens[object].type != JSON_OBJECT) return -1;
    if (!field_equals(parser, object, "type", "crypt")) return 0;
    {
        int cipher_result = field_segment_cipher(parser, object, "encryption",
            &segment->cipher, &segment->aes_cbc_essiv);
        if (cipher_result <= 0) return cipher_result;
    }
    if (!field_u64(parser, object, "offset", &segment->offset) ||
        !field_u64(parser, object, "iv_tweak", &segment->iv_tweak) ||
        !field_u64(parser, object, "sector_size", &size) ||
        (size != 512 && size != 4096)) return -1;
    segment->sector_size = (uint32_t)size;
    size_index = object_field(parser, object, "size");
    if (size_index < 0) return -1;
    if (token_string_equals(parser, (uint32_t)size_index, "dynamic")) {
        if (segment->offset >= device->byte_size) return -1;
        segment->size = device->byte_size - segment->offset;
    } else if (!parse_u64(parser, (uint32_t)size_index, &segment->size)) {
        return -1;
    }
    if (segment->offset < keys_end || segment->offset > device->byte_size ||
        segment->size > device->byte_size - segment->offset ||
        !segment->size ||
        (segment->offset & (segment->sector_size - 1u)) ||
        (segment->size & (segment->sector_size - 1u))) return -1;
    return 1;
}

static int af_diffuse(ml_hash_algorithm hash, uint8_t *data, size_t size)
{
    uint8_t input[68], digest[64];
    size_t digest_size = ml_hash_digest_size(hash), offset = 0;
    uint32_t chunk = 0;
    while (offset < size) {
        size_t amount = size - offset, i;
        if (amount > digest_size) amount = digest_size;
        input[0] = (uint8_t)(chunk >> 24);
        input[1] = (uint8_t)(chunk >> 16);
        input[2] = (uint8_t)(chunk >> 8);
        input[3] = (uint8_t)chunk;
        for (i = 0; i < amount; ++i) input[4 + i] = data[offset + i];
        if (!ml_hash_data(hash, input, 4 + amount, digest)) {
            secure_zero(input, sizeof(input));
            secure_zero(digest, sizeof(digest));
            return 0;
        }
        for (i = 0; i < amount; ++i) data[offset + i] = digest[i];
        offset += amount;
        ++chunk;
    }
    secure_zero(input, sizeof(input));
    secure_zero(digest, sizeof(digest));
    return 1;
}

static int af_merge(ml_hash_algorithm hash, const uint8_t *split,
                    uint8_t *key, size_t key_size, uint32_t stripes)
{
    uint32_t stripe;
    size_t i;
    for (i = 0; i < key_size; ++i) key[i] = 0;
    for (stripe = 0; stripe + 1 < stripes; ++stripe) {
        const uint8_t *part = split + (size_t)stripe * key_size;
        for (i = 0; i < key_size; ++i) key[i] ^= part[i];
        if (!af_diffuse(hash, key, key_size)) return 0;
    }
    split += (size_t)(stripes - 1) * key_size;
    for (i = 0; i < key_size; ++i) key[i] ^= split[i];
    return 1;
}

static int luks2_volume_read(void *context, uint64_t offset,
                             void *buffer, size_t length)
{
    ml_luks2_volume *volume = (ml_luks2_volume *)context;
    uint8_t *out = (uint8_t *)buffer;
    size_t done = 0;
    if (!volume || !volume->parent || (!buffer && length)) return -1;
    while (done < length) {
        uint64_t at = offset + done;
        uint64_t sector_number, physical;
        size_t within, amount;
        if (at < offset || at >= volume->byte_size) return -1;
        sector_number = at / volume->sector_size;
        within = (size_t)(at % volume->sector_size);
        amount = volume->sector_size - within;
        if (amount > length - done) amount = length - done;
        if (sector_number > UINT64_MAX - volume->iv_tweak ||
            sector_number > UINT64_MAX / volume->sector_size ||
            volume->payload_offset > UINT64_MAX - sector_number * volume->sector_size)
            return -1;
        physical = volume->payload_offset + sector_number * volume->sector_size;
        if (ml_block_read(volume->parent, physical, volume->sector_buffer,
                          volume->sector_size) != ML_BLOCK_OK) return -1;
        if (volume->aes_cbc_essiv) {
            if (!ml_aes_cbc_essiv_decrypt(volume->master_key,
                    volume->key_bytes, volume->iv_tweak + sector_number,
                    volume->sector_buffer, volume->sector_buffer,
                    volume->sector_size)) return -1;
        } else if (!ml_xts_decrypt(volume->cipher, volume->master_key,
                       volume->key_bytes,
                       volume->iv_tweak + sector_number,
                       volume->sector_buffer, volume->sector_buffer,
                       volume->sector_size)) {
            return -1;
        }
        for (size_t i = 0; i < amount; ++i)
            out[done + i] = volume->sector_buffer[within + i];
        done += amount;
    }
    return 0;
}

ml_luks2_result ml_luks2_open(ml_luks2_volume *volume,
                              const ml_block_device *device,
                              const void *passphrase, size_t passphrase_size,
                              void *scratch, size_t scratch_size,
                              ml_argon2_allocate_fn argon_allocate,
                              ml_argon2_free_fn argon_release,
                              void *argon_allocator_context,
                              const char **message)
{
    uint8_t *metadata, *material;
    json_token *tokens;
    json_parser parser;
    size_t metadata_size = 0, json_size = 0;
    uint64_t copy_offset = 0, keyslots_start, keyslots_size, keyslots_end;
    uint32_t root, keyslots_object, digests_object, segments_object;
    uint32_t config_object;
    uint32_t seen_slot_ids = 0;
    luks2_segment segment;
    int meta_result, parsed_segment;
    size_t token_capacity;
    if (message) *message = NULL;
    (void)argon_allocate;
    (void)argon_release;
    (void)argon_allocator_context;
#if !ML_ENABLE_KDF_PBKDF2 && !ML_ENABLE_KDF_ARGON2ID
    if (message) *message = "LUKS2 PBKDF2 support is disabled in this build";
    return ML_LUKS2_UNSUPPORTED;
#endif
#if !ML_ENABLE_CIPHER_AES_XTS && !ML_ENABLE_CIPHER_AES_CBC_ESSIV && !ML_ENABLE_CIPHER_SERPENT_XTS && !ML_ENABLE_CIPHER_TWOFISH_XTS
    if (message) *message = "LUKS2 cipher support is disabled in this build";
    return ML_LUKS2_UNSUPPORTED;
#endif
    if (!volume || !device || !device->read_at || !passphrase ||
        !passphrase_size || !scratch) {
        if (message) *message = "invalid LUKS2 unlock arguments";
        return ML_LUKS2_INVALID;
    }
    secure_zero(volume, sizeof(*volume));
    if (scratch_size < ML_LUKS2_SCRATCH_BYTES) {
        if (message) *message = "LUKS2 scratch buffer is too small";
        return ML_LUKS2_RANGE;
    }
    metadata = (uint8_t *)scratch;
    tokens = (json_token *)(metadata + ML_LUKS2_METADATA_MAX_BYTES);
    token_capacity = ML_LUKS2_METADATA_MAX_BYTES / sizeof(*tokens);
    material = metadata + 2u * ML_LUKS2_METADATA_MAX_BYTES;
    meta_result = read_valid_metadata(device, metadata, &metadata_size,
                                      &json_size, &copy_offset);
    if (meta_result == -2) return ML_LUKS2_NOT_LUKS;
    if (meta_result == 0) {
        if (message) *message = "LUKS2 metadata checksum algorithm is unsupported";
        return ML_LUKS2_UNSUPPORTED;
    }
    if (meta_result < 0) {
        if (message) *message = "LUKS2 header is malformed or its metadata checksum is invalid";
        return ML_LUKS2_BAD_FORMAT;
    }
    if (!parse_json(&parser, metadata + LUKS2_HEADER_BYTES, json_size,
                    tokens, token_capacity, &root)) {
        if (message) *message = "LUKS2 JSON metadata is malformed or exceeds parser limits";
        return ML_LUKS2_BAD_FORMAT;
    }
    (void)metadata_size;
    (void)copy_offset;
    {
        int keyslots_index = object_field(&parser, root, "keyslots");
        int digests_index = object_field(&parser, root, "digests");
        int segments_index = object_field(&parser, root, "segments");
        int config_index = object_field(&parser, root, "config");
        if (keyslots_index < 0 || digests_index < 0 ||
            segments_index < 0 || config_index < 0) {
            if (message) *message = "LUKS2 JSON lacks keyslots, digests, segments, or config";
            return ML_LUKS2_BAD_FORMAT;
        }
        keyslots_object = (uint32_t)keyslots_index;
        digests_object = (uint32_t)digests_index;
        segments_object = (uint32_t)segments_index;
        config_object = (uint32_t)config_index;
        if (parser.tokens[keyslots_object].type != JSON_OBJECT ||
            parser.tokens[digests_object].type != JSON_OBJECT ||
            parser.tokens[config_object].type != JSON_OBJECT ||
            !field_u64(&parser, config_object, "keyslots_size", &keyslots_size)) {
            if (message) *message = "LUKS2 keyslot area metadata is malformed";
            return ML_LUKS2_BAD_FORMAT;
        }
        keyslots_start = metadata_size * 2u;
        if (keyslots_start > device->byte_size ||
            keyslots_size > device->byte_size - keyslots_start) {
            if (message) *message = "LUKS2 keyslot area exceeds the device";
            return ML_LUKS2_BAD_FORMAT;
        }
        keyslots_end = keyslots_start + keyslots_size;
        parsed_segment = parse_segment(&parser, segments_object, device,
                                       keyslots_end, &segment);
        if (parsed_segment <= 0) {
            if (message) *message = parsed_segment == 0
                ? "LUKS2 data segment uses an unsupported cipher or layout"
                : "LUKS2 data segment metadata is malformed";
            return parsed_segment == 0 ? ML_LUKS2_UNSUPPORTED : ML_LUKS2_BAD_FORMAT;
        }
        if (object_size(&parser, keyslots_object) == SIZE_MAX ||
            object_size(&parser, keyslots_object) > LUKS2_MAX_SLOTS) {
            if (message) *message = "LUKS2 contains too many keyslots";
            return ML_LUKS2_UNSUPPORTED;
        }
    }

    {
        uint32_t cursor = keyslots_object + 1;
        int supported_slot_seen = 0;
        int wrong_passphrase_seen = 0;
        int unsupported_kdf_seen = 0;
        while (cursor < parser.tokens[keyslots_object].next) {
            uint32_t key_token = cursor;
            uint32_t slot_token = parser.tokens[key_token].next;
            uint32_t id;
            luks2_slot slot;
            luks2_digest digest;
            int slot_result, digest_result;
            uint64_t key_material_bytes;
            uint8_t pass_key[ML_LUKS2_MAX_KEY_BYTES];
            uint8_t candidate[ML_LUKS2_MAX_KEY_BYTES];
            uint8_t calculated[64];
            size_t digest_size, i;
            int derivation_ok = 0;
            cursor = parser.tokens[slot_token].next;
            if (!token_to_slot_id(&parser, key_token, &id)) {
                if (message) *message = "LUKS2 keyslot identifier is invalid";
                return ML_LUKS2_BAD_FORMAT;
            }
            if (seen_slot_ids & ((uint32_t)1u << id)) {
                if (message) *message = "LUKS2 keyslot identifier is duplicated";
                return ML_LUKS2_BAD_FORMAT;
            }
            seen_slot_ids |= (uint32_t)1u << id;
            slot_result = parse_keyslot(&parser, id, slot_token,
                                        keyslots_start, keyslots_end, &slot);
            if (slot_result < 0) {
                if (message) *message = "LUKS2 keyslot metadata is malformed";
                return ML_LUKS2_BAD_FORMAT;
            }
            if (slot_result == 0 || !slot.supported) {
                if (slot.unsupported_kdf) unsupported_kdf_seen = 1;
                continue;
            }
            supported_slot_seen = 1;
            digest_result = find_digest(&parser, digests_object, id, &digest);
            if (digest_result < 0) {
                if (message) *message = "LUKS2 keyslot digest metadata is malformed or ambiguous";
                return ML_LUKS2_BAD_FORMAT;
            }
            if (digest_result == 0) continue;
            key_material_bytes = (uint64_t)slot.key_bytes * slot.stripes;
            if (key_material_bytes > ML_LUKS2_MAX_AF_BYTES ||
                slot.area_size > ML_LUKS2_MAX_AREA_BYTES) {
                if (message) *message = "LUKS2 keyslot AF area exceeds configured limits";
                return ML_LUKS2_UNSUPPORTED;
            }
            if (slot.kdf_type == LUKS2_KDF_PBKDF2) {
                derivation_ok = ml_pbkdf2(slot.kdf_hash, passphrase,
                    passphrase_size, slot.salt, slot.salt_size,
                    slot.iterations, pass_key, slot.area_key_bytes);
            } else if (slot.kdf_type == LUKS2_KDF_ARGON2ID) {
#if ML_ENABLE_KDF_ARGON2ID
                derivation_ok = ml_argon2id_derive(passphrase,
                    passphrase_size, slot.salt, slot.salt_size,
                    slot.argon_time, slot.argon_memory_kib, slot.argon_lanes,
                    pass_key, slot.area_key_bytes, argon_allocate,
                    argon_release, argon_allocator_context);
#endif
            }
            if (!derivation_ok) {
                secure_zero(pass_key, sizeof(pass_key));
                if (message) *message = slot.kdf_type == LUKS2_KDF_ARGON2ID
                    ? "LUKS2 Argon2id derivation failed or memory is unavailable"
                    : "LUKS2 PBKDF2 derivation failed";
                return ML_LUKS2_UNSUPPORTED;
            }
            if (ml_block_read(device, slot.area_offset, material,
                              (size_t)slot.area_size) != ML_BLOCK_OK) {
                secure_zero(pass_key, sizeof(pass_key));
                if (message) *message = "cannot read LUKS2 keyslot area";
                return ML_LUKS2_IO;
            }
            for (uint64_t sector = 0; sector < slot.area_size / 512u; ++sector) {
                uint8_t *at = material + (size_t)sector * 512u;
                int decrypted = slot.aes_cbc_essiv
                    ? ml_aes_cbc_essiv_decrypt(pass_key,
                        slot.area_key_bytes, sector, at, at, 512u)
                    : ml_xts_decrypt(slot.cipher, pass_key,
                        slot.area_key_bytes, sector, at, at, 512u);
                if (!decrypted) {
                    secure_zero(pass_key, sizeof(pass_key));
                    secure_zero(material, (size_t)slot.area_size);
                    if (message) *message = "LUKS2 keyslot XTS decryption failed";
                    return ML_LUKS2_UNSUPPORTED;
                }
            }
            secure_zero(pass_key, sizeof(pass_key));
            if (!af_merge(slot.af_hash, material, candidate,
                          slot.key_bytes, slot.stripes)) {
                secure_zero(candidate, sizeof(candidate));
                secure_zero(material, (size_t)slot.area_size);
                if (message) *message = "LUKS2 AF merge failed";
                return ML_LUKS2_UNSUPPORTED;
            }
            digest_size = ml_hash_digest_size(digest.hash);
            if (!ml_pbkdf2(digest.hash, candidate, slot.key_bytes,
                           digest.salt, digest.salt_size, digest.iterations,
                           calculated, digest_size)) {
                secure_zero(candidate, sizeof(candidate));
                secure_zero(material, (size_t)slot.area_size);
                secure_zero(calculated, sizeof(calculated));
                if (message) *message = "LUKS2 master-key digest derivation failed";
                return ML_LUKS2_UNSUPPORTED;
            }
            secure_zero(material, (size_t)slot.area_size);
            if (bytes_equal(calculated, digest.digest, digest_size)) {
                volume->parent = device;
                volume->payload_offset = segment.offset;
                volume->byte_size = segment.size;
                volume->iv_tweak = segment.iv_tweak;
                volume->sector_size = segment.sector_size;
                volume->key_bytes = slot.key_bytes;
                volume->cipher = segment.cipher;
                volume->aes_cbc_essiv = segment.aes_cbc_essiv;
                for (i = 0; i < slot.key_bytes; ++i)
                    volume->master_key[i] = candidate[i];
                volume->device.context = volume;
                volume->device.byte_size = volume->byte_size;
                volume->device.logical_block_size = volume->sector_size;
                volume->device.read_at = luks2_volume_read;
                secure_zero(candidate, sizeof(candidate));
                secure_zero(calculated, sizeof(calculated));
                return ML_LUKS2_OK;
            }
            secure_zero(candidate, sizeof(candidate));
            secure_zero(calculated, sizeof(calculated));
            wrong_passphrase_seen = 1;
        }
        if (wrong_passphrase_seen) {
            if (message) *message = "LUKS2 passphrase did not unlock any supported keyslot";
            return ML_LUKS2_WRONG_PASSPHRASE;
        }
        if (!supported_slot_seen) {
            if (message) *message = unsupported_kdf_seen
                ? "LUKS2 KDF is disabled or its parameters exceed the configured resource limits"
                : "LUKS2 has no supported PBKDF2/Argon2id and XTS keyslot";
            return ML_LUKS2_UNSUPPORTED;
        }
        if (message) *message = "LUKS2 keyslot has no matching supported digest";
        return ML_LUKS2_UNSUPPORTED;
    }
}

#if ML_ENABLE_TPM2
static int decode_hex_digest(const json_parser *parser, uint32_t index,
                             uint8_t output[32])
{
    const json_token *value;
    size_t i;
    if (index >= parser->token_count) return 0;
    value = &parser->tokens[index];
    if (value->type != JSON_STRING || value->end - value->start != 64)
        return 0;
    for (i = 0; i < 32; ++i) {
        int high = hex_digit(parser->text[value->start + i * 2]);
        int low = hex_digit(parser->text[value->start + i * 2 + 1]);
        if (high < 0 || low < 0) return 0;
        output[i] = (uint8_t)((high << 4) | low);
    }
    return 1;
}

ml_luks2_result ml_luks2_read_tpm2_token(const ml_block_device *device,
                                         ml_tpm2_token *token,
                                         void *scratch, size_t scratch_size,
                                         const char **message)
{
    uint8_t *metadata;
    json_token *tokens;
    json_parser parser;
    size_t metadata_size = 0, json_size = 0;
    uint64_t copy_offset = 0;
    size_t token_capacity;
    uint32_t root, token_object = UINT32_MAX;
    int token_count = 0, meta_result, tokens_index;
    uint32_t cursor;
    ml_luks2_result result = ML_LUKS2_BAD_FORMAT;

    if (message) *message = NULL;
    if (!device || !device->read_at || !token || !scratch) {
        if (message) *message = "invalid LUKS2 TPM2 token arguments";
        return ML_LUKS2_INVALID;
    }
    if (scratch_size < 2u * ML_LUKS2_METADATA_MAX_BYTES) {
        if (message) *message = "LUKS2 token scratch buffer is too small";
        return ML_LUKS2_RANGE;
    }
    secure_zero(token, sizeof(*token));
    metadata = (uint8_t *)scratch;
    tokens = (json_token *)(metadata + ML_LUKS2_METADATA_MAX_BYTES);
    token_capacity = ML_LUKS2_METADATA_MAX_BYTES / sizeof(*tokens);
    meta_result = read_valid_metadata(device, metadata, &metadata_size,
                                      &json_size, &copy_offset);
    if (meta_result == -2) {
        if (message) *message = "device is not a LUKS2 volume";
        return ML_LUKS2_NOT_LUKS;
    }
    if (meta_result == 0) {
        if (message) *message = "LUKS2 metadata checksum algorithm is unsupported";
        return ML_LUKS2_UNSUPPORTED;
    }
    if (meta_result < 0 ||
        !parse_json(&parser, metadata + LUKS2_HEADER_BYTES, json_size,
                    tokens, token_capacity, &root)) {
        if (message) *message = "LUKS2 metadata is malformed or its checksum is invalid";
        return ML_LUKS2_BAD_FORMAT;
    }
    (void)metadata_size;
    (void)copy_offset;
    tokens_index = object_field(&parser, root, "tokens");
    if (tokens_index < 0 || parser.tokens[tokens_index].type != JSON_OBJECT) {
        if (message) *message = "LUKS2 metadata has no token object";
        return ML_LUKS2_UNSUPPORTED;
    }
    cursor = (uint32_t)tokens_index + 1;
    while (cursor < parser.tokens[tokens_index].next) {
        uint32_t value = parser.tokens[cursor].next;
        int type;
        if (value >= parser.tokens[tokens_index].next ||
            parser.tokens[value].type != JSON_OBJECT) {
            if (message) *message = "LUKS2 token entry is malformed";
            return ML_LUKS2_BAD_FORMAT;
        }
        type = object_field(&parser, value, "type");
        if (type == -2) {
            if (message) *message = "LUKS2 token has duplicate type fields";
            return ML_LUKS2_BAD_FORMAT;
        }
        if (type >= 0 && token_string_equals(&parser, (uint32_t)type,
                                             "systemd-tpm2")) {
            token_object = value;
            ++token_count;
        }
        cursor = parser.tokens[value].next;
    }
    if (token_count == 0) {
        if (message) *message = "LUKS2 volume has no systemd TPM2 token";
        return ML_LUKS2_UNSUPPORTED;
    }
    if (token_count != 1) {
        if (message) *message = "LUKS2 volume has multiple systemd TPM2 tokens";
        return ML_LUKS2_UNSUPPORTED;
    }

    {
        int field;
        uint64_t number;
        uint32_t array, item;
        size_t pcr_count = 0, slot_count = 0;
        uint32_t slot_mask = 0;
        field = object_field(&parser, token_object, "tpm2-pin");
        if (field == -2 || (field >= 0 && parser.tokens[field].type != JSON_FALSE)) {
            if (message) *message = "systemd TPM2 tokens with PIN protection are unsupported";
            result = ML_LUKS2_UNSUPPORTED;
            goto done;
        }
        field = object_field(&parser, token_object, "keyslots");
        if (field < 0 || parser.tokens[field].type != JSON_ARRAY) goto malformed;
        array = (uint32_t)field;
        item = array + 1;
        while (item < parser.tokens[array].next) {
            uint32_t slot_id;
            if (!token_to_slot_id(&parser, item, &slot_id) ||
                (slot_mask & ((uint32_t)1u << slot_id))) goto malformed;
            slot_mask |= (uint32_t)1u << slot_id;
            ++slot_count;
            item = parser.tokens[item].next;
        }
        if (slot_count == 0) goto malformed;

        field = object_field(&parser, token_object, "tpm2-pcrs");
        if (field < 0 || parser.tokens[field].type != JSON_ARRAY) goto malformed;
        array = (uint32_t)field;
        item = array + 1;
        while (item < parser.tokens[array].next) {
            if (!parse_u64(&parser, item, &number) || number >= 24 ||
                (token->pcr_mask & ((uint32_t)1u << number))) goto malformed;
            token->pcr_mask |= (uint32_t)1u << number;
            ++pcr_count;
            item = parser.tokens[item].next;
        }
        if (pcr_count == 0) goto malformed;

        field = object_field(&parser, token_object, "tpm2-pcr-bank");
        if (field >= 0 && token_string_equals(&parser, (uint32_t)field, "sha256"))
            token->pcr_bank = ML_TPM2_ALG_SHA256;
        else if (field >= 0 && token_string_equals(&parser, (uint32_t)field, "sha1"))
            token->pcr_bank = ML_TPM2_ALG_SHA1;
        else {
            if (message) *message = "systemd TPM2 token uses an unsupported PCR bank";
            result = ML_LUKS2_UNSUPPORTED;
            goto done;
        }

        field = object_field(&parser, token_object, "tpm2-primary-alg");
        if (field >= 0 && token_string_equals(&parser, (uint32_t)field, "ecc"))
            token->primary_algorithm = ML_TPM2_ALG_ECC;
        else if (field >= 0 && token_string_equals(&parser, (uint32_t)field, "rsa"))
            token->primary_algorithm = ML_TPM2_ALG_RSA;
        else {
            if (message) *message = "systemd TPM2 token uses an unsupported primary algorithm";
            result = ML_LUKS2_UNSUPPORTED;
            goto done;
        }

        field = object_field(&parser, token_object, "tpm2-policy-hash");
        if (field < 0 || !decode_hex_digest(&parser, (uint32_t)field,
                                            token->policy_hash)) goto malformed;
        field = object_field(&parser, token_object, "tpm2-blob");
        if (field < 0 || !decode_base64(&parser, (uint32_t)field,
                                        token->blob, sizeof(token->blob),
                                        &token->blob_size) ||
            token->blob_size == 0) goto malformed;
    }
    result = ML_LUKS2_OK;
    goto done;

malformed:
    if (message) *message = "systemd TPM2 token metadata is malformed";
    result = ML_LUKS2_BAD_FORMAT;
done:
    if (result != ML_LUKS2_OK) secure_zero(token, sizeof(*token));
    return result;
}
#endif
