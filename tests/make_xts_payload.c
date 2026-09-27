/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Test fixture writer for selected LUKS1 and LUKS2 cipher profiles. */
#include "ml_crypto.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LUKS1_HEADER_SIZE 592u
#define LUKS2_HEADER_SIZE 16384u
#define LUKS2_JSON_OFFSET 4096u

typedef struct {
    FILE *plain;
    FILE *image;
    FILE *key_file;
    uint8_t key[64];
    size_t key_size;
    uint8_t input[4096];
    uint8_t output[4096];
    uint8_t header[LUKS2_HEADER_SIZE];
} fixture;

static uint32_t read_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}

static int file_size(FILE *file, uint64_t *size)
{
    long end;
    if (fseek(file, 0, SEEK_END) != 0) return 0;
    end = ftell(file);
    if (end < 0 || fseek(file, 0, SEEK_SET) != 0) return 0;
    *size = (uint64_t)end;
    return 1;
}

static int json_uint(const char *object, const char *field, uint64_t *value)
{
    char name[48];
    const char *at;
    char *end;
    unsigned long long parsed;
    if (strlen(field) + 4 >= sizeof(name)) return 0;
    name[0] = '"';
    strcpy(name + 1, field);
    strcat(name, "\":");
    at = strstr(object, name);
    if (!at) return 0;
    at += strlen(name);
    while (*at == ' ' || *at == '\t') ++at;
    if (*at == '"') ++at;
    if (*at < '0' || *at > '9') return 0;
    parsed = strtoull(at, &end, 10);
    if (end == at || (*end != '"' && *end != ',' && *end != '}')) return 0;
    *value = (uint64_t)parsed;
    return 1;
}

static ml_xts_cipher detect_cipher(const char *name)
{
    if (strncmp(name, "aes-xts-plain64", 15) == 0) return ML_XTS_AES;
    if (strncmp(name, "serpent-xts-plain64", 19) == 0) return ML_XTS_SERPENT;
    if (strncmp(name, "twofish-xts-plain64", 19) == 0) return ML_XTS_TWOFISH;
    return (ml_xts_cipher)-1;
}

static void store_le64(uint8_t output[8], uint64_t value)
{
    unsigned i;
    for (i = 0; i < 8; ++i) output[i] = (uint8_t)(value >> (i * 8));
}

static int encrypt_cbc_essiv_sector(fixture *f, uint64_t sector,
                                    uint32_t sector_size)
{
    ml_aes_context data_key, iv_key;
    uint8_t essiv_key[32], iv_input[16] = {0}, iv[16], block[16];
    size_t offset;
    int ok = 0;
    if ((f->key_size != 16 && f->key_size != 24 && f->key_size != 32) ||
        !ml_hash_data(ML_HASH_SHA256, f->key, f->key_size, essiv_key) ||
        !ml_aes_set_key(&data_key, f->key, f->key_size) ||
        !ml_aes_set_key(&iv_key, essiv_key, f->key_size))
        goto done;
    store_le64(iv_input, sector);
    ml_aes_encrypt_block(&iv_key, iv_input, iv);
    for (offset = 0; offset < sector_size; offset += sizeof(block)) {
        unsigned i;
        for (i = 0; i < sizeof(block); ++i)
            block[i] = f->input[offset + i] ^ iv[i];
        ml_aes_encrypt_block(&data_key, block, f->output + offset);
        memcpy(iv, f->output + offset, sizeof(iv));
    }
    ok = 1;
done:
    memset(&data_key, 0, sizeof(data_key));
    memset(&iv_key, 0, sizeof(iv_key));
    memset(essiv_key, 0, sizeof(essiv_key));
    memset(iv_input, 0, sizeof(iv_input));
    memset(iv, 0, sizeof(iv));
    memset(block, 0, sizeof(block));
    return ok;
}

static int encrypt_payload(fixture *f, uint64_t payload_offset,
                           uint64_t iv_tweak, uint32_t sector_size,
                           uint64_t plain_size, ml_xts_cipher cipher,
                           int aes_cbc_essiv)
{
    uint64_t image_size, sector;
    if (!file_size(f->image, &image_size) || sector_size < 512 ||
        sector_size > sizeof(f->input) || (sector_size & 15u) ||
        (aes_cbc_essiv
            ? (f->key_size != 16 && f->key_size != 24 && f->key_size != 32)
            : (f->key_size != 32 && f->key_size != 64)) ||
        (plain_size % sector_size) || payload_offset > image_size ||
        plain_size > image_size - payload_offset) {
        fprintf(stderr, "payload fixture does not fit its encrypted segment\n");
        return 0;
    }
    if (fseek(f->image, (long)payload_offset, SEEK_SET) != 0) return 0;
    for (sector = 0; sector < plain_size / sector_size; ++sector) {
        if (fread(f->input, 1, sector_size, f->plain) != sector_size) {
            fprintf(stderr, "short plaintext fixture\n");
            return 0;
        }
        if (sector > UINT64_MAX - iv_tweak ||
            (aes_cbc_essiv
                ? !encrypt_cbc_essiv_sector(f, iv_tweak + sector,
                                             sector_size)
                : !ml_xts_encrypt(cipher, f->key, f->key_size,
                    iv_tweak + sector, f->input, f->output, sector_size))) {
            fprintf(stderr, "cannot encrypt fixture sector\n");
            return 0;
        }
        if (fwrite(f->output, 1, sector_size, f->image) != sector_size) {
            perror("write encrypted fixture");
            return 0;
        }
    }
    return fflush(f->image) == 0;
}

static int write_luks1(fixture *f, uint64_t plain_size)
{
    uint64_t payload_offset;
    ml_xts_cipher cipher;
    char name[33];
    size_t i, length = 0;
    if (fread(f->header, 1, LUKS1_HEADER_SIZE, f->image) != LUKS1_HEADER_SIZE ||
        memcmp(f->header, "LUKS\xba\xbe", 6) != 0 ||
        ((uint16_t)f->header[6] << 8 | f->header[7]) != 1 ||
        read_be32(f->header + 108) != f->key_size || f->key_size != 64) {
        fprintf(stderr, "fixture image is not a 512-bit-key LUKS1 volume\n");
        return 0;
    }
    while (length < 32 && f->header[8 + length]) ++length;
    if (length == 0 || length >= 32) return 0;
    for (i = 0; i < length; ++i) name[i] = (char)f->header[8 + i];
    name[length] = '\0';
    if (strcmp(name, "aes") == 0) cipher = ML_XTS_AES;
    else if (strcmp(name, "serpent") == 0) cipher = ML_XTS_SERPENT;
    else if (strcmp(name, "twofish") == 0) cipher = ML_XTS_TWOFISH;
    else {
        fprintf(stderr, "unsupported LUKS1 XTS fixture cipher: %s\n", name);
        return 0;
    }
    payload_offset = (uint64_t)read_be32(f->header + 104) * 512u;
    return encrypt_payload(f, payload_offset, 0, 512, plain_size, cipher, 0);
}

static int write_luks2(fixture *f, uint64_t plain_size)
{
    char *json, *segment, *encryption;
    uint64_t payload_offset, iv_tweak, sector_size;
    ml_xts_cipher cipher;
    int aes_cbc_essiv;
    if (fread(f->header, 1, LUKS2_HEADER_SIZE, f->image) != LUKS2_HEADER_SIZE ||
        memcmp(f->header, "LUKS\xba\xbe", 6) != 0 ||
        ((uint16_t)f->header[6] << 8 | f->header[7]) != 2) {
        fprintf(stderr, "fixture image is not LUKS2\n");
        return 0;
    }
    json = (char *)f->header + LUKS2_JSON_OFFSET;
    json[LUKS2_HEADER_SIZE - LUKS2_JSON_OFFSET - 1] = '\0';
    segment = strstr(json, "\"segments\"");
    if (!segment) return 0;
    segment = strstr(segment, "\"0\"");
    if (!segment) return 0;
    encryption = strstr(segment, "\"encryption\":\"");
    if (!encryption) return 0;
    encryption += strlen("\"encryption\":\"");
    aes_cbc_essiv = strncmp(encryption, "aes-cbc-essiv:sha256",
                            sizeof("aes-cbc-essiv:sha256") - 1) == 0;
    cipher = aes_cbc_essiv ? ML_XTS_AES : detect_cipher(encryption);
    if ((int)cipher < 0 || !json_uint(segment, "offset", &payload_offset) ||
        !json_uint(segment, "iv_tweak", &iv_tweak) ||
        !json_uint(segment, "sector_size", &sector_size) ||
        sector_size > UINT32_MAX) {
        fprintf(stderr, "unsupported or malformed LUKS2 segment fixture\n");
        return 0;
    }
    return encrypt_payload(f, payload_offset, iv_tweak, (uint32_t)sector_size,
                           plain_size, cipher, aes_cbc_essiv);
}

int main(int argc, char **argv)
{
    fixture f;
    uint64_t plain_size, key_size;
    int result = 1;
    memset(&f, 0, sizeof(f));
    if (argc != 4) {
        fprintf(stderr, "usage: make_xts_payload PLAIN_IMAGE LUKS_IMAGE VOLUME_KEY\n");
        return 2;
    }
    f.plain = fopen(argv[1], "rb");
    f.image = fopen(argv[2], "r+b");
    f.key_file = fopen(argv[3], "rb");
    if (!f.plain || !f.image || !f.key_file) {
        perror("open fixture input");
        goto done;
    }
    if (!file_size(f.key_file, &key_size) || key_size == 0 ||
        key_size > sizeof(f.key) || fseek(f.key_file, 0, SEEK_SET) != 0 ||
        fread(f.key, 1, (size_t)key_size, f.key_file) != key_size ||
        !file_size(f.plain, &plain_size)) {
        fprintf(stderr, "short volume key or invalid plaintext fixture\n");
        goto done;
    }
    f.key_size = (size_t)key_size;
    if (fread(f.header, 1, 8, f.image) != 8 || fseek(f.image, 0, SEEK_SET) != 0) {
        fprintf(stderr, "cannot read encrypted fixture header\n");
        goto done;
    }
    if (((uint16_t)f.header[6] << 8 | f.header[7]) == 1)
        result = write_luks1(&f, plain_size) ? 0 : 1;
    else if (((uint16_t)f.header[6] << 8 | f.header[7]) == 2)
        result = write_luks2(&f, plain_size) ? 0 : 1;
    else fprintf(stderr, "fixture image has an unsupported LUKS version\n");

done:
    if (f.plain) fclose(f.plain);
    if (f.image) fclose(f.image);
    if (f.key_file) fclose(f.key_file);
    memset(&f, 0, sizeof(f));
    return result;
}
