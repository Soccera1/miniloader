/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * Independent read-only LUKS1 AES reader. The on-disk header and keyslot
 * flow follow GRUB's LUKS driver and the LUKS1 on-disk format specification.
 * No GRUB runtime or command interpreter is included.
 */
#include "ml_luks1.h"
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

#define LUKS1_HEADER_BYTES 592u
#define LUKS1_KEY_ENABLED 0x00ac71f3u
#define LUKS1_KEY_DISABLED 0x0000deadu
#define LUKS1_MAX_ITERATIONS 10000000u

static uint16_t luks_be16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static uint32_t luks_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}

static int luks_copy_string(char *out, size_t capacity,
                            const uint8_t *input, size_t input_size)
{
    size_t length = 0, i;
    while (length < input_size && input[length]) ++length;
    if (length == 0 || length == input_size || length >= capacity) return 0;
    for (i = 0; i < length; ++i) {
        if (input[i] < 0x20 || input[i] > 0x7e) return 0;
        out[i] = (char)input[i];
    }
    out[length] = '\0';
    return 1;
}

static int luks_text_equal(const char *a, const char *b)
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

static void luks_zero(void *buffer, size_t size)
{
    volatile uint8_t *p = (volatile uint8_t *)buffer;
    while (size--) *p++ = 0;
}

static int luks_diffuse(ml_hash_algorithm hash, uint8_t *data, size_t size)
{
    uint8_t input[68], digest[64];
    size_t digest_size = ml_hash_digest_size(hash), offset = 0;
    uint32_t chunk = 0;
    while (offset < size) {
        size_t amount = size - offset;
        size_t i;
        if (amount > digest_size) amount = digest_size;
        input[0] = (uint8_t)(chunk >> 24);
        input[1] = (uint8_t)(chunk >> 16);
        input[2] = (uint8_t)(chunk >> 8);
        input[3] = (uint8_t)chunk;
        for (i = 0; i < amount; ++i) input[4 + i] = data[offset + i];
        if (!ml_hash_data(hash, input, 4 + amount, digest)) return 0;
        for (i = 0; i < amount; ++i) data[offset + i] = digest[i];
        offset += amount;
        chunk++;
    }
    luks_zero(input, sizeof(input));
    luks_zero(digest, sizeof(digest));
    return 1;
}

static int luks_af_merge(ml_hash_algorithm hash,
                         const uint8_t *split, uint8_t *key,
                         size_t key_size, uint32_t stripes)
{
    uint32_t stripe;
    size_t i;
    for (i = 0; i < key_size; ++i) key[i] = 0;
    for (stripe = 0; stripe + 1 < stripes; ++stripe) {
        const uint8_t *part = split + (size_t)stripe * key_size;
        for (i = 0; i < key_size; ++i) key[i] ^= part[i];
        if (!luks_diffuse(hash, key, key_size)) return 0;
    }
    split += (size_t)(stripes - 1) * key_size;
    for (i = 0; i < key_size; ++i) key[i] ^= split[i];
    return 1;
}

static int luks_constant_equal(const uint8_t *a, const uint8_t *b,
                               size_t size)
{
    uint8_t difference = 0;
    size_t i;
    for (i = 0; i < size; ++i) difference |= a[i] ^ b[i];
    return difference == 0;
}

static int luks_decrypt_keyslot(const uint8_t *key, size_t key_size,
                                uint8_t cipher_profile, uint8_t *material,
                                size_t size)
{
    size_t sector;
    if ((size & 511u) != 0) return 0;
    for (sector = 0; sector < size / 512u; ++sector) {
        uint8_t *data = material + sector * 512u;
        if (cipher_profile == 1
                ? !ml_aes_cbc_essiv_decrypt(key, key_size, sector,
                                            data, data, 512u)
                : !ml_xts_decrypt((ml_xts_cipher)(cipher_profile == 2 ?
                                      ML_XTS_SERPENT : cipher_profile == 3 ?
                                      ML_XTS_TWOFISH : ML_XTS_AES),
                                  key, key_size, sector, data, data, 512u))
            return 0;
    }
    return 1;
}

static int luks_volume_read(void *context, uint64_t offset,
                            void *buffer, size_t length)
{
    ml_luks1_volume *volume = (ml_luks1_volume *)context;
    uint8_t *out = (uint8_t *)buffer;
    size_t done = 0;
    if (!volume || !volume->parent || (!buffer && length)) return -1;
    while (done < length) {
        uint64_t at = offset + done;
        uint64_t sector_number, physical;
        size_t within, amount;
        if (at < offset || at >= volume->byte_size) return -1;
        sector_number = at / 512u;
        within = (size_t)(at % 512u);
        amount = 512u - within;
        if (amount > length - done) amount = length - done;
        if (sector_number > UINT64_MAX / 512u ||
            volume->payload_offset > UINT64_MAX - sector_number * 512u)
            return -1;
        physical = volume->payload_offset + sector_number * 512u;
        if (ml_block_read(volume->parent, physical, volume->sector_buffer,
                          sizeof(volume->sector_buffer)) != ML_BLOCK_OK)
            return -1;
        if (volume->cipher_profile == 1
                ? !ml_aes_cbc_essiv_decrypt(volume->master_key,
                    volume->key_bytes, sector_number, volume->sector_buffer,
                    volume->sector_buffer, sizeof(volume->sector_buffer))
                : !ml_xts_decrypt((ml_xts_cipher)(volume->cipher_profile == 2 ?
                    ML_XTS_SERPENT : volume->cipher_profile == 3 ?
                    ML_XTS_TWOFISH : ML_XTS_AES), volume->master_key,
                    volume->key_bytes, sector_number, volume->sector_buffer,
                    volume->sector_buffer, sizeof(volume->sector_buffer)))
            return -1;
        for (size_t i = 0; i < amount; ++i)
            out[done + i] = volume->sector_buffer[within + i];
        done += amount;
    }
    return 0;
}

ml_luks1_result ml_luks1_open(ml_luks1_volume *volume,
                              const ml_block_device *device,
                              const void *passphrase, size_t passphrase_size,
                              void *scratch, size_t scratch_size,
    const char **message)
{
    uint8_t header[LUKS1_HEADER_BYTES];
    uint8_t digest[20];
    uint8_t candidate[ML_LUKS1_MAX_KEY_BYTES];
    char cipher[33], mode[33], hash_name[33];
    ml_hash_algorithm hash;
    uint32_t payload_sector, key_bytes, digest_iterations;
    uint8_t cipher_profile = 0;
#if ML_ENABLE_CIPHER_AES_CBC_ESSIV
    int cipher_is_aes = 0;
#endif
    size_t slot, i;
    if (message) *message = NULL;
#if !ML_ENABLE_KDF_PBKDF2
    return message ? (*message = "PBKDF2 support is disabled in this build", ML_LUKS1_UNSUPPORTED)
                   : ML_LUKS1_UNSUPPORTED;
#endif
#if !ML_ENABLE_CIPHER_AES_XTS && !ML_ENABLE_CIPHER_AES_CBC_ESSIV && \
    !ML_ENABLE_CIPHER_SERPENT_XTS && !ML_ENABLE_CIPHER_TWOFISH_XTS
    return message ? (*message = "LUKS1 cipher support is disabled in this build", ML_LUKS1_UNSUPPORTED)
                   : ML_LUKS1_UNSUPPORTED;
#endif
    if (!volume || !device || !device->read_at || !passphrase ||
        passphrase_size == 0 || !scratch)
        return message ? (*message = "invalid LUKS1 unlock arguments", ML_LUKS1_INVALID)
                       : ML_LUKS1_INVALID;
    luks_zero(volume, sizeof(*volume));
    if (scratch_size < ML_LUKS1_SCRATCH_BYTES)
        return message ? (*message = "LUKS1 key material scratch buffer is too small", ML_LUKS1_RANGE)
                       : ML_LUKS1_RANGE;
    if (ml_block_read(device, 0, header, sizeof(header)) != ML_BLOCK_OK)
        return message ? (*message = "cannot read LUKS1 header", ML_LUKS1_IO)
                       : ML_LUKS1_IO;
    if (header[0] != 'L' || header[1] != 'U' || header[2] != 'K' ||
        header[3] != 'S' || header[4] != 0xba || header[5] != 0xbe)
        return ML_LUKS1_NOT_LUKS;
    if (luks_be16(header + 6) != 1)
        return message ? (*message = "LUKS header version is not LUKS1", ML_LUKS1_UNSUPPORTED)
                       : ML_LUKS1_UNSUPPORTED;
    if (!luks_copy_string(cipher, sizeof(cipher), header + 8, 32) ||
        !luks_copy_string(mode, sizeof(mode), header + 40, 32) ||
        !luks_copy_string(hash_name, sizeof(hash_name), header + 72, 32))
        return message ? (*message = "malformed LUKS1 cipher or hash name", ML_LUKS1_BAD_FORMAT)
                       : ML_LUKS1_BAD_FORMAT;
    if (luks_text_equal(cipher, "aes")) {
#if ML_ENABLE_CIPHER_AES_CBC_ESSIV
        cipher_is_aes = 1;
#endif
    }
    else if (luks_text_equal(cipher, "serpent")) {
#if ML_ENABLE_CIPHER_SERPENT_XTS
        cipher_profile = 2;
#else
        return message ? (*message = "Serpent-XTS support is disabled in this build", ML_LUKS1_UNSUPPORTED)
                       : ML_LUKS1_UNSUPPORTED;
#endif
    } else if (luks_text_equal(cipher, "twofish")) {
#if ML_ENABLE_CIPHER_TWOFISH_XTS
        cipher_profile = 3;
#else
        return message ? (*message = "Twofish-XTS support is disabled in this build", ML_LUKS1_UNSUPPORTED)
                       : ML_LUKS1_UNSUPPORTED;
#endif
    } else return message ? (*message = "LUKS1 cipher is unsupported; supported ciphers are AES, Serpent, and Twofish", ML_LUKS1_UNSUPPORTED)
                          : ML_LUKS1_UNSUPPORTED;
    if (luks_text_equal(mode, "xts-plain64")) {
        if (cipher_profile == 0) {
#if !ML_ENABLE_CIPHER_AES_XTS
            return message ? (*message = "AES-XTS support is disabled in this build", ML_LUKS1_UNSUPPORTED)
                           : ML_LUKS1_UNSUPPORTED;
#endif
        }
    } else if (luks_text_equal(mode, "cbc-essiv:sha256")) {
#if !ML_ENABLE_CIPHER_AES_CBC_ESSIV
        return message ? (*message = "AES-CBC-ESSIV:sha256 support is disabled in this build", ML_LUKS1_UNSUPPORTED)
                       : ML_LUKS1_UNSUPPORTED;
#else
        if (!cipher_is_aes)
            return message ? (*message = "CBC-ESSIV is only supported with AES", ML_LUKS1_UNSUPPORTED)
                           : ML_LUKS1_UNSUPPORTED;
        cipher_profile = 1;
#endif
    } else {
        return message ? (*message = "LUKS1 cipher mode is unsupported; supported modes are XTS-plain64 and AES-CBC-ESSIV:sha256", ML_LUKS1_UNSUPPORTED)
                       : ML_LUKS1_UNSUPPORTED;
    }
    if (luks_text_equal(hash_name, "sha1")) hash = ML_HASH_SHA1;
    else if (luks_text_equal(hash_name, "sha256")) hash = ML_HASH_SHA256;
    else if (luks_text_equal(hash_name, "sha512")) hash = ML_HASH_SHA512;
    else if (luks_text_equal(hash_name, "ripemd160")) hash = ML_HASH_RIPEMD160;
    else if (luks_text_equal(hash_name, "whirlpool")) hash = ML_HASH_WHIRLPOOL;
    else return message ? (*message = "LUKS1 PBKDF2 hash is unsupported; this build supports SHA-1, SHA-256, SHA-512, RIPEMD160, and Whirlpool", ML_LUKS1_UNSUPPORTED)
                        : ML_LUKS1_UNSUPPORTED;
    payload_sector = luks_be32(header + 104);
    key_bytes = luks_be32(header + 108);
    digest_iterations = luks_be32(header + 164);
    if (!payload_sector ||
        (cipher_profile == 1 ? (key_bytes != 16 && key_bytes != 24 && key_bytes != 32)
                   : (key_bytes != 32 && key_bytes != 64)) ||
        (uint64_t)payload_sector * 512u >= device->byte_size ||
        digest_iterations == 0 || digest_iterations > LUKS1_MAX_ITERATIONS)
        return message ? (*message = "invalid LUKS1 payload or master-key digest parameters", ML_LUKS1_BAD_FORMAT)
                       : ML_LUKS1_BAD_FORMAT;
    for (slot = 0; slot < 8; ++slot) {
        const uint8_t *record = header + 208 + slot * 48;
        uint32_t active = luks_be32(record);
        uint32_t iterations = luks_be32(record + 4);
        uint32_t material_sector = luks_be32(record + 40);
        uint32_t stripes = luks_be32(record + 44);
        uint64_t material_offset, material_bytes, payload_offset;
        uint8_t *material = (uint8_t *)scratch;
        uint8_t pass_key[ML_LUKS1_MAX_KEY_BYTES];
        if (active == LUKS1_KEY_DISABLED) continue;
        if (active != LUKS1_KEY_ENABLED)
            return message ? (*message = "invalid LUKS1 keyslot state", ML_LUKS1_BAD_FORMAT)
                           : ML_LUKS1_BAD_FORMAT;
        if (iterations == 0 || iterations > LUKS1_MAX_ITERATIONS ||
            stripes == 0 || stripes > ML_LUKS1_MAX_STRIPES || !material_sector)
            return message ? (*message = "LUKS1 keyslot KDF or stripe parameters exceed supported limits", ML_LUKS1_UNSUPPORTED)
                           : ML_LUKS1_UNSUPPORTED;
        material_bytes = (uint64_t)key_bytes * stripes;
        material_offset = (uint64_t)material_sector * 512u;
        payload_offset = (uint64_t)payload_sector * 512u;
        if (material_bytes > scratch_size || material_bytes > SIZE_MAX ||
            (material_bytes & 511u) || material_offset > payload_offset ||
            material_bytes > payload_offset - material_offset ||
            material_offset > device->byte_size ||
            material_bytes > device->byte_size - material_offset)
            return message ? (*message = "LUKS1 keyslot material lies outside the key area", ML_LUKS1_BAD_FORMAT)
                           : ML_LUKS1_BAD_FORMAT;
        if (!ml_pbkdf2(hash, passphrase, passphrase_size,
                       record + 8, 32, iterations, pass_key, key_bytes)) {
            luks_zero(pass_key, sizeof(pass_key));
            return message ? (*message = "LUKS1 PBKDF2 derivation failed", ML_LUKS1_UNSUPPORTED)
                           : ML_LUKS1_UNSUPPORTED;
        }
        if (ml_block_read(device, material_offset, material,
                          (size_t)material_bytes) != ML_BLOCK_OK) {
            luks_zero(pass_key, sizeof(pass_key));
            return message ? (*message = "cannot read LUKS1 keyslot material", ML_LUKS1_IO)
                           : ML_LUKS1_IO;
        }
        if (!luks_decrypt_keyslot(pass_key, key_bytes, cipher_profile, material,
                                  (size_t)material_bytes) ||
            !luks_af_merge(hash, material, candidate, key_bytes, stripes)) {
            luks_zero(pass_key, sizeof(pass_key));
            luks_zero(material, (size_t)material_bytes);
            return message ? (*message = "LUKS1 keyslot decryption failed", ML_LUKS1_UNSUPPORTED)
                           : ML_LUKS1_UNSUPPORTED;
        }
        if (!ml_pbkdf2(hash, candidate, key_bytes, header + 132, 32,
                       digest_iterations, digest, sizeof(digest))) {
            luks_zero(pass_key, sizeof(pass_key));
            luks_zero(material, (size_t)material_bytes);
            luks_zero(candidate, sizeof(candidate));
            return message ? (*message = "LUKS1 master-key digest derivation failed", ML_LUKS1_UNSUPPORTED)
                           : ML_LUKS1_UNSUPPORTED;
        }
        luks_zero(pass_key, sizeof(pass_key));
        luks_zero(material, (size_t)material_bytes);
        if (!luks_constant_equal(digest, header + 112, sizeof(digest))) {
            luks_zero(candidate, sizeof(candidate));
            continue;
        }
        for (i = 0; i < key_bytes; ++i) volume->master_key[i] = candidate[i];
        volume->key_bytes = key_bytes;
        volume->parent = device;
        volume->payload_offset = payload_offset;
        volume->byte_size = device->byte_size - payload_offset;
        volume->cipher_profile = cipher_profile;
        volume->device.context = volume;
        volume->device.byte_size = volume->byte_size;
        volume->device.logical_block_size = 512;
        volume->device.read_at = luks_volume_read;
        luks_zero(candidate, sizeof(candidate));
        luks_zero(digest, sizeof(digest));
        luks_zero(header, sizeof(header));
        return ML_LUKS1_OK;
    }
    luks_zero(candidate, sizeof(candidate));
    luks_zero(digest, sizeof(digest));
    luks_zero(header, sizeof(header));
    return message ? (*message = "LUKS1 passphrase did not unlock any keyslot", ML_LUKS1_WRONG_PASSPHRASE)
                   : ML_LUKS1_WRONG_PASSPHRASE;
}
