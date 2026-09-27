/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef ML_CRYPTO_H
#define ML_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

typedef enum {
    ML_HASH_SHA1 = 1,
    ML_HASH_SHA256 = 2,
    ML_HASH_SHA512 = 3,
    ML_HASH_RIPEMD160 = 4,
    ML_HASH_WHIRLPOOL = 5
} ml_hash_algorithm;

size_t ml_hash_digest_size(ml_hash_algorithm algorithm);
int ml_hash_data(ml_hash_algorithm algorithm,
                 const void *input, size_t input_size, void *output);
int ml_hmac_data(ml_hash_algorithm algorithm,
                 const void *key, size_t key_size,
                 const void *data, size_t data_size, void *output);
int ml_pbkdf2(ml_hash_algorithm algorithm,
              const void *password, size_t password_size,
              const void *salt, size_t salt_size,
              uint32_t iterations, void *output, size_t output_size);

typedef struct {
    uint8_t round_key[240];
    unsigned rounds;
} ml_aes_context;

int ml_aes_set_key(ml_aes_context *context,
                   const uint8_t *key, size_t key_size);
void ml_aes_encrypt_block(const ml_aes_context *context,
                          const uint8_t input[16], uint8_t output[16]);
void ml_aes_decrypt_block(const ml_aes_context *context,
                          const uint8_t input[16], uint8_t output[16]);
int ml_aes_xts_decrypt(const uint8_t *key, size_t key_size,
                       uint64_t sector_number,
                       const uint8_t *input, uint8_t *output, size_t size);

typedef enum {
    ML_XTS_AES = 0,
    ML_XTS_SERPENT = 1,
    ML_XTS_TWOFISH = 2
} ml_xts_cipher;

int ml_xts_decrypt(ml_xts_cipher cipher, const uint8_t *key,
                   size_t key_size, uint64_t sector_number,
                   const uint8_t *input, uint8_t *output, size_t size);
int ml_xts_encrypt(ml_xts_cipher cipher, const uint8_t *key,
                   size_t key_size, uint64_t sector_number,
                   const uint8_t *input, uint8_t *output, size_t size);
int ml_aes_cbc_essiv_decrypt(const uint8_t *key, size_t key_size,
                             uint64_t sector_number,
                             const uint8_t *input, uint8_t *output,
                             size_t size);

#endif
