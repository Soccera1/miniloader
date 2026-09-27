/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "ml_crypto.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#if ML_ENABLE_CIPHER_SERPENT_XTS
#include "serpent.h"
#endif
#if ML_ENABLE_CIPHER_TWOFISH_XTS
#include "twofish.h"
#endif

static void from_hex(const char *hex, uint8_t *output, size_t size)
{
    size_t i;
    for (i = 0; i < size; ++i) {
        unsigned high = hex[i * 2] <= '9' ? (unsigned)(hex[i * 2] - '0')
            : (unsigned)(hex[i * 2] - 'a' + 10);
        unsigned low = hex[i * 2 + 1] <= '9' ? (unsigned)(hex[i * 2 + 1] - '0')
            : (unsigned)(hex[i * 2 + 1] - 'a' + 10);
        output[i] = (uint8_t)((high << 4) | low);
    }
}

static void check_vectors(void)
{
    static const char sha1_vector[] = "0c60c80f961f0e71f3a9b524af6012062fe037a6";
    static const char sha1_iter2_vector[] = "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957";
    static const char sha1_iter2_64_vector[] = "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957cae93136266537a8d7bf4b76c51094cc1ae010b19923ddc4395cd064acb023ffd1edd5ef4be8ffe61426c28e";
    static const char sha256_vector[] = "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b";
    static const char sha512_abc[] = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";
    static const char sha512_pbkdf2[] = "e1d9c16aa681708a45f5c7c4e215ceb66e011a2e9f0040713f18aefdb866d53cf76cab2868a39b9f7840edce4fef5a82be67335c77a6068e04112754f27ccf4e";
    static const char ripemd160_abc[] = "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc";
    static const char ripemd160_pbkdf2[] = "768dcc27b7bfdef794a1ff9d935090fcf598555e66913180b9ce363c615e9ed953b95fd07169be53";
    static const char whirlpool_abc[] = "4e2448a4c6f486bb16b6562c73b4020bf3043e3a731bce721ae1b303d97e6d4c7181eebdb6c57e277d0e34957114cbd6c797fc9d95d8b582d225292076d4eef5";
    static const char whirlpool_pbkdf2[] = "110b2e4266f03c334f6085bf421a68d6976a2f767e0bb6041a9c9315ec0d249fc8cb5fac1f9f3b87dbb98e9b4b220dfe0d6b55f88109dd558c30f0a0356f7d9f";
    static const char cbc_essiv_ciphertext[] = "70979459b899f8eb0d02c3b12fe6033827d3ca31f992966077e9ca8f34b4a3dc";
    static const char aes_key_hex[] = "000102030405060708090a0b0c0d0e0f";
    static const char aes_input_hex[] = "00112233445566778899aabbccddeeff";
    static const char aes_output_hex[] = "69c4e0d86a7b0430d8cdb78070b4c55a";
    uint8_t output[64], expected[64], key[16], input[16];
    uint8_t cbc_key[32], cbc_input[32], cbc_plain[32];
    ml_aes_context aes;
    assert(ml_pbkdf2(ML_HASH_SHA1, "password", 8, "salt", 4, 1,
                     output, 20));
    from_hex(sha1_vector, expected, 20);
    assert(memcmp(output, expected, 20) == 0);
    assert(ml_pbkdf2(ML_HASH_SHA1, "password", 8, "salt", 4, 2,
                     output, 20));
    from_hex(sha1_iter2_vector, expected, 20);
    assert(memcmp(output, expected, 20) == 0);
    assert(ml_pbkdf2(ML_HASH_SHA1, "password", 8, "salt", 4, 2,
                     output, 64));
    from_hex(sha1_iter2_64_vector, expected, 64);
    assert(memcmp(output, expected, 64) == 0);
    assert(ml_pbkdf2(ML_HASH_SHA256, "password", 8, "salt", 4, 1,
                     output, 32));
    from_hex(sha256_vector, expected, 32);
    assert(memcmp(output, expected, 32) == 0);
    assert(ml_hash_data(ML_HASH_SHA512, "abc", 3, output));
    from_hex(sha512_abc, expected, 64);
    assert(memcmp(output, expected, 64) == 0);
    assert(ml_pbkdf2(ML_HASH_SHA512, "password", 8, "salt", 4, 2,
                     output, 64));
    from_hex(sha512_pbkdf2, expected, 64);
    assert(memcmp(output, expected, 64) == 0);
    assert(ml_hash_data(ML_HASH_RIPEMD160, "abc", 3, output));
    from_hex(ripemd160_abc, expected, 20);
    assert(memcmp(output, expected, 20) == 0);
    assert(ml_pbkdf2(ML_HASH_RIPEMD160, "password", 8, "salt", 4, 2,
                     output, 40));
    from_hex(ripemd160_pbkdf2, expected, 40);
    assert(memcmp(output, expected, 40) == 0);
    assert(ml_hash_data(ML_HASH_WHIRLPOOL, "abc", 3, output));
    from_hex(whirlpool_abc, expected, 64);
    assert(memcmp(output, expected, 64) == 0);
    assert(ml_pbkdf2(ML_HASH_WHIRLPOOL, "password", 8, "salt", 4, 2,
                     output, 64));
    from_hex(whirlpool_pbkdf2, expected, 64);
    assert(memcmp(output, expected, 64) == 0);
    from_hex(aes_key_hex, key, sizeof(key));
    from_hex(aes_input_hex, input, sizeof(input));
    from_hex(aes_output_hex, expected, 16);
    assert(ml_aes_set_key(&aes, key, sizeof(key)));
    ml_aes_encrypt_block(&aes, input, output);
    assert(memcmp(output, expected, 16) == 0);
    ml_aes_decrypt_block(&aes, output, output);
    assert(memcmp(output, input, 16) == 0);
    from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
             cbc_plain, sizeof(cbc_plain));
    from_hex(cbc_essiv_ciphertext, cbc_input, sizeof(cbc_input));
    for (size_t i = 0; i < sizeof(cbc_key); ++i) cbc_key[i] = (uint8_t)i;
    assert(ml_aes_cbc_essiv_decrypt(cbc_key, sizeof(cbc_key),
             0x0102030405060708ull, cbc_input, output, sizeof(cbc_input)));
    assert(memcmp(output, cbc_plain, sizeof(cbc_plain)) == 0);
}

static void check_xts_round_trip(void)
{
    uint8_t key[64], plain[512], cipher[512], result[512], tweak_input[16] = {0};
    uint8_t tweak[16], block[16];
    ml_aes_context data_key, tweak_key;
    size_t offset;
    unsigned i;
    for (i = 0; i < sizeof(key); ++i) key[i] = (uint8_t)(i * 3u + 1u);
    for (i = 0; i < sizeof(plain); ++i) plain[i] = (uint8_t)(i * 37u + 9u);
    assert(ml_aes_set_key(&data_key, key, 32));
    assert(ml_aes_set_key(&tweak_key, key + 32, 32));
    tweak_input[0] = 7;
    ml_aes_encrypt_block(&tweak_key, tweak_input, tweak);
    for (offset = 0; offset < sizeof(plain); offset += 16) {
        uint8_t carry = 0;
        for (i = 0; i < 16; ++i) block[i] = plain[offset + i] ^ tweak[i];
        ml_aes_encrypt_block(&data_key, block, block);
        for (i = 0; i < 16; ++i) cipher[offset + i] = block[i] ^ tweak[i];
        for (i = 0; i < 16; ++i) {
            uint8_t next = (uint8_t)(tweak[i] >> 7);
            tweak[i] = (uint8_t)((tweak[i] << 1) | carry);
            carry = next;
        }
        if (carry) tweak[0] ^= 0x87u;
    }
    assert(ml_aes_xts_decrypt(key, sizeof(key), 7, cipher, result,
                              sizeof(cipher)));
    assert(memcmp(result, plain, sizeof(plain)) == 0);
}

static void check_alt_cipher_vectors(void)
{
    uint8_t key[32] = {0}, input[16] = {0}, output[16], expected[16];
#if ML_ENABLE_CIPHER_SERPENT_XTS
    struct serpent_ctx serpent;
    from_hex("d29d576fcea3a3a7ed9099f29273d78e", input, sizeof(input));
    from_hex("b2288b968ae8b08648d1ce9606fd992d", expected, sizeof(expected));
    serpent_set_key(&serpent, 16, key);
    serpent_encrypt(&serpent, sizeof(input), output, input);
    assert(memcmp(output, expected, sizeof(output)) == 0);
    serpent_decrypt(&serpent, sizeof(input), output, output);
    assert(memcmp(output, input, sizeof(output)) == 0);
#endif
#if ML_ENABLE_CIPHER_TWOFISH_XTS
    memset(input, 0, sizeof(input));
    from_hex("9f589f5cf6122c32b6bfec2f2ae8c35a", expected, sizeof(expected));
    {
        struct twofish_ctx twofish;
        twofish_set_key(&twofish, 16, key);
        twofish_encrypt(&twofish, sizeof(input), output, input);
        assert(memcmp(output, expected, sizeof(output)) == 0);
        twofish_decrypt(&twofish, sizeof(input), output, output);
        assert(memcmp(output, input, sizeof(output)) == 0);
    }
#endif
}

int main(void)
{
    check_vectors();
    check_xts_round_trip();
    check_alt_cipher_vectors();
    puts("SHA-1/SHA-256/SHA-512/RIPEMD160/Whirlpool, PBKDF2, AES, and XTS tests passed");
    return 0;
}
