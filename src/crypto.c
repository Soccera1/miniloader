/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Standalone SHA-1, SHA-256, SHA-512, RIPEMD160, Whirlpool, PBKDF2, AES and XTS. */
#include "ml_crypto.h"

#ifndef ML_ENABLE_CIPHER_SERPENT_XTS
#define ML_ENABLE_CIPHER_SERPENT_XTS 0
#endif
#ifndef ML_ENABLE_CIPHER_TWOFISH_XTS
#define ML_ENABLE_CIPHER_TWOFISH_XTS 0
#endif

#if ML_ENABLE_CIPHER_SERPENT_XTS
#include "serpent.h"
#endif
#if ML_ENABLE_CIPHER_TWOFISH_XTS
#include "twofish.h"
#endif

typedef struct {
    ml_hash_algorithm algorithm;
    uint32_t state[8];
    uint64_t state64[8];
    uint64_t byte_count;
    uint8_t block[128];
    size_t used;
} ml_hash_context;

static uint32_t rotr32(uint32_t value, unsigned count)
{
    return (value >> count) | (value << (32u - count));
}

static uint64_t rotr64(uint64_t value, unsigned count)
{
    return (value >> count) | (value << (64u - count));
}

static uint32_t load_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static uint32_t load_le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t load_be64(const uint8_t *p)
{
    uint64_t value = 0;
    unsigned i;
    for (i = 0; i < 8; ++i) value = (value << 8) | p[i];
    return value;
}

static void store_be32(uint8_t *p, uint32_t value)
{
    p[0] = (uint8_t)(value >> 24);
    p[1] = (uint8_t)(value >> 16);
    p[2] = (uint8_t)(value >> 8);
    p[3] = (uint8_t)value;
}

static void store_le32(uint8_t *p, uint32_t value)
{
    p[0] = (uint8_t)value;
    p[1] = (uint8_t)(value >> 8);
    p[2] = (uint8_t)(value >> 16);
    p[3] = (uint8_t)(value >> 24);
}

static void store_le64(uint8_t *p, uint64_t value)
{
    unsigned i;
    for (i = 0; i < 8; ++i) p[i] = (uint8_t)(value >> (i * 8u));
}

static void store_be64(uint8_t *p, uint64_t value)
{
    unsigned i;
    for (i = 0; i < 8; ++i) p[i] = (uint8_t)(value >> (56u - i * 8u));
}

static void sha1_transform(ml_hash_context *context, const uint8_t block[64])
{
    uint32_t w[80], a, b, c, d, e;
    unsigned i;
    for (i = 0; i < 16; ++i) w[i] = load_be32(block + i * 4u);
    for (; i < 80; ++i) {
        uint32_t x = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16];
        w[i] = (x << 1) | (x >> 31);
    }
    a = context->state[0]; b = context->state[1]; c = context->state[2];
    d = context->state[3]; e = context->state[4];
    for (i = 0; i < 80; ++i) {
        uint32_t f, k, temp;
        if (i < 20) { f = (b & c) | (~b & d); k = 0x5a827999u; }
        else if (i < 40) { f = b ^ c ^ d; k = 0x6ed9eba1u; }
        else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8f1bbcdcu; }
        else { f = b ^ c ^ d; k = 0xca62c1d6u; }
        temp = ((a << 5) | (a >> 27)) + f + e + k + w[i];
        e = d; d = c; c = (b << 30) | (b >> 2); b = a; a = temp;
    }
    context->state[0] += a; context->state[1] += b;
    context->state[2] += c; context->state[3] += d;
    context->state[4] += e;
}

static const uint32_t sha256_k[64] = {
    0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
    0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
    0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
    0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
    0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
    0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
    0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
    0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
};

static void sha256_transform(ml_hash_context *context, const uint8_t block[64])
{
    uint32_t w[64], a, b, c, d, e, f, g, h;
    unsigned i;
    for (i = 0; i < 16; ++i) w[i] = load_be32(block + i * 4u);
    for (; i < 64; ++i) {
        uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    a = context->state[0]; b = context->state[1]; c = context->state[2]; d = context->state[3];
    e = context->state[4]; f = context->state[5]; g = context->state[6]; h = context->state[7];
    for (i = 0; i < 64; ++i) {
        uint32_t s1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        uint32_t choice = (e & f) ^ (~e & g);
        uint32_t t1 = h + s1 + choice + sha256_k[i] + w[i];
        uint32_t s0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = s0 + majority;
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    context->state[0] += a; context->state[1] += b;
    context->state[2] += c; context->state[3] += d;
    context->state[4] += e; context->state[5] += f;
    context->state[6] += g; context->state[7] += h;
}

static const uint64_t sha512_k[80] = {
    0x428a2f98d728ae22ull,0x7137449123ef65cdull,0xb5c0fbcfec4d3b2full,0xe9b5dba58189dbbcull,
    0x3956c25bf348b538ull,0x59f111f1b605d019ull,0x923f82a4af194f9bull,0xab1c5ed5da6d8118ull,
    0xd807aa98a3030242ull,0x12835b0145706fbeull,0x243185be4ee4b28cull,0x550c7dc3d5ffb4e2ull,
    0x72be5d74f27b896full,0x80deb1fe3b1696b1ull,0x9bdc06a725c71235ull,0xc19bf174cf692694ull,
    0xe49b69c19ef14ad2ull,0xefbe4786384f25e3ull,0x0fc19dc68b8cd5b5ull,0x240ca1cc77ac9c65ull,
    0x2de92c6f592b0275ull,0x4a7484aa6ea6e483ull,0x5cb0a9dcbd41fbd4ull,0x76f988da831153b5ull,
    0x983e5152ee66dfabull,0xa831c66d2db43210ull,0xb00327c898fb213full,0xbf597fc7beef0ee4ull,
    0xc6e00bf33da88fc2ull,0xd5a79147930aa725ull,0x06ca6351e003826full,0x142929670a0e6e70ull,
    0x27b70a8546d22ffcull,0x2e1b21385c26c926ull,0x4d2c6dfc5ac42aedull,0x53380d139d95b3dfull,
    0x650a73548baf63deull,0x766a0abb3c77b2a8ull,0x81c2c92e47edaee6ull,0x92722c851482353bull,
    0xa2bfe8a14cf10364ull,0xa81a664bbc423001ull,0xc24b8b70d0f89791ull,0xc76c51a30654be30ull,
    0xd192e819d6ef5218ull,0xd69906245565a910ull,0xf40e35855771202aull,0x106aa07032bbd1b8ull,
    0x19a4c116b8d2d0c8ull,0x1e376c085141ab53ull,0x2748774cdf8eeb99ull,0x34b0bcb5e19b48a8ull,
    0x391c0cb3c5c95a63ull,0x4ed8aa4ae3418acbull,0x5b9cca4f7763e373ull,0x682e6ff3d6b2b8a3ull,
    0x748f82ee5defb2fcull,0x78a5636f43172f60ull,0x84c87814a1f0ab72ull,0x8cc702081a6439ecull,
    0x90befffa23631e28ull,0xa4506cebde82bde9ull,0xbef9a3f7b2c67915ull,0xc67178f2e372532bull,
    0xca273eceea26619cull,0xd186b8c721c0c207ull,0xeada7dd6cde0eb1eull,0xf57d4f7fee6ed178ull,
    0x06f067aa72176fbaull,0x0a637dc5a2c898a6ull,0x113f9804bef90daeull,0x1b710b35131c471bull,
    0x28db77f523047d84ull,0x32caab7b40c72493ull,0x3c9ebe0a15c9bebcull,0x431d67c49c100d4cull,
    0x4cc5d4becb3e42b6ull,0x597f299cfc657e2aull,0x5fcb6fab3ad6faecull,0x6c44198c4a475817ull
};

static void sha512_transform(ml_hash_context *context, const uint8_t block[128])
{
    uint64_t w[80], a, b, c, d, e, f, g, h;
    unsigned i;
    for (i = 0; i < 16; ++i) w[i] = load_be64(block + i * 8u);
    for (; i < 80; ++i) {
        uint64_t s0 = rotr64(w[i - 15], 1) ^ rotr64(w[i - 15], 8) ^
                      (w[i - 15] >> 7);
        uint64_t s1 = rotr64(w[i - 2], 19) ^ rotr64(w[i - 2], 61) ^
                      (w[i - 2] >> 6);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    a = context->state64[0]; b = context->state64[1];
    c = context->state64[2]; d = context->state64[3];
    e = context->state64[4]; f = context->state64[5];
    g = context->state64[6]; h = context->state64[7];
    for (i = 0; i < 80; ++i) {
        uint64_t s1 = rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41);
        uint64_t choice = (e & f) ^ (~e & g);
        uint64_t t1 = h + s1 + choice + sha512_k[i] + w[i];
        uint64_t s0 = rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39);
        uint64_t majority = (a & b) ^ (a & c) ^ (b & c);
        uint64_t t2 = s0 + majority;
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    context->state64[0] += a; context->state64[1] += b;
    context->state64[2] += c; context->state64[3] += d;
    context->state64[4] += e; context->state64[5] += f;
    context->state64[6] += g; context->state64[7] += h;
}

/* Whirlpool v3.0 (2003), designed by Paulo S. L. M. Barreto and Vincent Rijmen. */
static const uint8_t whirlpool_sbox[256] = {
    0x18,0x23,0xc6,0xe8,0x87,0xb8,0x01,0x4f,0x36,0xa6,0xd2,0xf5,0x79,0x6f,0x91,0x52,
    0x60,0xbc,0x9b,0x8e,0xa3,0x0c,0x7b,0x35,0x1d,0xe0,0xd7,0xc2,0x2e,0x4b,0xfe,0x57,
    0x15,0x77,0x37,0xe5,0x9f,0xf0,0x4a,0xda,0x58,0xc9,0x29,0x0a,0xb1,0xa0,0x6b,0x85,
    0xbd,0x5d,0x10,0xf4,0xcb,0x3e,0x05,0x67,0xe4,0x27,0x41,0x8b,0xa7,0x7d,0x95,0xd8,
    0xfb,0xee,0x7c,0x66,0xdd,0x17,0x47,0x9e,0xca,0x2d,0xbf,0x07,0xad,0x5a,0x83,0x33,
    0x63,0x02,0xaa,0x71,0xc8,0x19,0x49,0xd9,0xf2,0xe3,0x5b,0x88,0x9a,0x26,0x32,0xb0,
    0xe9,0x0f,0xd5,0x80,0xbe,0xcd,0x34,0x48,0xff,0x7a,0x90,0x5f,0x20,0x68,0x1a,0xae,
    0xb4,0x54,0x93,0x22,0x64,0xf1,0x73,0x12,0x40,0x08,0xc3,0xec,0xdb,0xa1,0x8d,0x3d,
    0x97,0x00,0xcf,0x2b,0x76,0x82,0xd6,0x1b,0xb5,0xaf,0x6a,0x50,0x45,0xf3,0x30,0xef,
    0x3f,0x55,0xa2,0xea,0x65,0xba,0x2f,0xc0,0xde,0x1c,0xfd,0x4d,0x92,0x75,0x06,0x8a,
    0xb2,0xe6,0x0e,0x1f,0x62,0xd4,0xa8,0x96,0xf9,0xc5,0x25,0x59,0x84,0x72,0x39,0x4c,
    0x5e,0x78,0x38,0x8c,0xd1,0xa5,0xe2,0x61,0xb3,0x21,0x9c,0x1e,0x43,0xc7,0xfc,0x04,
    0x51,0x99,0x6d,0x0d,0xfa,0xdf,0x7e,0x24,0x3b,0xab,0xce,0x11,0x8f,0x4e,0xb7,0xeb,
    0x3c,0x81,0x94,0xf7,0xb9,0x13,0x2c,0xd3,0xe7,0x6e,0xc4,0x03,0x56,0x44,0x7f,0xa9,
    0x2a,0xbb,0xc1,0x53,0xdc,0x0b,0x9d,0x6c,0x31,0x74,0xf6,0x46,0xac,0x89,0x14,0xe1,
    0x16,0x3a,0x69,0x09,0x70,0xb6,0xd0,0xed,0xcc,0x42,0x98,0xa4,0x28,0x5c,0xf8,0x86
};

static const uint64_t whirlpool_round_constants[10] = {
    0x1823c6e887b8014full,0x36a6d2f5796f9152ull,
    0x60bc9b8ea30c7b35ull,0x1de0d7c22e4bfe57ull,
    0x157737e59ff04adaull,0x58c9290ab1a06b85ull,
    0xbd5d10f4cb3e0567ull,0xe427418ba77d95d8ull,
    0xfbee7c66dd17479eull,0xca2dbf07ad5a8333ull
};

static uint64_t whirlpool_c0[256];
static int whirlpool_tables_ready;

static uint8_t whirlpool_xtime(uint8_t value)
{
    return (uint8_t)((value << 1) ^ ((value & 0x80u) ? 0x1du : 0u));
}

static uint8_t whirlpool_multiply(uint8_t value, unsigned factor)
{
    uint8_t result = 0;
    while (factor) {
        if (factor & 1u) result ^= value;
        value = whirlpool_xtime(value);
        factor >>= 1;
    }
    return result;
}

static void whirlpool_init_tables(void)
{
    unsigned i;
    if (whirlpool_tables_ready) return;
    for (i = 0; i < 256; ++i) {
        uint8_t s = whirlpool_sbox[i];
        whirlpool_c0[i] = ((uint64_t)s << 56) | ((uint64_t)s << 48) |
            ((uint64_t)whirlpool_multiply(s, 4) << 40) |
            ((uint64_t)s << 32) |
            ((uint64_t)whirlpool_multiply(s, 8) << 24) |
            ((uint64_t)whirlpool_multiply(s, 5) << 16) |
            ((uint64_t)whirlpool_multiply(s, 2) << 8) |
            (uint64_t)whirlpool_multiply(s, 9);
    }
    whirlpool_tables_ready = 1;
}

static uint64_t whirlpool_transform_word(const uint64_t input[8], unsigned word)
{
    uint64_t result = 0;
    unsigned column;
    for (column = 0; column < 8; ++column) {
        unsigned source = (word + 8u - column) & 7u;
        uint8_t byte = (uint8_t)(input[source] >> (56u - column * 8u));
        result ^= rotr64(whirlpool_c0[byte], column * 8u);
    }
    return result;
}

static void whirlpool_transform(ml_hash_context *context, const uint8_t block[64])
{
    uint64_t key[8], state[8], next_key[8], next_state[8], message[8];
    unsigned i, round;
    whirlpool_init_tables();
    for (i = 0; i < 8; ++i) {
        message[i] = load_be64(block + i * 8u);
        key[i] = context->state64[i];
        state[i] = message[i] ^ key[i];
    }
    for (round = 0; round < 10; ++round) {
        for (i = 0; i < 8; ++i) {
            next_key[i] = whirlpool_transform_word(key, i);
            if (i == 0) next_key[i] ^= whirlpool_round_constants[round];
            next_state[i] = whirlpool_transform_word(state, i) ^ next_key[i];
        }
        for (i = 0; i < 8; ++i) {
            key[i] = next_key[i];
            state[i] = next_state[i];
        }
    }
    for (i = 0; i < 8; ++i)
        context->state64[i] ^= state[i] ^ message[i];
}

static uint32_t ripemd_rol(uint32_t value, unsigned count)
{
    return (value << count) | (value >> (32u - count));
}

static uint32_t ripemd_f(unsigned round, uint32_t x, uint32_t y, uint32_t z)
{
    switch (round) {
    case 0: return x ^ y ^ z;
    case 1: return (x & y) | (~x & z);
    case 2: return (x | ~y) ^ z;
    case 3: return (x & z) | (y & ~z);
    default: return x ^ (y | ~z);
    }
}

static void ripemd160_transform(ml_hash_context *context,
                                const uint8_t block[64])
{
    static const uint8_t r[80] = {
         0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15,
         7, 4,13, 1,10, 6,15, 3,12, 0, 9, 5, 2,14,11, 8,
         3,10,14, 4, 9,15, 8, 1, 2, 7, 0, 6,13,11, 5,12,
         1, 9,11,10, 0, 8,12, 4,13, 3, 7,15,14, 5, 6, 2,
         4, 0, 5, 9, 7,12, 2,10,14, 1, 3, 8,11, 6,15,13
    };
    static const uint8_t rp[80] = {
         5,14, 7, 0, 9, 2,11, 4,13, 6,15, 8, 1,10, 3,12,
         6,11, 3, 7, 0,13, 5,10,14,15, 8,12, 4, 9, 1, 2,
        15, 5, 1, 3, 7,14, 6, 9,11, 8,12, 2,10, 0, 4,13,
         8, 6, 4, 1, 3,11,15, 0, 5,12, 2,13, 9, 7,10,14,
        12,15,10, 4, 1, 5, 8, 7, 6, 2,13,14, 0, 3, 9,11
    };
    static const uint8_t s[80] = {
        11,14,15,12, 5, 8, 7, 9,11,13,14,15, 6, 7, 9, 8,
         7, 6, 8,13,11, 9, 7,15, 7,12,15, 9,11, 7,13,12,
        11,13, 6, 7,14, 9,13,15,14, 8,13, 6, 5,12, 7, 5,
        11,12,14,15,14,15, 9, 8, 9,14, 5, 6, 8, 6, 5,12,
         9,15, 5,11, 6, 8,13,12, 5,12,13,14,11, 8, 5, 6
    };
    static const uint8_t sp[80] = {
         8, 9, 9,11,13,15,15, 5, 7, 7, 8,11,14,14,12, 6,
         9,13,15, 7,12, 8, 9,11, 7, 7,12, 7, 6,15,13,11,
         9, 7,15,11, 8, 6, 6,14,12,13, 5,14,13,13, 7, 5,
        15, 5, 8,11,14,14, 6,14, 6, 9,12, 9,12, 5,15, 8,
         8, 5,12, 9,12, 5,14, 6, 8,13, 6, 5,15,13,11,11
    };
    static const uint32_t k[5] = {
        0x00000000u,0x5a827999u,0x6ed9eba1u,0x8f1bbcdcu,0xa953fd4eu
    };
    static const uint32_t kp[5] = {
        0x50a28be6u,0x5c4dd124u,0x6d703ef3u,0x7a6d76e9u,0x00000000u
    };
    uint32_t x[16];
    uint32_t a, b, c, d, e, aa, bb, cc, dd, ee;
    unsigned i;
    for (i = 0; i < 16; ++i) x[i] = load_le32(block + i * 4u);
    a = aa = context->state[0];
    b = bb = context->state[1];
    c = cc = context->state[2];
    d = dd = context->state[3];
    e = ee = context->state[4];
    for (i = 0; i < 80; ++i) {
        unsigned round = i / 16;
        uint32_t t = ripemd_rol(a + ripemd_f(round, b, c, d) + x[r[i]] +
                                k[round], s[i]) + e;
        a = e; e = d; d = ripemd_rol(c, 10); c = b; b = t;
        t = ripemd_rol(aa + ripemd_f(4 - round, bb, cc, dd) + x[rp[i]] +
                       kp[round], sp[i]) + ee;
        aa = ee; ee = dd; dd = ripemd_rol(cc, 10); cc = bb; bb = t;
    }
    {
        uint32_t t = context->state[1] + c + dd;
        context->state[1] = context->state[2] + d + ee;
        context->state[2] = context->state[3] + e + aa;
        context->state[3] = context->state[4] + a + bb;
        context->state[4] = context->state[0] + b + cc;
        context->state[0] = t;
    }
}

static void hash_init(ml_hash_context *context, ml_hash_algorithm algorithm)
{
    size_t i;
    context->algorithm = algorithm;
    context->byte_count = 0;
    context->used = 0;
    if (algorithm == ML_HASH_SHA1) {
        static const uint32_t initial[5] = {
            0x67452301u,0xefcdab89u,0x98badcfeu,0x10325476u,0xc3d2e1f0u
        };
        for (i = 0; i < 5; ++i) context->state[i] = initial[i];
    } else if (algorithm == ML_HASH_SHA256) {
        static const uint32_t initial[8] = {
            0x6a09e667u,0xbb67ae85u,0x3c6ef372u,0xa54ff53au,
            0x510e527fu,0x9b05688cu,0x1f83d9abu,0x5be0cd19u
        };
        for (i = 0; i < 8; ++i) context->state[i] = initial[i];
    } else if (algorithm == ML_HASH_SHA512) {
        static const uint64_t initial[8] = {
            0x6a09e667f3bcc908ull,0xbb67ae8584caa73bull,
            0x3c6ef372fe94f82bull,0xa54ff53a5f1d36f1ull,
            0x510e527fade682d1ull,0x9b05688c2b3e6c1full,
            0x1f83d9abfb41bd6bull,0x5be0cd19137e2179ull
        };
        for (i = 0; i < 8; ++i) context->state64[i] = initial[i];
    } else if (algorithm == ML_HASH_WHIRLPOOL) {
        for (i = 0; i < 8; ++i) context->state64[i] = 0;
    } else {
        static const uint32_t initial[5] = {
            0x67452301u,0xefcdab89u,0x98badcfeu,0x10325476u,0xc3d2e1f0u
        };
        for (i = 0; i < 5; ++i) context->state[i] = initial[i];
    }
}

static void hash_update(ml_hash_context *context, const uint8_t *data,
                        size_t size)
{
    size_t block_size = context->algorithm == ML_HASH_SHA512 ? 128u : 64u;
    context->byte_count += size;
    while (size) {
        size_t amount = block_size - context->used;
        if (amount > size) amount = size;
        for (size_t i = 0; i < amount; ++i)
            context->block[context->used + i] = data[i];
        context->used += amount;
        data += amount;
        size -= amount;
        if (context->used == block_size) {
            if (context->algorithm == ML_HASH_SHA1)
                sha1_transform(context, context->block);
            else if (context->algorithm == ML_HASH_SHA256)
                sha256_transform(context, context->block);
            else if (context->algorithm == ML_HASH_SHA512)
                sha512_transform(context, context->block);
            else if (context->algorithm == ML_HASH_WHIRLPOOL)
                whirlpool_transform(context, context->block);
            else
                ripemd160_transform(context, context->block);
            context->used = 0;
        }
    }
}

static void hash_final(ml_hash_context *context, uint8_t *digest)
{
    uint64_t bit_count = context->byte_count * 8u;
    uint8_t padding[128] = {0x80};
    uint8_t encoded_length[32] = {0};
    size_t pad_size;
    size_t i;
    if (context->algorithm == ML_HASH_SHA512) {
        pad_size = context->used < 112 ? 112 - context->used
                                       : 240 - context->used;
        store_be64(encoded_length + 8, bit_count);
        hash_update(context, padding, pad_size);
        hash_update(context, encoded_length, sizeof(encoded_length));
        for (i = 0; i < 8; ++i)
            store_be64(digest + i * 8u, context->state64[i]);
    } else if (context->algorithm == ML_HASH_WHIRLPOOL) {
        pad_size = context->used < 32 ? 32 - context->used
                                      : 96 - context->used;
        store_be64(encoded_length + 24, bit_count);
        hash_update(context, padding, pad_size);
        hash_update(context, encoded_length, sizeof(encoded_length));
        for (i = 0; i < 8; ++i)
            store_be64(digest + i * 8u, context->state64[i]);
    } else if (context->algorithm == ML_HASH_RIPEMD160) {
        pad_size = context->used < 56 ? 56 - context->used
                                      : 120 - context->used;
        store_le64(encoded_length, bit_count);
        hash_update(context, padding, pad_size);
        hash_update(context, encoded_length, 8);
        for (i = 0; i < 5; ++i)
            store_le32(digest + i * 4u, context->state[i]);
    } else {
        unsigned words = context->algorithm == ML_HASH_SHA1 ? 5 : 8;
        pad_size = context->used < 56 ? 56 - context->used
                                      : 120 - context->used;
        store_be64(encoded_length + 8, bit_count);
        hash_update(context, padding, pad_size);
        hash_update(context, encoded_length + 8, 8);
        for (i = 0; i < words; ++i)
            store_be32(digest + i * 4u, context->state[i]);
    }
}

size_t ml_hash_digest_size(ml_hash_algorithm algorithm)
{
    if (algorithm == ML_HASH_SHA1) return 20;
    if (algorithm == ML_HASH_SHA256) return 32;
    if (algorithm == ML_HASH_SHA512) return 64;
    if (algorithm == ML_HASH_RIPEMD160) return 20;
    if (algorithm == ML_HASH_WHIRLPOOL) return 64;
    return 0;
}

int ml_hash_data(ml_hash_algorithm algorithm,
                 const void *input, size_t input_size, void *output)
{
    ml_hash_context context;
    size_t digest_size = ml_hash_digest_size(algorithm);
    if (!digest_size || (!input && input_size) || !output) return 0;
    hash_init(&context, algorithm);
    hash_update(&context, (const uint8_t *)input, input_size);
    hash_final(&context, (uint8_t *)output);
    return 1;
}

static void hmac(ml_hash_algorithm algorithm,
                 const uint8_t *key, size_t key_size,
                 const uint8_t *first, size_t first_size,
                 const uint8_t *second, size_t second_size,
                 uint8_t *output)
{
    uint8_t key_block[128] = {0}, digest[64], pad[128];
    size_t digest_size = ml_hash_digest_size(algorithm),
           block_size = algorithm == ML_HASH_SHA512 ? 128u : 64u, i;
    ml_hash_context context;
    if (digest_size == 0) return;
    if (key_size > block_size) {
        hash_init(&context, algorithm);
        hash_update(&context, key, key_size);
        hash_final(&context, digest);
        key = digest;
        key_size = digest_size;
    }
    for (i = 0; i < key_size; ++i) key_block[i] = key[i];
    for (i = 0; i < block_size; ++i) pad[i] = key_block[i] ^ 0x36u;
    hash_init(&context, algorithm);
    hash_update(&context, pad, block_size);
    if (first_size) hash_update(&context, first, first_size);
    if (second_size) hash_update(&context, second, second_size);
    hash_final(&context, digest);
    for (i = 0; i < block_size; ++i) pad[i] = key_block[i] ^ 0x5cu;
    hash_init(&context, algorithm);
    hash_update(&context, pad, block_size);
    hash_update(&context, digest, digest_size);
    hash_final(&context, output);
}

int ml_hmac_data(ml_hash_algorithm algorithm,
                 const void *key, size_t key_size,
                 const void *data, size_t data_size, void *output)
{
    if ((!key && key_size) || (!data && data_size) || !output ||
        ml_hash_digest_size(algorithm) == 0)
        return 0;
    hmac(algorithm, (const uint8_t *)key, key_size,
         (const uint8_t *)data, data_size, NULL, 0, (uint8_t *)output);
    return 1;
}

int ml_pbkdf2(ml_hash_algorithm algorithm,
              const void *password, size_t password_size,
              const void *salt, size_t salt_size,
              uint32_t iterations, void *output, size_t output_size)
{
    const uint8_t *pass = (const uint8_t *)password;
    const uint8_t *salt_bytes = (const uint8_t *)salt;
    uint8_t u[64], t[64], counter[4];
    uint8_t *out = (uint8_t *)output;
    size_t digest_size = ml_hash_digest_size(algorithm), done = 0;
    uint64_t blocks, block;
    if ((!password && password_size) || (!salt && salt_size) ||
        (!output && output_size) || digest_size == 0 || iterations == 0)
        return 0;
    blocks = ((uint64_t)output_size + digest_size - 1) / digest_size;
    if (blocks > 0xffffffffu) return 0;
    for (block = 1; block <= blocks; ++block) {
        uint32_t index = (uint32_t)block;
        uint32_t iteration;
        size_t n;
        counter[0] = (uint8_t)(index >> 24); counter[1] = (uint8_t)(index >> 16);
        counter[2] = (uint8_t)(index >> 8); counter[3] = (uint8_t)index;
        hmac(algorithm, pass, password_size, salt_bytes, salt_size,
             counter, sizeof(counter), u);
        for (n = 0; n < digest_size; ++n) t[n] = u[n];
        for (iteration = 1; iteration < iterations; ++iteration) {
            hmac(algorithm, pass, password_size, u, digest_size, NULL, 0, u);
            for (n = 0; n < digest_size; ++n) t[n] ^= u[n];
        }
        n = output_size - done;
        if (n > digest_size) n = digest_size;
        for (size_t j = 0; j < n; ++j) out[done + j] = t[j];
        done += n;
    }
    return 1;
}

static const uint8_t aes_sbox[256] = {
0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static const uint8_t aes_inv_sbox[256] = {
0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
};

static uint8_t aes_xtime(uint8_t x)
{
    return (uint8_t)((x << 1) ^ ((x >> 7) * 0x1bu));
}

static uint8_t aes_mul(uint8_t x, uint8_t y)
{
    uint8_t result = 0;
    while (y) {
        if (y & 1u) result ^= x;
        x = aes_xtime(x);
        y >>= 1;
    }
    return result;
}

int ml_aes_set_key(ml_aes_context *context, const uint8_t *key, size_t key_size)
{
    unsigned nk, words, i;
    uint8_t temp[4], rcon = 1;
    if (!context || !key || (key_size != 16 && key_size != 24 && key_size != 32))
        return 0;
    nk = (unsigned)(key_size / 4);
    context->rounds = nk + 6;
    words = 4 * (context->rounds + 1);
    for (i = 0; i < nk * 4; ++i) context->round_key[i] = key[i];
    for (i = nk; i < words; ++i) {
        unsigned j;
        for (j = 0; j < 4; ++j) temp[j] = context->round_key[(i - 1) * 4 + j];
        if (i % nk == 0) {
            uint8_t first = temp[0];
            temp[0] = aes_sbox[temp[1]] ^ rcon;
            temp[1] = aes_sbox[temp[2]];
            temp[2] = aes_sbox[temp[3]];
            temp[3] = aes_sbox[first];
            rcon = aes_xtime(rcon);
        } else if (nk > 6 && i % nk == 4) {
            for (j = 0; j < 4; ++j) temp[j] = aes_sbox[temp[j]];
        }
        for (j = 0; j < 4; ++j)
            context->round_key[i * 4 + j] = context->round_key[(i - nk) * 4 + j] ^ temp[j];
    }
    return 1;
}

static void aes_add_key(uint8_t state[16], const uint8_t *key)
{
    unsigned i;
    for (i = 0; i < 16; ++i) state[i] ^= key[i];
}

static void aes_shift_rows(uint8_t s[16])
{
    uint8_t t;
    t=s[1]; s[1]=s[5]; s[5]=s[9]; s[9]=s[13]; s[13]=t;
    t=s[2]; s[2]=s[10]; s[10]=t; t=s[6]; s[6]=s[14]; s[14]=t;
    t=s[15]; s[15]=s[11]; s[11]=s[7]; s[7]=s[3]; s[3]=t;
}

static void aes_inv_shift_rows(uint8_t s[16])
{
    uint8_t t;
    t=s[13]; s[13]=s[9]; s[9]=s[5]; s[5]=s[1]; s[1]=t;
    t=s[2]; s[2]=s[10]; s[10]=t; t=s[6]; s[6]=s[14]; s[14]=t;
    t=s[3]; s[3]=s[7]; s[7]=s[11]; s[11]=s[15]; s[15]=t;
}

static void aes_mix_columns(uint8_t s[16])
{
    unsigned c;
    for (c = 0; c < 4; ++c) {
        uint8_t *p = s + c * 4;
        uint8_t a=p[0],b=p[1],d=p[2],e=p[3];
        p[0]=aes_mul(a,2)^aes_mul(b,3)^d^e;
        p[1]=a^aes_mul(b,2)^aes_mul(d,3)^e;
        p[2]=a^b^aes_mul(d,2)^aes_mul(e,3);
        p[3]=aes_mul(a,3)^b^d^aes_mul(e,2);
    }
}

static void aes_inv_mix_columns(uint8_t s[16])
{
    unsigned c;
    for (c = 0; c < 4; ++c) {
        uint8_t *p = s + c * 4;
        uint8_t a=p[0],b=p[1],d=p[2],e=p[3];
        p[0]=aes_mul(a,14)^aes_mul(b,11)^aes_mul(d,13)^aes_mul(e,9);
        p[1]=aes_mul(a,9)^aes_mul(b,14)^aes_mul(d,11)^aes_mul(e,13);
        p[2]=aes_mul(a,13)^aes_mul(b,9)^aes_mul(d,14)^aes_mul(e,11);
        p[3]=aes_mul(a,11)^aes_mul(b,13)^aes_mul(d,9)^aes_mul(e,14);
    }
}

void ml_aes_encrypt_block(const ml_aes_context *context,
                          const uint8_t input[16], uint8_t output[16])
{
    uint8_t state[16];
    unsigned round, i;
    for (i = 0; i < 16; ++i) state[i] = input[i];
    aes_add_key(state, context->round_key);
    for (round = 1; round < context->rounds; ++round) {
        for (i = 0; i < 16; ++i) state[i] = aes_sbox[state[i]];
        aes_shift_rows(state);
        aes_mix_columns(state);
        aes_add_key(state, context->round_key + round * 16);
    }
    for (i = 0; i < 16; ++i) state[i] = aes_sbox[state[i]];
    aes_shift_rows(state);
    aes_add_key(state, context->round_key + context->rounds * 16);
    for (i = 0; i < 16; ++i) output[i] = state[i];
}

void ml_aes_decrypt_block(const ml_aes_context *context,
                          const uint8_t input[16], uint8_t output[16])
{
    uint8_t state[16];
    unsigned round, i;
    for (i = 0; i < 16; ++i) state[i] = input[i];
    aes_add_key(state, context->round_key + context->rounds * 16);
    for (round = context->rounds - 1; round > 0; --round) {
        aes_inv_shift_rows(state);
        for (i = 0; i < 16; ++i) state[i] = aes_inv_sbox[state[i]];
        aes_add_key(state, context->round_key + round * 16);
        aes_inv_mix_columns(state);
    }
    aes_inv_shift_rows(state);
    for (i = 0; i < 16; ++i) state[i] = aes_inv_sbox[state[i]];
    aes_add_key(state, context->round_key);
    for (i = 0; i < 16; ++i) output[i] = state[i];
}

typedef union {
    ml_aes_context aes;
#if ML_ENABLE_CIPHER_SERPENT_XTS
    struct serpent_ctx serpent;
#endif
#if ML_ENABLE_CIPHER_TWOFISH_XTS
    struct twofish_ctx twofish;
#endif
} ml_xts_schedule;

/* Pre-boot storage reads are serialized. Keeping the key schedules in static
 * storage avoids several kilobytes of stack use for Twofish-XTS. */
static ml_xts_schedule xts_data_schedule;
static ml_xts_schedule xts_tweak_schedule;

static int xts_set_key(ml_xts_cipher cipher, ml_xts_schedule *schedule,
                       const uint8_t *key, size_t key_size)
{
    switch (cipher) {
    case ML_XTS_AES:
        return ml_aes_set_key(&schedule->aes, key, key_size);
#if ML_ENABLE_CIPHER_SERPENT_XTS
    case ML_XTS_SERPENT:
        if (key_size != 16 && key_size != 24 && key_size != 32) return 0;
        serpent_set_key(&schedule->serpent, key_size, key);
        return 1;
#endif
#if ML_ENABLE_CIPHER_TWOFISH_XTS
    case ML_XTS_TWOFISH:
        if (key_size != 16 && key_size != 24 && key_size != 32) return 0;
        twofish_set_key(&schedule->twofish, key_size, key);
        return 1;
#endif
    default:
        return 0;
    }
}

static void xts_encrypt_block(ml_xts_cipher cipher,
                              const ml_xts_schedule *schedule,
                              const uint8_t input[16], uint8_t output[16])
{
    switch (cipher) {
    case ML_XTS_AES:
        ml_aes_encrypt_block(&schedule->aes, input, output);
        break;
#if ML_ENABLE_CIPHER_SERPENT_XTS
    case ML_XTS_SERPENT:
        serpent_encrypt(&schedule->serpent, 16, output, input);
        break;
#endif
#if ML_ENABLE_CIPHER_TWOFISH_XTS
    case ML_XTS_TWOFISH:
        twofish_encrypt(&schedule->twofish, 16, output, input);
        break;
#endif
    default:
        break;
    }
}

static void xts_decrypt_block(ml_xts_cipher cipher,
                              const ml_xts_schedule *schedule,
                              const uint8_t input[16], uint8_t output[16])
{
    switch (cipher) {
    case ML_XTS_AES:
        ml_aes_decrypt_block(&schedule->aes, input, output);
        break;
#if ML_ENABLE_CIPHER_SERPENT_XTS
    case ML_XTS_SERPENT:
        serpent_decrypt(&schedule->serpent, 16, output, input);
        break;
#endif
#if ML_ENABLE_CIPHER_TWOFISH_XTS
    case ML_XTS_TWOFISH:
        twofish_decrypt(&schedule->twofish, 16, output, input);
        break;
#endif
    default:
        break;
    }
}

static int xts_crypt(ml_xts_cipher cipher, int decrypt,
                     const uint8_t *key, size_t key_size,
                     uint64_t sector_number, const uint8_t *input,
                     uint8_t *output, size_t size)
{
    uint8_t tweak_input[16] = {0}, tweak[16], block[16];
    size_t half, offset;
    unsigned i;
    volatile uint8_t *wipe;
    int supported = 1, result = 0;
    if (!key || (!input && size) || (!output && size) ||
        (key_size != 32 && key_size != 64) || (size & 15u)) return 0;
    half = key_size / 2;
    if (cipher == ML_XTS_AES && half != 16 && half != 32) return 0;
#if ML_ENABLE_CIPHER_SERPENT_XTS
    if (cipher == ML_XTS_SERPENT && half != 16 && half != 24 && half != 32)
        return 0;
#endif
#if ML_ENABLE_CIPHER_TWOFISH_XTS
    if (cipher == ML_XTS_TWOFISH && half != 16 && half != 24 && half != 32)
        return 0;
#endif
    if (cipher != ML_XTS_AES
#if ML_ENABLE_CIPHER_SERPENT_XTS
        && cipher != ML_XTS_SERPENT
#endif
#if ML_ENABLE_CIPHER_TWOFISH_XTS
        && cipher != ML_XTS_TWOFISH
#endif
       ) return 0;
    if (!xts_set_key(cipher, &xts_data_schedule, key, half) ||
        !xts_set_key(cipher, &xts_tweak_schedule, key + half, half)) {
        supported = 0;
        goto done;
    }
    for (i = 0; i < 8; ++i)
        tweak_input[i] = (uint8_t)(sector_number >> (8u * i));
    xts_encrypt_block(cipher, &xts_tweak_schedule, tweak_input, tweak);
    for (offset = 0; offset < size; offset += 16) {
        for (i = 0; i < 16; ++i) block[i] = input[offset + i] ^ tweak[i];
        if (decrypt)
            xts_decrypt_block(cipher, &xts_data_schedule, block, block);
        else
            xts_encrypt_block(cipher, &xts_data_schedule, block, block);
        for (i = 0; i < 16; ++i) output[offset + i] = block[i] ^ tweak[i];
        {
            uint8_t carry = 0;
            for (i = 0; i < 16; ++i) {
                uint8_t next = (uint8_t)(tweak[i] >> 7);
                tweak[i] = (uint8_t)((tweak[i] << 1) | carry);
                carry = next;
            }
            if (carry) tweak[0] ^= 0x87u;
        }
    }
    result = 1;
done:
    wipe = (volatile uint8_t *)&xts_data_schedule;
    for (i = 0; i < sizeof(xts_data_schedule); ++i) wipe[i] = 0;
    wipe = (volatile uint8_t *)&xts_tweak_schedule;
    for (i = 0; i < sizeof(xts_tweak_schedule); ++i) wipe[i] = 0;
    wipe = tweak_input;
    for (i = 0; i < sizeof(tweak_input); ++i) wipe[i] = 0;
    wipe = tweak;
    for (i = 0; i < sizeof(tweak); ++i) wipe[i] = 0;
    wipe = block;
    for (i = 0; i < sizeof(block); ++i) wipe[i] = 0;
    return result && supported;
}

int ml_xts_decrypt(ml_xts_cipher cipher, const uint8_t *key,
                   size_t key_size, uint64_t sector_number,
                   const uint8_t *input, uint8_t *output, size_t size)
{
    return xts_crypt(cipher, 1, key, key_size, sector_number,
                     input, output, size);
}

int ml_xts_encrypt(ml_xts_cipher cipher, const uint8_t *key,
                   size_t key_size, uint64_t sector_number,
                   const uint8_t *input, uint8_t *output, size_t size)
{
    return xts_crypt(cipher, 0, key, key_size, sector_number,
                     input, output, size);
}

int ml_aes_xts_decrypt(const uint8_t *key, size_t key_size,
                       uint64_t sector_number,
                       const uint8_t *input, uint8_t *output, size_t size)
{
    return ml_xts_decrypt(ML_XTS_AES, key, key_size, sector_number,
                          input, output, size);
}

int ml_aes_cbc_essiv_decrypt(const uint8_t *key, size_t key_size,
                             uint64_t sector_number,
                             const uint8_t *input, uint8_t *output,
                             size_t size)
{
    ml_aes_context data_key, iv_key;
    uint8_t essiv_key[32], iv_input[16] = {0}, iv[16];
    uint8_t ciphertext[16], plaintext[16];
    size_t offset;
    unsigned i;
    volatile uint8_t *wipe;
    if (!key || (!input && size) || (!output && size) ||
        (key_size != 16 && key_size != 24 && key_size != 32) ||
        (size & 15u)) return 0;
    if (!ml_hash_data(ML_HASH_SHA256, key, key_size, essiv_key) ||
        !ml_aes_set_key(&data_key, key, key_size) ||
        !ml_aes_set_key(&iv_key, essiv_key, key_size))
        return 0;
    store_le64(iv_input, sector_number);
    ml_aes_encrypt_block(&iv_key, iv_input, iv);
    for (offset = 0; offset < size; offset += 16) {
        for (i = 0; i < 16; ++i) ciphertext[i] = input[offset + i];
        ml_aes_decrypt_block(&data_key, ciphertext, plaintext);
        for (i = 0; i < 16; ++i) output[offset + i] = plaintext[i] ^ iv[i];
        for (i = 0; i < 16; ++i) iv[i] = ciphertext[i];
    }
    wipe = (volatile uint8_t *)&data_key;
    for (i = 0; i < sizeof(data_key); ++i) wipe[i] = 0;
    wipe = (volatile uint8_t *)&iv_key;
    for (i = 0; i < sizeof(iv_key); ++i) wipe[i] = 0;
    wipe = essiv_key;
    for (i = 0; i < sizeof(essiv_key); ++i) wipe[i] = 0;
    wipe = iv_input;
    for (i = 0; i < sizeof(iv_input); ++i) wipe[i] = 0;
    wipe = iv;
    for (i = 0; i < sizeof(iv); ++i) wipe[i] = 0;
    wipe = ciphertext;
    for (i = 0; i < sizeof(ciphertext); ++i) wipe[i] = 0;
    wipe = plaintext;
    for (i = 0; i < sizeof(plaintext); ++i) wipe[i] = 0;
    return 1;
}
