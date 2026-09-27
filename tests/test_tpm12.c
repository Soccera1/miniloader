/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "ml_tpm12.h"
#include "ml_crypto.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

#define TPM_TAG_RQU_COMMAND 0x00c1u
#define TPM_TAG_RSP_COMMAND 0x00c4u
#define TPM_TAG_RSP_AUTH1_COMMAND 0x00c5u
#define TPM_TAG_RSP_AUTH2_COMMAND 0x00c6u
#define TPM_ORD_OIAP 0x0000000au
#define TPM_ORD_LOAD_KEY2 0x00000041u
#define TPM_ORD_GET_RANDOM 0x00000046u
#define TPM_ORD_UNSEAL 0x00000018u
#define MAX_PACKET 16384u

typedef struct {
    uint32_t handle;
    uint8_t nonce_even[20];
} fake_session;

typedef struct {
    fake_session sessions[8];
    size_t session_count;
    uint8_t random_byte;
    uint8_t key_blob[32];
    size_t key_blob_size;
    uint8_t stored_data[32];
    size_t stored_data_size;
    uint8_t sealed_key[32];
    int pcr_mismatch;
    int corrupt_response_hmac;
    unsigned load_commands;
    unsigned unseal_commands;
} fake_tpm;

static uint16_t get_be16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static uint32_t get_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void put_be16(uint8_t *p, uint16_t value)
{
    p[0] = (uint8_t)(value >> 8);
    p[1] = (uint8_t)value;
}

static void put_be32(uint8_t *p, uint32_t value)
{
    p[0] = (uint8_t)(value >> 24);
    p[1] = (uint8_t)(value >> 16);
    p[2] = (uint8_t)(value >> 8);
    p[3] = (uint8_t)value;
}

static void set_response(uint8_t *response, size_t *response_size,
                         uint16_t tag, uint32_t rc,
                         const uint8_t *parameters, size_t parameter_size)
{
    size_t size = 10 + parameter_size;
    assert(size <= MAX_PACKET);
    put_be16(response, tag);
    put_be32(response + 2, (uint32_t)size);
    put_be32(response + 6, rc);
    if (parameter_size) memcpy(response + 10, parameters, parameter_size);
    *response_size = size;
}

static fake_session *find_session(fake_tpm *fake, uint32_t handle)
{
    size_t i;
    for (i = 0; i < fake->session_count; ++i)
        if (fake->sessions[i].handle == handle) return &fake->sessions[i];
    return NULL;
}

static int verify_request_auth(const uint8_t secret[20], uint32_t ordinal,
                               const uint8_t *parameters,
                               size_t parameters_size,
                               const uint8_t *auth, fake_tpm *fake)
{
    uint8_t digest_input[8192], digest[20], hmac_input[61], expected[20];
    size_t used = 0;
    fake_session *session = find_session(fake, get_be32(auth));
    int ok = 0;
    if (!session || parameters_size + 4 > sizeof(digest_input)) return 0;
    put_be32(digest_input, ordinal);
    memcpy(digest_input + 4, parameters, parameters_size);
    if (!ml_hash_data(ML_HASH_SHA1, digest_input, parameters_size + 4, digest))
        goto done;
    memcpy(hmac_input + used, digest, 20); used += 20;
    memcpy(hmac_input + used, session->nonce_even, 20); used += 20;
    memcpy(hmac_input + used, auth + 4, 20); used += 20;
    hmac_input[used++] = auth[24];
    if (used != sizeof(hmac_input) ||
        !ml_hmac_data(ML_HASH_SHA1, secret, 20, hmac_input, used, expected))
        goto done;
    ok = memcmp(expected, auth + 25, 20) == 0;
done:
    memset(digest_input, 0, sizeof(digest_input));
    memset(digest, 0, sizeof(digest));
    memset(hmac_input, 0, sizeof(hmac_input));
    memset(expected, 0, sizeof(expected));
    return ok;
}

static void make_response_auth(const uint8_t secret[20], uint32_t ordinal,
                               const uint8_t *parameters,
                               size_t parameters_size,
                               fake_session *session,
                               const uint8_t *request_auth,
                               uint8_t continue_session, uint8_t output[41],
                               int corrupt)
{
    uint8_t digest_input[8192], digest[20], hmac_input[61], mac[20];
    size_t used = 0;
    put_be32(digest_input, 0);
    put_be32(digest_input + 4, ordinal);
    if (parameters_size) memcpy(digest_input + 8, parameters, parameters_size);
    assert(ml_hash_data(ML_HASH_SHA1, digest_input,
                        8 + parameters_size, digest));
    memcpy(hmac_input + used, digest, 20); used += 20;
    for (size_t i = 0; i < 20; ++i)
        output[i] = (uint8_t)(session->nonce_even[i] + 0x31u);
    memcpy(hmac_input + used, output, 20); used += 20;
    memcpy(hmac_input + used, request_auth + 4, 20); used += 20;
    hmac_input[used++] = continue_session;
    assert(used == sizeof(hmac_input));
    assert(ml_hmac_data(ML_HASH_SHA1, secret, 20, hmac_input, used, mac));
    output[20] = continue_session;
    memcpy(output + 21, mac, 20);
    if (corrupt) output[21] ^= 0x80;
    memset(digest_input, 0, sizeof(digest_input));
    memset(digest, 0, sizeof(digest));
    memset(hmac_input, 0, sizeof(hmac_input));
    memset(mac, 0, sizeof(mac));
}

static int submit_fake_tpm(void *context, const uint8_t *command,
                           size_t command_size, uint8_t *response,
                           size_t response_capacity, size_t *response_size)
{
    fake_tpm *fake = context;
    uint32_t ordinal;
    uint8_t params[MAX_PACKET];
    size_t params_size = 0;
    if (!fake || !command || !response || !response_size ||
        command_size < 10 || command_size > MAX_PACKET ||
        get_be32(command + 2) != command_size || response_capacity < 10)
        return 0;
    ordinal = get_be32(command + 6);
    memset(response, 0, response_capacity);
    if (ordinal == TPM_ORD_GET_RANDOM) {
        uint32_t wanted;
        size_t i;
        if (command_size != 14) return 0;
        wanted = get_be32(command + 10);
        if (wanted == 0 || wanted > 64) return 0;
        put_be32(params, wanted);
        for (i = 0; i < wanted; ++i) params[4 + i] = fake->random_byte++;
        set_response(response, response_size, TPM_TAG_RSP_COMMAND, 0,
                     params, (size_t)wanted + 4);
    } else if (ordinal == TPM_ORD_OIAP) {
        fake_session *session;
        size_t i;
        if (command_size != 10 || fake->session_count >= 8) return 0;
        session = &fake->sessions[fake->session_count++];
        session->handle = (uint32_t)(0x100 + fake->session_count);
        for (i = 0; i < 20; ++i)
            session->nonce_even[i] = (uint8_t)(0xa0 + fake->session_count + i);
        put_be32(params, session->handle);
        memcpy(params + 4, session->nonce_even, 20);
        set_response(response, response_size, TPM_TAG_RSP_COMMAND, 0,
                     params, 24);
    } else if (ordinal == TPM_ORD_LOAD_KEY2) {
        uint8_t srk_secret[20] = {0};
        const uint8_t *auth;
        fake_session *session;
        uint8_t response_parameters[4 + 41];
        size_t blob_offset = 14, blob_size;
        if (get_be16(command) != 0x00c2 || command_size < blob_offset + 45)
            return 0;
        auth = command + command_size - 45;
        blob_size = (size_t)(auth - (command + blob_offset));
        if (get_be32(command + 10) != 0x40000000u ||
            blob_size != fake->key_blob_size ||
            memcmp(command + blob_offset, fake->key_blob, blob_size) != 0 ||
            !verify_request_auth(srk_secret, ordinal,
                command + blob_offset, blob_size, auth, fake)) return 0;
        session = find_session(fake, get_be32(auth));
        if (!session) return 0;
        put_be32(response_parameters, 0x81000001u);
        make_response_auth(srk_secret, ordinal, NULL, 0, session, auth, 0,
                           response_parameters + 4,
                           fake->corrupt_response_hmac);
        set_response(response, response_size, TPM_TAG_RSP_AUTH1_COMMAND,
                     0, response_parameters, sizeof(response_parameters));
        ++fake->load_commands;
    } else if (ordinal == TPM_ORD_UNSEAL) {
        uint8_t usage_secret[20];
        const uint8_t *auth1, *auth2;
        fake_session *session1, *session2;
        uint8_t response_parameters[4 + 32 + 2 * 41];
        if (fake->pcr_mismatch) {
            set_response(response, response_size, TPM_TAG_RSP_COMMAND,
                         0x00000026u, NULL, 0);
            ++fake->unseal_commands;
            return 1;
        }
        if (get_be16(command) != 0x00c3 || command_size < 14 + 90 ||
            get_be32(command + 10) != 0x81000001u ||
            !ml_hash_data(ML_HASH_SHA1, "password", 8, usage_secret)) return 0;
        auth1 = command + command_size - 90;
        auth2 = command + command_size - 45;
        params_size = (size_t)(auth1 - (command + 14));
        if (params_size != fake->stored_data_size ||
            memcmp(command + 14, fake->stored_data, params_size) != 0 ||
            !verify_request_auth(usage_secret, ordinal, command + 14,
                params_size, auth1, fake) ||
            !verify_request_auth(usage_secret, ordinal, command + 14,
                params_size, auth2, fake)) return 0;
        session1 = find_session(fake, get_be32(auth1));
        session2 = find_session(fake, get_be32(auth2));
        if (!session1 || !session2) return 0;
        put_be32(response_parameters, sizeof(fake->sealed_key));
        memcpy(response_parameters + 4, fake->sealed_key,
               sizeof(fake->sealed_key));
        make_response_auth(usage_secret, ordinal, response_parameters,
            4 + sizeof(fake->sealed_key), session1, auth1, 0,
            response_parameters + 4 + sizeof(fake->sealed_key),
            fake->corrupt_response_hmac);
        make_response_auth(usage_secret, ordinal, response_parameters,
            4 + sizeof(fake->sealed_key), session2, auth2, 0,
            response_parameters + 4 + sizeof(fake->sealed_key) + 41,
            fake->corrupt_response_hmac);
        set_response(response, response_size, TPM_TAG_RSP_AUTH2_COMMAND,
                     0, response_parameters, sizeof(response_parameters));
        memset(usage_secret, 0, sizeof(usage_secret));
        ++fake->unseal_commands;
    } else if (ordinal == 0x000000bau) {
        set_response(response, response_size, TPM_TAG_RSP_COMMAND, 0,
                     NULL, 0);
    } else {
        return 0;
    }
    return *response_size <= response_capacity;
}

static int b64_encode(const uint8_t *input, size_t input_size,
                      char *output, size_t capacity, size_t *output_size)
{
    static const char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t i = 0, used = 0;
    while (i < input_size) {
        uint32_t value = (uint32_t)input[i++] << 16;
        size_t remain = input_size - i;
        if (remain > 0) value |= (uint32_t)input[i++] << 8;
        if (remain > 1) value |= input[i++];
        if (used + 4 >= capacity) return 0;
        output[used++] = alphabet[(value >> 18) & 63];
        output[used++] = alphabet[(value >> 12) & 63];
        output[used++] = remain > 0 ? alphabet[(value >> 6) & 63] : '=';
        output[used++] = remain > 1 ? alphabet[value & 63] : '=';
    }
    output[used] = '\0';
    *output_size = used;
    return 1;
}

static int make_envelope(fake_tpm *fake, const uint8_t *plain,
                          size_t plain_size, uint8_t *envelope,
                          size_t capacity, size_t *envelope_size)
{
    static const char begin[] = "-----BEGIN TSS-----\n-----TSS KEY-----\n";
    static const char enc_key[] = "\n-----ENC KEY-----\nSymmetric Key: AES-256-CBC\n";
    static const char enc_data[] = "\n-----ENC DAT-----\n";
    static const char end[] = "\n-----END TSS-----\n";
    char key64[128], stored64[128], cipher64[512];
    uint8_t padded[256], ciphertext[256];
    ml_aes_context aes;
    static const uint8_t iv[16] = {
        'I','B','M',' ','S','E','A','L','I','B','M',' ','S','E','A','L'
    };
    uint8_t previous[16];
    size_t key64_size = 0, stored64_size = 0, cipher64_size = 0;
    size_t padded_size, i, used = 0;
    uint8_t pad;
    int ok = 0;
    assert(fake->key_blob_size <= sizeof(fake->key_blob));
    assert(fake->stored_data_size <= sizeof(fake->stored_data));
    if (!b64_encode(fake->key_blob, fake->key_blob_size,
            key64, sizeof(key64), &key64_size) ||
        !b64_encode(fake->stored_data, fake->stored_data_size,
            stored64, sizeof(stored64), &stored64_size)) goto done;
    pad = (uint8_t)(16 - (plain_size & 15u));
    padded_size = plain_size + pad;
    if (padded_size > sizeof(padded) ||
        !ml_aes_set_key(&aes, fake->sealed_key, sizeof(fake->sealed_key))) goto done;
    memcpy(padded, plain, plain_size);
    memset(padded + plain_size, pad, pad);
    memcpy(previous, iv, sizeof(previous));
    for (i = 0; i < padded_size; i += 16) {
        uint8_t block[16];
        unsigned j;
        for (j = 0; j < 16; ++j) block[j] = padded[i + j] ^ previous[j];
        ml_aes_encrypt_block(&aes, block, ciphertext + i);
        memcpy(previous, ciphertext + i, 16);
        memset(block, 0, sizeof(block));
    }
    if (!b64_encode(ciphertext, padded_size, cipher64,
            sizeof(cipher64), &cipher64_size)) goto done;
#define ADD_TEXT(s) do { size_t n_ = sizeof(s) - 1; if (used + n_ > capacity) goto done; memcpy(envelope + used, s, n_); used += n_; } while (0)
#define ADD_B64(s, n) do { if (used + (n) + 1 > capacity) goto done; memcpy(envelope + used, s, n); used += n; envelope[used++] = '\n'; } while (0)
    ADD_TEXT(begin);
    ADD_B64(key64, key64_size);
    ADD_TEXT(enc_key);
    ADD_B64(stored64, stored64_size);
    ADD_TEXT(enc_data);
    ADD_B64(cipher64, cipher64_size);
    ADD_TEXT(end);
#undef ADD_TEXT
#undef ADD_B64
    *envelope_size = used;
    ok = 1;
done:
    memset(key64, 0, sizeof(key64));
    memset(stored64, 0, sizeof(stored64));
    memset(cipher64, 0, sizeof(cipher64));
    memset(padded, 0, sizeof(padded));
    memset(ciphertext, 0, sizeof(ciphertext));
    memset(previous, 0, sizeof(previous));
    memset(&aes, 0, sizeof(aes));
    return ok;
}

static int make_sidecar(fake_tpm *fake, const uint8_t *plain,
                        size_t plain_size, uint8_t *sidecar,
                        size_t capacity, size_t *sidecar_size)
{
    static const char prefix[] =
        "{\"format\":\"miniloader-tpm12-v1\",\"luks_uuid\":\""
        "00112233-4455-6677-8899-aabbccddeeff\",\"pcrs\":[7],\"sealed_blob\":\"";
    static const char suffix[] = "\"}\n";
    uint8_t envelope[4096];
    char encoded[8192];
    size_t envelope_size = 0, encoded_size = 0, used = 0;
    int ok = 0;
    if (!make_envelope(fake, plain, plain_size, envelope,
            sizeof(envelope), &envelope_size) ||
        !b64_encode(envelope, envelope_size, encoded, sizeof(encoded),
                    &encoded_size)) goto done;
    if (sizeof(prefix) - 1 + encoded_size + sizeof(suffix) - 1 > capacity)
        goto done;
    memcpy(sidecar + used, prefix, sizeof(prefix) - 1); used += sizeof(prefix) - 1;
    memcpy(sidecar + used, encoded, encoded_size); used += encoded_size;
    memcpy(sidecar + used, suffix, sizeof(suffix) - 1); used += sizeof(suffix) - 1;
    *sidecar_size = used;
    ok = 1;
done:
    memset(envelope, 0, sizeof(envelope));
    memset(encoded, 0, sizeof(encoded));
    return ok;
}

static void init_fake(fake_tpm *fake)
{
    size_t i;
    memset(fake, 0, sizeof(*fake));
    fake->key_blob_size = 7;
    memcpy(fake->key_blob, "KEYBLOB", fake->key_blob_size);
    fake->stored_data_size = 9;
    memcpy(fake->stored_data, "SEALED123", fake->stored_data_size);
    for (i = 0; i < sizeof(fake->sealed_key); ++i)
        fake->sealed_key[i] = (uint8_t)(0x40 + i);
}

int main(void)
{
    const char passphrase[] = "demo-passphrase";
    const char uuid[] = "00112233-4455-6677-8899-aabbccddeeff";
    uint8_t sidecar[12000], secret[128];
    size_t sidecar_size = 0, secret_size = 0;
    fake_tpm fake;

    init_fake(&fake);
    assert(make_sidecar(&fake, (const uint8_t *)passphrase,
                        sizeof(passphrase) - 1, sidecar, sizeof(sidecar),
                        &sidecar_size));
    assert(ml_tpm12_unseal_sidecar(submit_fake_tpm, &fake, sidecar,
        sidecar_size, uuid, secret, sizeof(secret), &secret_size));
    assert(secret_size == sizeof(passphrase) - 1);
    assert(memcmp(secret, passphrase, secret_size) == 0);
    assert(fake.load_commands == 1 && fake.unseal_commands == 1);

    init_fake(&fake);
    assert(!ml_tpm12_unseal_sidecar(submit_fake_tpm, &fake, sidecar,
        sidecar_size, "11112233-4455-6677-8899-aabbccddeeff",
        secret, sizeof(secret), &secret_size));
    assert(secret_size == 0 && secret[0] == 0 && fake.load_commands == 0);

    init_fake(&fake);
    fake.pcr_mismatch = 1;
    memset(secret, 0xa5, sizeof(secret));
    assert(!ml_tpm12_unseal_sidecar(submit_fake_tpm, &fake, sidecar,
        sidecar_size, uuid, secret, sizeof(secret), &secret_size));
    assert(secret_size == 0 && secret[0] == 0 && fake.unseal_commands == 1);

    init_fake(&fake);
    fake.corrupt_response_hmac = 1;
    memset(secret, 0xa5, sizeof(secret));
    assert(!ml_tpm12_unseal_sidecar(submit_fake_tpm, &fake, sidecar,
        sidecar_size, uuid, secret, sizeof(secret), &secret_size));
    assert(secret_size == 0 && secret[0] == 0);

    sidecar[sidecar_size / 2] = '!';
    memset(secret, 0xa5, sizeof(secret));
    assert(!ml_tpm12_unseal_sidecar(submit_fake_tpm, &fake, sidecar,
        sidecar_size, uuid, secret, sizeof(secret), &secret_size));
    assert(secret_size == 0 && secret[0] == 0);
    puts("TPM 1.2 sidecar unseal, authorization, PCR failure and malformed data checks passed");
    return 0;
}
