/* SPDX-License-Identifier: GPL-3.0-or-later */
/* TPM 1.2 OIAP, LoadKey2, Unseal and tpm-tools envelope support. */
#include "ml_tpm12.h"
#include "ml_crypto.h"

#define TPM_TAG_RQU_COMMAND       0x00c1u
#define TPM_TAG_RQU_AUTH1_COMMAND 0x00c2u
#define TPM_TAG_RQU_AUTH2_COMMAND 0x00c3u
#define TPM_TAG_RSP_COMMAND       0x00c4u
#define TPM_TAG_RSP_AUTH1_COMMAND 0x00c5u
#define TPM_TAG_RSP_AUTH2_COMMAND 0x00c6u

#define TPM_ORD_OIAP         0x0000000au
#define TPM_ORD_LOAD_KEY2    0x00000041u
#define TPM_ORD_GET_RANDOM   0x00000046u
#define TPM_ORD_UNSEAL       0x00000018u
#define TPM_ORD_FLUSH_SPEC   0x000000bau
#define TPM_KH_SRK           0x40000000u
#define TPM_RT_KEY           0x0001u
#define TPM_SUCCESS          0u
#define TPM_HEADER_BYTES     10u
#define TPM_AUTH_BYTES       45u
#define TPM_AUTH_RESPONSE_BYTES 41u
#define TPM_MAX_COMMAND_BYTES (ML_TPM12_MAX_BLOB_BYTES + 256u)

typedef struct {
    uint32_t handle;
    uint8_t nonce_even[20];
} tpm12_oiap;

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

static void copy_bytes(void *destination, const void *source, size_t size)
{
    uint8_t *out = (uint8_t *)destination;
    const uint8_t *in = (const uint8_t *)source;
    size_t i;
    for (i = 0; i < size; ++i) out[i] = in[i];
}

static void wipe(void *buffer, size_t size)
{
    volatile uint8_t *p = (volatile uint8_t *)buffer;
    while (size--) *p++ = 0;
}

static int constant_equal(const uint8_t *a, const uint8_t *b, size_t size)
{
    uint8_t difference = 0;
    size_t i;
    for (i = 0; i < size; ++i) difference |= (uint8_t)(a[i] ^ b[i]);
    return difference == 0;
}

static int append(uint8_t *buffer, size_t capacity, size_t *used,
                  const void *data, size_t size)
{
    if (*used > capacity || size > capacity - *used) return 0;
    if (size) copy_bytes(buffer + *used, data, size);
    *used += size;
    return 1;
}

static int command_start(uint8_t *buffer, size_t capacity, uint16_t tag,
                         uint32_t ordinal, size_t *used)
{
    if (!buffer || !used || capacity < TPM_HEADER_BYTES) return 0;
    put_be16(buffer, tag);
    put_be32(buffer + 2, 0);
    put_be32(buffer + 6, ordinal);
    *used = TPM_HEADER_BYTES;
    return 1;
}

static int command_finish(uint8_t *buffer, size_t capacity, size_t used)
{
    if (used > capacity || used > UINT32_MAX) return 0;
    put_be32(buffer + 2, (uint32_t)used);
    return 1;
}

static int transmit(ml_tpm12_submit_fn submit, void *context,
                    const uint8_t *command, size_t command_size,
                    uint8_t *response, size_t response_capacity,
                    size_t *response_size, uint32_t *return_code)
{
    size_t amount = 0;
    if (!submit || !command || command_size < TPM_HEADER_BYTES ||
        command_size > UINT32_MAX || !response || !response_size ||
        !return_code || response_capacity < TPM_HEADER_BYTES ||
        get_be32(command + 2) != command_size ||
        !submit(context, command, command_size, response, response_capacity,
                &amount) || amount < TPM_HEADER_BYTES ||
        amount > response_capacity || get_be32(response + 2) != amount)
        return 0;
    *response_size = amount;
    *return_code = get_be32(response + 6);
    return 1;
}

static int get_random(ml_tpm12_submit_fn submit, void *context,
                      uint8_t *output, size_t amount)
{
    uint8_t command[TPM_HEADER_BYTES + 4];
    uint8_t response[TPM_HEADER_BYTES + 4 + 64];
    size_t done = 0;
    if (!output || amount == 0) return 0;
    while (done < amount) {
        size_t command_size, response_size = 0, take;
        uint32_t rc = 0, wanted;
        if (amount - done > 64u) wanted = 64u;
        else wanted = (uint32_t)(amount - done);
        if (!command_start(command, sizeof(command), TPM_TAG_RQU_COMMAND,
                           TPM_ORD_GET_RANDOM, &command_size)) return 0;
        put_be32(command + command_size, wanted);
        command_size += 4;
        if (!command_finish(command, sizeof(command), command_size) ||
            !transmit(submit, context, command, command_size, response,
                      sizeof(response), &response_size, &rc) ||
            rc != TPM_SUCCESS || get_be16(response) != TPM_TAG_RSP_COMMAND ||
            response_size < TPM_HEADER_BYTES + 4) {
            wipe(response, sizeof(response));
            return 0;
        }
        take = get_be32(response + TPM_HEADER_BYTES);
        if (take == 0 || take > wanted ||
            take != response_size - TPM_HEADER_BYTES - 4) {
            wipe(response, sizeof(response));
            return 0;
        }
        copy_bytes(output + done, response + TPM_HEADER_BYTES + 4, take);
        done += take;
        wipe(response, sizeof(response));
    }
    return 1;
}

static int oiap_start(ml_tpm12_submit_fn submit, void *context,
                      tpm12_oiap *session)
{
    uint8_t command[TPM_HEADER_BYTES], response[TPM_HEADER_BYTES + 24];
    size_t command_size, response_size = 0;
    uint32_t rc = 0;
    int ok = 0;
    if (!session || !command_start(command, sizeof(command),
            TPM_TAG_RQU_COMMAND, TPM_ORD_OIAP, &command_size) ||
        !command_finish(command, sizeof(command), command_size) ||
        !transmit(submit, context, command, command_size, response,
            sizeof(response), &response_size, &rc) || rc != TPM_SUCCESS ||
        get_be16(response) != TPM_TAG_RSP_COMMAND || response_size != sizeof(response))
        goto done;
    session->handle = get_be32(response + TPM_HEADER_BYTES);
    if (session->handle == 0) goto done;
    copy_bytes(session->nonce_even, response + TPM_HEADER_BYTES + 4, 20);
    ok = 1;
done:
    wipe(response, sizeof(response));
    return ok;
}

static int make_auth(const uint8_t secret[20], uint32_t ordinal,
                     const uint8_t *parameters, size_t parameters_size,
                     const tpm12_oiap *session, const uint8_t nonce_odd[20],
                     uint8_t continue_session, uint8_t output[TPM_AUTH_BYTES])
{
    uint8_t digest_input[ML_TPM12_MAX_BLOB_BYTES + 4];
    uint8_t parameter_digest[20], hmac_input[61];
    size_t digest_size = 0, used = 0;
    int ok = 0;
    if (!secret || !session || !nonce_odd || !output ||
        parameters_size > ML_TPM12_MAX_BLOB_BYTES ||
        (parameters_size && !parameters) ||
        !append(digest_input, sizeof(digest_input), &digest_size,
                (uint8_t[4]){(uint8_t)(ordinal >> 24), (uint8_t)(ordinal >> 16),
                    (uint8_t)(ordinal >> 8), (uint8_t)ordinal}, 4) ||
        !append(digest_input, sizeof(digest_input), &digest_size,
                parameters, parameters_size) ||
        !ml_hash_data(ML_HASH_SHA1, digest_input, digest_size,
                      parameter_digest)) goto done;
    if (!append(hmac_input, sizeof(hmac_input), &used,
                parameter_digest, sizeof(parameter_digest)) ||
        !append(hmac_input, sizeof(hmac_input), &used,
                session->nonce_even, sizeof(session->nonce_even)) ||
        !append(hmac_input, sizeof(hmac_input), &used,
                nonce_odd, 20) ||
        !append(hmac_input, sizeof(hmac_input), &used,
                &continue_session, 1) || used != sizeof(hmac_input) ||
        !ml_hmac_data(ML_HASH_SHA1, secret, 20, hmac_input, used,
                      output + 25)) goto done;
    put_be32(output, session->handle);
    copy_bytes(output + 4, nonce_odd, 20);
    output[24] = continue_session;
    ok = 1;
done:
    wipe(digest_input, sizeof(digest_input));
    wipe(parameter_digest, sizeof(parameter_digest));
    wipe(hmac_input, sizeof(hmac_input));
    return ok;
}

static int verify_auth_response(const uint8_t secret[20], uint32_t ordinal,
                                const uint8_t *parameters,
                                size_t parameters_size,
                                const tpm12_oiap *session,
                                const uint8_t nonce_odd[20],
                                const uint8_t *response_auth,
                                uint8_t expected_continue)
{
    uint8_t digest_input[ML_TPM12_MAX_BLOB_BYTES + 8];
    uint8_t parameter_digest[20], hmac_input[61], expected[20];
    size_t digest_size = 0, used = 0;
    int ok = 0;
    if (!secret || !session || !nonce_odd || !response_auth ||
        parameters_size > ML_TPM12_MAX_BLOB_BYTES ||
        (parameters_size && !parameters) ||
        !append(digest_input, sizeof(digest_input), &digest_size,
                (uint8_t[4]){0, 0, 0, 0}, 4) ||
        !append(digest_input, sizeof(digest_input), &digest_size,
                (uint8_t[4]){(uint8_t)(ordinal >> 24), (uint8_t)(ordinal >> 16),
                    (uint8_t)(ordinal >> 8), (uint8_t)ordinal}, 4) ||
        !append(digest_input, sizeof(digest_input), &digest_size,
                parameters, parameters_size) ||
        !ml_hash_data(ML_HASH_SHA1, digest_input, digest_size,
                      parameter_digest)) goto done;
    if (response_auth[20] != expected_continue ||
        !append(hmac_input, sizeof(hmac_input), &used,
                parameter_digest, sizeof(parameter_digest)) ||
        !append(hmac_input, sizeof(hmac_input), &used,
                response_auth, 20) ||
        !append(hmac_input, sizeof(hmac_input), &used,
                nonce_odd, 20) ||
        !append(hmac_input, sizeof(hmac_input), &used,
                response_auth + 20, 1) || used != sizeof(hmac_input) ||
        !ml_hmac_data(ML_HASH_SHA1, secret, 20, hmac_input, used, expected))
        goto done;
    ok = constant_equal(expected, response_auth + 21, sizeof(expected));
done:
    wipe(digest_input, sizeof(digest_input));
    wipe(parameter_digest, sizeof(parameter_digest));
    wipe(hmac_input, sizeof(hmac_input));
    wipe(expected, sizeof(expected));
    return ok;
}

static int load_key(ml_tpm12_submit_fn submit, void *context,
                    const uint8_t *key_blob, size_t key_blob_size,
                    uint32_t *key_handle)
{
    uint8_t command[TPM_MAX_COMMAND_BYTES];
    uint8_t response[TPM_HEADER_BYTES + 4 + TPM_AUTH_RESPONSE_BYTES];
    uint8_t nonce_odd[20], auth[TPM_AUTH_BYTES], srk_secret[20] = {0};
    tpm12_oiap session = {0};
    size_t command_size = 0, response_size = 0;
    uint32_t rc = 0;
    int ok = 0;
    if (!submit || !key_blob || key_blob_size == 0 ||
        key_blob_size > ML_TPM12_MAX_BLOB_BYTES || !key_handle ||
        !oiap_start(submit, context, &session) ||
        !get_random(submit, context, nonce_odd, sizeof(nonce_odd)) ||
        !make_auth(srk_secret, TPM_ORD_LOAD_KEY2, key_blob, key_blob_size,
                   &session, nonce_odd, 0, auth) ||
        !command_start(command, sizeof(command), TPM_TAG_RQU_AUTH1_COMMAND,
                       TPM_ORD_LOAD_KEY2, &command_size)) goto done;
    put_be32(command + command_size, TPM_KH_SRK);
    command_size += 4;
    if (!append(command, sizeof(command), &command_size, key_blob,
                key_blob_size) ||
        !append(command, sizeof(command), &command_size, auth, sizeof(auth)) ||
        !command_finish(command, sizeof(command), command_size) ||
        !transmit(submit, context, command, command_size, response,
                  sizeof(response), &response_size, &rc) || rc != TPM_SUCCESS ||
        get_be16(response) != TPM_TAG_RSP_AUTH1_COMMAND ||
        response_size != sizeof(response)) goto done;
    *key_handle = get_be32(response + TPM_HEADER_BYTES);
    if (*key_handle == 0 ||
        !verify_auth_response(srk_secret, TPM_ORD_LOAD_KEY2, NULL, 0,
            &session, nonce_odd, response + TPM_HEADER_BYTES + 4, 0)) {
        *key_handle = 0;
        goto done;
    }
    ok = 1;
done:
    wipe(command, sizeof(command));
    wipe(response, sizeof(response));
    wipe(nonce_odd, sizeof(nonce_odd));
    wipe(auth, sizeof(auth));
    wipe(srk_secret, sizeof(srk_secret));
    wipe(&session, sizeof(session));
    return ok;
}

static int unseal_blob(ml_tpm12_submit_fn submit, void *context,
                       uint32_t key_handle,
                       const uint8_t *stored_data, size_t stored_data_size,
                       uint8_t *secret, size_t secret_capacity,
                       size_t *secret_size)
{
    uint8_t command[TPM_MAX_COMMAND_BYTES];
    uint8_t response[TPM_MAX_COMMAND_BYTES];
    uint8_t nonce_odd[2][20], auth[2][TPM_AUTH_BYTES];
    uint8_t usage_secret[20];
    tpm12_oiap sessions[2] = {{0}};
    size_t command_size = 0, response_size = 0, output_size, auth_offset;
    uint32_t rc = 0;
    int ok = 0;
    if (!submit || !key_handle || !stored_data || stored_data_size == 0 ||
        stored_data_size > ML_TPM12_MAX_BLOB_BYTES || !secret ||
        !secret_size || !oiap_start(submit, context, &sessions[0]) ||
        !oiap_start(submit, context, &sessions[1]) ||
        !get_random(submit, context, &nonce_odd[0][0], sizeof(nonce_odd)) ||
        !ml_hash_data(ML_HASH_SHA1, "password", 8, usage_secret) ||
        !make_auth(usage_secret, TPM_ORD_UNSEAL, stored_data,
                   stored_data_size, &sessions[0], nonce_odd[0], 0, auth[0]) ||
        !make_auth(usage_secret, TPM_ORD_UNSEAL, stored_data,
                   stored_data_size, &sessions[1], nonce_odd[1], 0, auth[1]) ||
        !command_start(command, sizeof(command), TPM_TAG_RQU_AUTH2_COMMAND,
                       TPM_ORD_UNSEAL, &command_size)) goto done;
    put_be32(command + command_size, key_handle);
    command_size += 4;
    if (!append(command, sizeof(command), &command_size, stored_data,
                stored_data_size) ||
        !append(command, sizeof(command), &command_size, auth[0], sizeof(auth[0])) ||
        !append(command, sizeof(command), &command_size, auth[1], sizeof(auth[1])) ||
        !command_finish(command, sizeof(command), command_size) ||
        !transmit(submit, context, command, command_size, response,
                  sizeof(response), &response_size, &rc) || rc != TPM_SUCCESS ||
        get_be16(response) != TPM_TAG_RSP_AUTH2_COMMAND ||
        response_size < TPM_HEADER_BYTES + 4 + 2 * TPM_AUTH_RESPONSE_BYTES)
        goto done;
    output_size = get_be32(response + TPM_HEADER_BYTES);
    if (output_size > secret_capacity ||
        output_size != response_size - TPM_HEADER_BYTES - 4 -
                       2 * TPM_AUTH_RESPONSE_BYTES) goto done;
    auth_offset = TPM_HEADER_BYTES + 4 + output_size;
    if (!verify_auth_response(usage_secret, TPM_ORD_UNSEAL,
            response + TPM_HEADER_BYTES, 4 + output_size, &sessions[0],
            nonce_odd[0], response + auth_offset, 0) ||
        !verify_auth_response(usage_secret, TPM_ORD_UNSEAL,
            response + TPM_HEADER_BYTES, 4 + output_size, &sessions[1],
            nonce_odd[1], response + auth_offset + TPM_AUTH_RESPONSE_BYTES, 0))
        goto done;
    copy_bytes(secret, response + TPM_HEADER_BYTES + 4, output_size);
    *secret_size = output_size;
    ok = 1;
done:
    if (!ok && secret && secret_capacity) wipe(secret, secret_capacity);
    if (secret_size && !ok) *secret_size = 0;
    wipe(command, sizeof(command));
    wipe(response, sizeof(response));
    wipe(nonce_odd, sizeof(nonce_odd));
    wipe(auth, sizeof(auth));
    wipe(usage_secret, sizeof(usage_secret));
    wipe(sessions, sizeof(sessions));
    return ok;
}

static void flush_key(ml_tpm12_submit_fn submit, void *context,
                      uint32_t key_handle)
{
    uint8_t command[TPM_HEADER_BYTES + 6], response[TPM_HEADER_BYTES];
    size_t command_size = 0, response_size = 0;
    uint32_t rc = 0;
    if (!key_handle || !command_start(command, sizeof(command),
            TPM_TAG_RQU_COMMAND, TPM_ORD_FLUSH_SPEC, &command_size)) return;
    put_be32(command + command_size, key_handle);
    command_size += 4;
    put_be16(command + command_size, TPM_RT_KEY);
    command_size += 2;
    if (command_finish(command, sizeof(command), command_size))
        (void)transmit(submit, context, command, command_size, response,
                       sizeof(response), &response_size, &rc);
    wipe(response, sizeof(response));
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

static int decode_base64(const uint8_t *input, size_t input_size,
                         uint8_t *output, size_t output_capacity,
                         size_t *output_size)
{
    uint8_t quartet[4];
    size_t q = 0, used = 0, i;
    int finished = 0;
    if (!input || !output || !output_size) return 0;
    for (i = 0; i < input_size; ++i) {
        uint8_t c = input[i];
        if (c == '\r' || c == '\n' || c == ' ' || c == '\t') continue;
        if (finished || (c != '=' && base64_value(c) < 0)) return 0;
        quartet[q++] = c;
        if (q == 4) {
            int a = base64_value(quartet[0]), b = base64_value(quartet[1]);
            int c2 = quartet[2] == '=' ? 0 : base64_value(quartet[2]);
            int d = quartet[3] == '=' ? 0 : base64_value(quartet[3]);
            size_t bytes;
            if (a < 0 || b < 0 || c2 < 0 || d < 0 || quartet[0] == '=' ||
                quartet[1] == '=' || (quartet[2] == '=' && quartet[3] != '='))
                return 0;
            bytes = quartet[2] == '=' ? 1 : quartet[3] == '=' ? 2 : 3;
            if ((quartet[2] == '=' && (b & 0x0f)) ||
                (quartet[3] == '=' && quartet[2] != '=' && (c2 & 0x03)) ||
                used > output_capacity || bytes > output_capacity - used)
                return 0;
            output[used++] = (uint8_t)((a << 2) | (b >> 4));
            if (bytes > 1)
                output[used++] = (uint8_t)((b << 4) | (c2 >> 2));
            if (bytes > 2)
                output[used++] = (uint8_t)((c2 << 6) | d);
            finished = bytes != 3;
            q = 0;
        }
    }
    if (q != 0 || used == 0) return 0;
    *output_size = used;
    return 1;
}

static const uint8_t *find_bytes(const uint8_t *input, size_t input_size,
                                 const char *needle, size_t needle_size)
{
    size_t i;
    if (!input || !needle || needle_size > input_size) return NULL;
    for (i = 0; i <= input_size - needle_size; ++i) {
        size_t j;
        for (j = 0; j < needle_size && input[i + j] == (uint8_t)needle[j]; ++j) {}
        if (j == needle_size) return input + i;
    }
    return NULL;
}

static int decode_section(const uint8_t *begin, const uint8_t *end,
                          uint8_t *output, size_t output_capacity,
                          size_t *output_size)
{
    if (!begin || !end || end < begin) return 0;
    return decode_base64(begin, (size_t)(end - begin), output,
                         output_capacity, output_size);
}

static int parse_tss_envelope(const uint8_t *envelope, size_t envelope_size,
                              uint8_t key_blob[ML_TPM12_MAX_BLOB_BYTES],
                              size_t *key_blob_size,
                              uint8_t stored_data[ML_TPM12_MAX_BLOB_BYTES],
                              size_t *stored_data_size,
                              uint8_t ciphertext[ML_TPM12_MAX_CIPHERTEXT_BYTES],
                              size_t *ciphertext_size)
{
    static const char begin_tag[] = "-----BEGIN TSS-----\n";
    static const char key_tag[] = "-----TSS KEY-----\n";
    static const char enc_key_tag[] = "-----ENC KEY-----\n";
    static const char type_tag[] = "Symmetric Key: AES-256-CBC\n";
    static const char enc_data_tag[] = "-----ENC DAT-----\n";
    static const char end_tag[] = "-----END TSS-----";
    const uint8_t *key_start, *key_end, *stored_start, *stored_end;
    const uint8_t *data_start, *data_end, *cursor;
    size_t begin_size = sizeof(begin_tag) - 1;
    size_t key_size = sizeof(key_tag) - 1;
    size_t enc_key_size = sizeof(enc_key_tag) - 1;
    size_t type_size = sizeof(type_tag) - 1;
    size_t enc_data_size = sizeof(enc_data_tag) - 1;
    size_t end_size = sizeof(end_tag) - 1;
    if (!envelope || envelope_size > ML_TPM12_MAX_ENVELOPE_BYTES ||
        envelope_size < begin_size + key_size + enc_key_size + type_size +
                        enc_data_size + end_size ||
        envelope_size < begin_size ||
        !constant_equal(envelope, (const uint8_t *)begin_tag, begin_size))
        return 0;
    cursor = envelope + begin_size;
    if ((size_t)(envelope + envelope_size - cursor) < key_size ||
        !constant_equal(cursor, (const uint8_t *)key_tag, key_size)) return 0;
    key_start = cursor + key_size;
    key_end = find_bytes(key_start, (size_t)(envelope + envelope_size - key_start),
                         enc_key_tag, enc_key_size);
    if (!key_end) return 0;
    cursor = key_end + enc_key_size;
    if ((size_t)(envelope + envelope_size - cursor) < type_size ||
        !constant_equal(cursor, (const uint8_t *)type_tag, type_size)) return 0;
    stored_start = cursor + type_size;
    stored_end = find_bytes(stored_start,
        (size_t)(envelope + envelope_size - stored_start),
        enc_data_tag, enc_data_size);
    if (!stored_end) return 0;
    data_start = stored_end + enc_data_size;
    data_end = find_bytes(data_start,
        (size_t)(envelope + envelope_size - data_start), end_tag, end_size);
    if (!data_end) return 0;
    cursor = data_end + end_size;
    while (cursor < envelope + envelope_size) {
        if (*cursor != '\r' && *cursor != '\n' && *cursor != ' ' && *cursor != '\t')
            return 0;
        ++cursor;
    }
    return decode_section(key_start, key_end, key_blob,
               ML_TPM12_MAX_BLOB_BYTES, key_blob_size) &&
           decode_section(stored_start, stored_end, stored_data,
               ML_TPM12_MAX_BLOB_BYTES, stored_data_size) &&
           decode_section(data_start, data_end, ciphertext,
               ML_TPM12_MAX_CIPHERTEXT_BYTES, ciphertext_size) &&
           (*ciphertext_size >= 16 && (*ciphertext_size & 15u) == 0);
}

static int aes_cbc_decrypt(const uint8_t key[32], const uint8_t *ciphertext,
                           size_t ciphertext_size, uint8_t *plaintext,
                           size_t plaintext_capacity, size_t *plaintext_size)
{
    static const uint8_t iv_constant[16] = {
        'I','B','M',' ','S','E','A','L','I','B','M',' ','S','E','A','L'
    };
    ml_aes_context aes;
    uint8_t previous[16], block[16], decrypted[16];
    size_t offset, pad, size;
    unsigned i;
    int ok = 0;
    if (!key || !ciphertext || ciphertext_size == 0 ||
        (ciphertext_size & 15u) != 0 || !plaintext || !plaintext_size ||
        ciphertext_size > plaintext_capacity ||
        !ml_aes_set_key(&aes, key, 32)) return 0;
    copy_bytes(previous, iv_constant, sizeof(previous));
    for (offset = 0; offset < ciphertext_size; offset += 16) {
        copy_bytes(block, ciphertext + offset, sizeof(block));
        ml_aes_decrypt_block(&aes, block, decrypted);
        for (i = 0; i < 16; ++i) plaintext[offset + i] = decrypted[i] ^ previous[i];
        copy_bytes(previous, block, sizeof(previous));
    }
    pad = plaintext[ciphertext_size - 1];
    if (pad == 0 || pad > 16 || pad > ciphertext_size) goto done;
    for (i = 0; i < pad; ++i)
        if (plaintext[ciphertext_size - 1 - i] != pad) goto done;
    size = ciphertext_size - pad;
    if (size == 0 || size > plaintext_capacity) goto done;
    *plaintext_size = size;
    ok = 1;
done:
    if (!ok) {
        wipe(plaintext, plaintext_capacity);
        *plaintext_size = 0;
    } else {
        wipe(plaintext + size, ciphertext_size - size);
    }
    wipe(&aes, sizeof(aes));
    wipe(previous, sizeof(previous));
    wipe(block, sizeof(block));
    wipe(decrypted, sizeof(decrypted));
    return ok;
}

static int json_string(const uint8_t *json, size_t json_size,
                       const char *field, uint8_t *value,
                       size_t value_capacity, size_t *value_size)
{
    uint8_t needle[80];
    size_t field_size = 0, needle_size, i, start, used;
    const uint8_t *found;
    if (!json || !field || !value || !value_size) return 0;
    while (field[field_size]) {
        if (field_size + 2 >= sizeof(needle)) return 0;
        needle[field_size + 1] = (uint8_t)field[field_size];
        ++field_size;
    }
    needle[0] = '"';
    needle[field_size + 1] = '"';
    needle_size = field_size + 2;
    found = find_bytes(json, json_size, (const char *)needle, needle_size);
    if (!found) return 0;
    i = (size_t)(found - json) + needle_size;
    while (i < json_size && (json[i] == ' ' || json[i] == '\t' ||
           json[i] == '\r' || json[i] == '\n')) ++i;
    if (i >= json_size || json[i++] != ':') return 0;
    while (i < json_size && (json[i] == ' ' || json[i] == '\t' ||
           json[i] == '\r' || json[i] == '\n')) ++i;
    if (i >= json_size || json[i++] != '"') return 0;
    start = i;
    while (i < json_size && json[i] != '"') {
        if (json[i] == '\\' || json[i] < 0x20) return 0;
        ++i;
    }
    if (i >= json_size || i - start > value_capacity) return 0;
    used = i - start;
    copy_bytes(value, json + start, used);
    *value_size = used;
    return 1;
}

static int json_string_view(const uint8_t *json, size_t json_size,
                            const char *field, const uint8_t **value,
                            size_t *value_size)
{
    uint8_t needle[80];
    size_t field_size = 0, needle_size, i, start;
    const uint8_t *found;
    if (!json || !field || !value || !value_size) return 0;
    while (field[field_size]) {
        if (field_size + 2 >= sizeof(needle)) return 0;
        needle[field_size + 1] = (uint8_t)field[field_size];
        ++field_size;
    }
    needle[0] = '"';
    needle[field_size + 1] = '"';
    needle_size = field_size + 2;
    found = find_bytes(json, json_size, (const char *)needle, needle_size);
    if (!found) return 0;
    i = (size_t)(found - json) + needle_size;
    while (i < json_size && (json[i] == ' ' || json[i] == '\t' ||
           json[i] == '\r' || json[i] == '\n')) ++i;
    if (i >= json_size || json[i++] != ':') return 0;
    while (i < json_size && (json[i] == ' ' || json[i] == '\t' ||
           json[i] == '\r' || json[i] == '\n')) ++i;
    if (i >= json_size || json[i++] != '"') return 0;
    start = i;
    while (i < json_size && json[i] != '"') {
        if (json[i] == '\\' || json[i] < 0x20) return 0;
        ++i;
    }
    if (i >= json_size) return 0;
    *value = json + start;
    *value_size = i - start;
    return 1;
}

static int uuid_equal(const uint8_t *value, size_t value_size,
                      const char *expected)
{
    size_t i;
    if (!expected || value_size != 36) return 0;
    for (i = 0; i < 36; ++i) {
        uint8_t a = value[i], b = (uint8_t)expected[i];
        if (a >= 'A' && a <= 'F') a = (uint8_t)(a + ('a' - 'A'));
        if (b >= 'A' && b <= 'F') b = (uint8_t)(b + ('a' - 'A'));
        if (a != b) return 0;
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (a != '-') return 0;
        } else if (!((a >= '0' && a <= '9') || (a >= 'a' && a <= 'f'))) {
            return 0;
        }
    }
    return expected[36] == '\0';
}

static int unseal_parts(ml_tpm12_submit_fn submit, void *context,
                        const uint8_t *key_blob, size_t key_blob_size,
                        const uint8_t *stored_data, size_t stored_data_size,
                        const uint8_t *ciphertext, size_t ciphertext_size,
                        uint8_t *secret, size_t secret_capacity,
                        size_t *secret_size)
{
    uint8_t key_handle_secret[ML_TPM12_MAX_SECRET_BYTES];
    uint8_t plaintext[ML_TPM12_MAX_CIPHERTEXT_BYTES];
    size_t unsealed_size = 0, plaintext_size = 0;
    uint32_t key_handle = 0;
    int ok = 0;
    if (!secret || !secret_size || secret_capacity == 0 ||
        !load_key(submit, context, key_blob, key_blob_size, &key_handle) ||
        !unseal_blob(submit, context, key_handle, stored_data, stored_data_size,
                     key_handle_secret, sizeof(key_handle_secret), &unsealed_size) ||
        unsealed_size != 32 ||
        !aes_cbc_decrypt(key_handle_secret, ciphertext, ciphertext_size,
                         plaintext, sizeof(plaintext), &plaintext_size) ||
        plaintext_size > secret_capacity) goto done;
    copy_bytes(secret, plaintext, plaintext_size);
    *secret_size = plaintext_size;
    ok = 1;
done:
    if (key_handle) flush_key(submit, context, key_handle);
    wipe(key_handle_secret, sizeof(key_handle_secret));
    wipe(plaintext, sizeof(plaintext));
    if (!ok) {
        if (secret && secret_capacity) wipe(secret, secret_capacity);
        if (secret_size) *secret_size = 0;
    }
    return ok;
}

int ml_tpm12_unseal_envelope(ml_tpm12_submit_fn submit, void *context,
                             const uint8_t *envelope, size_t envelope_size,
                             uint8_t *secret, size_t secret_capacity,
                             size_t *secret_size)
{
    uint8_t key_blob[ML_TPM12_MAX_BLOB_BYTES];
    uint8_t stored_data[ML_TPM12_MAX_BLOB_BYTES];
    uint8_t ciphertext[ML_TPM12_MAX_CIPHERTEXT_BYTES];
    size_t key_blob_size = 0, stored_data_size = 0, ciphertext_size = 0;
    int ok = 0;
    if (secret_size) *secret_size = 0;
    if (!secret || !secret_size || secret_capacity == 0) return 0;
    wipe(secret, secret_capacity);
    if (!parse_tss_envelope(envelope, envelope_size, key_blob,
            &key_blob_size, stored_data, &stored_data_size, ciphertext,
            &ciphertext_size)) goto done;
    ok = unseal_parts(submit, context, key_blob, key_blob_size,
        stored_data, stored_data_size, ciphertext, ciphertext_size,
        secret, secret_capacity, secret_size);
done:
    wipe(key_blob, sizeof(key_blob));
    wipe(stored_data, sizeof(stored_data));
    wipe(ciphertext, sizeof(ciphertext));
    if (!ok) {
        wipe(secret, secret_capacity);
        *secret_size = 0;
    }
    return ok;
}

int ml_tpm12_unseal_sidecar(ml_tpm12_submit_fn submit, void *context,
                            const uint8_t *sidecar, size_t sidecar_size,
                            const char *expected_uuid,
                            uint8_t *secret, size_t secret_capacity,
                            size_t *secret_size)
{
    static const char format_string[] = "miniloader-tpm12-v1";
    uint8_t format[64], uuid[64];
    uint8_t envelope[ML_TPM12_MAX_ENVELOPE_BYTES];
    const uint8_t *encoded = NULL;
    size_t format_size = 0, uuid_size = 0, encoded_size = 0, envelope_size = 0;
    int ok = 0;
    if (secret_size) *secret_size = 0;
    if (!sidecar || sidecar_size == 0 ||
        sidecar_size > ML_TPM12_MAX_ENVELOPE_BYTES * 2u || !expected_uuid ||
        !secret || !secret_size || secret_capacity == 0) return 0;
    wipe(secret, secret_capacity);
    if (!json_string(sidecar, sidecar_size, "format", format,
            sizeof(format), &format_size) ||
        format_size != sizeof(format_string) - 1 ||
        !constant_equal(format, (const uint8_t *)format_string, format_size) ||
        !json_string(sidecar, sidecar_size, "luks_uuid", uuid,
            sizeof(uuid), &uuid_size) || !uuid_equal(uuid, uuid_size, expected_uuid) ||
        !json_string_view(sidecar, sidecar_size, "sealed_blob", &encoded,
            &encoded_size) ||
        !decode_base64(encoded, encoded_size, envelope, sizeof(envelope),
                       &envelope_size)) goto done;
    ok = ml_tpm12_unseal_envelope(submit, context, envelope, envelope_size,
                                  secret, secret_capacity, secret_size);
done:
    wipe(format, sizeof(format));
    wipe(uuid, sizeof(uuid));
    wipe(envelope, sizeof(envelope));
    if (!ok) {
        wipe(secret, secret_capacity);
        *secret_size = 0;
    }
    return ok;
}
