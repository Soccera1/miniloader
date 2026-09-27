/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Minimal TPM 2.0 command client for systemd-compatible LUKS2 tokens. */
#include "ml_tpm2.h"

#include <string.h>

#define TPM_ST_NO_SESSIONS 0x8001u
#define TPM_ST_SESSIONS    0x8002u
#define TPM_RC_INITIALIZE  0x00000100u
#define TPM_RH_OWNER       0x40000001u
#define TPM_RH_NULL        0x40000007u
#define TPM_RS_PW          0x40000009u
#define TPM_ALG_SHA1       0x0004u
#define TPM_ALG_SHA256     0x000bu
#define TPM_ALG_AES        0x0006u
#define TPM_ALG_NULL       0x0010u
#define TPM_ALG_CFB        0x0043u
#define TPM_ALG_ECC        0x0023u
#define TPM_ALG_RSA        0x0001u
#define TPM_ECC_NIST_P256  0x0003u
#define TPM_SE_POLICY      0x01u
#define TPM_CC_STARTUP             0x00000144u
#define TPM_CC_GET_RANDOM          0x0000017bu
#define TPM_CC_START_AUTH_SESSION  0x00000176u
#define TPM_CC_POLICY_PCR          0x0000017fu
#define TPM_CC_POLICY_GET_DIGEST   0x00000189u
#define TPM_CC_CREATE_PRIMARY      0x00000131u
#define TPM_CC_LOAD                0x00000157u
#define TPM_CC_UNSEAL              0x0000015eu
#define TPM_CC_FLUSH_CONTEXT       0x00000165u

typedef struct {
    const uint8_t *data;
    size_t size;
} tpm_span;

static uint16_t get_be16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static uint32_t get_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
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

static void wipe(void *buffer, size_t size)
{
    volatile uint8_t *p = (volatile uint8_t *)buffer;
    while (size--) *p++ = 0;
}

static void copy_bytes(void *destination, const void *source, size_t size)
{
    volatile uint8_t *dst = (volatile uint8_t *)destination;
    const uint8_t *src = (const uint8_t *)source;
    size_t i;
    for (i = 0; i < size; ++i) dst[i] = src[i];
}

static void set_bytes(void *destination, uint8_t value, size_t size)
{
    volatile uint8_t *dst = (volatile uint8_t *)destination;
    size_t i;
    for (i = 0; i < size; ++i) dst[i] = value;
}

static int ct_equal(const uint8_t *a, const uint8_t *b, size_t size)
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

static int append_u8(uint8_t *buffer, size_t capacity, size_t *used,
                     uint8_t value)
{
    return append(buffer, capacity, used, &value, sizeof(value));
}

static int append_u16(uint8_t *buffer, size_t capacity, size_t *used,
                      uint16_t value)
{
    uint8_t bytes[2];
    put_be16(bytes, value);
    return append(buffer, capacity, used, bytes, sizeof(bytes));
}

static int append_u32(uint8_t *buffer, size_t capacity, size_t *used,
                      uint32_t value)
{
    uint8_t bytes[4];
    put_be32(bytes, value);
    return append(buffer, capacity, used, bytes, sizeof(bytes));
}

static int transmit(ml_tpm2_submit_fn submit, void *context,
                    uint16_t tag, uint32_t code,
                    const uint32_t *handles, size_t handle_count,
                    const uint8_t *authorization, size_t authorization_size,
                    const uint8_t *parameters, size_t parameter_size,
                    uint8_t *response, size_t response_capacity,
                    size_t *response_size, uint32_t *return_code)
{
    uint8_t command[ML_TPM2_MAX_COMMAND_BYTES];
    size_t command_size = 10, response_length = 0, i;
    uint32_t rc;
    if (!submit || !response || !response_size || !return_code ||
        handle_count > 3 ||
        (tag != TPM_ST_NO_SESSIONS && tag != TPM_ST_SESSIONS) ||
        (tag == TPM_ST_NO_SESSIONS && authorization_size) ||
        (tag == TPM_ST_SESSIONS && (!authorization || !authorization_size)))
        return 0;
    put_be16(command, tag);
    put_be32(command + 6, code);
    for (i = 0; i < handle_count; ++i) {
        if (!append_u32(command, sizeof(command), &command_size, handles[i]))
            return 0;
    }
    if (authorization_size) {
        if (authorization_size > UINT32_MAX ||
            !append_u32(command, sizeof(command), &command_size,
                        (uint32_t)authorization_size) ||
            !append(command, sizeof(command), &command_size,
                    authorization, authorization_size)) return 0;
    }
    if (!append(command, sizeof(command), &command_size,
                parameters, parameter_size)) return 0;
    if (command_size > UINT32_MAX) return 0;
    put_be32(command + 2, (uint32_t)command_size);
    if (!submit(context, command, command_size, response, response_capacity,
                &response_length) || response_length < 10 ||
        response_length > response_capacity ||
        get_be32(response + 2) != response_length) {
        wipe(command, command_size);
        return 0;
    }
    rc = get_be32(response + 6);
    *return_code = rc;
    *response_size = response_length;
    wipe(command, command_size);
    return 1;
}

static int response_parts(const uint8_t *response, size_t response_size,
                          size_t handle_count, int sessions,
                          tpm_span *parameters)
{
    size_t offset = 10u + 4u * handle_count;
    uint16_t tag;
    if (!response || !parameters || response_size < offset) return 0;
    tag = get_be16(response);
    if (sessions) {
        uint32_t parameter_size;
        size_t auth_offset;
        uint16_t nonce_size, hmac_size;
        if (tag != TPM_ST_SESSIONS || response_size - offset < 4) return 0;
        parameter_size = get_be32(response + offset);
        offset += 4;
        if (parameter_size > response_size - offset) return 0;
        parameters->data = response + offset;
        parameters->size = parameter_size;
        auth_offset = offset + parameter_size;
        if (response_size - auth_offset < 5) return 0;
        nonce_size = get_be16(response + auth_offset);
        auth_offset += 2;
        if (nonce_size > response_size - auth_offset) return 0;
        auth_offset += nonce_size;
        if (auth_offset >= response_size) return 0;
        ++auth_offset; /* TPMA_SESSION */
        if (response_size - auth_offset < 2) return 0;
        hmac_size = get_be16(response + auth_offset);
        auth_offset += 2;
        if (hmac_size != response_size - auth_offset) return 0;
    } else {
        if (tag != TPM_ST_NO_SESSIONS) return 0;
        parameters->data = response + offset;
        parameters->size = response_size - offset;
    }
    return 1;
}

static int send_simple(ml_tpm2_submit_fn submit, void *context,
                       uint32_t code, const uint32_t *handles,
                       size_t handle_count, const uint8_t *parameters,
                       size_t parameter_size, uint32_t *returned_handle,
                       tpm_span *response_parameters)
{
    uint8_t response[ML_TPM2_MAX_RESPONSE_BYTES];
    size_t response_size = 0;
    uint32_t rc = 0;
    tpm_span view;
    if (!transmit(submit, context, TPM_ST_NO_SESSIONS, code,
                  handles, handle_count, NULL, 0,
                  parameters, parameter_size, response, sizeof(response),
                  &response_size, &rc) || rc != 0 ||
        !response_parts(response, response_size,
                        returned_handle ? 1u : 0u, 0, &view)) {
        wipe(response, sizeof(response));
        return 0;
    }
    if (returned_handle) *returned_handle = get_be32(response + 10);
    if (response_parameters) *response_parameters = view;
    else if (view.size != 0) {
        wipe(response, sizeof(response));
        return 0;
    }
    wipe(response, sizeof(response));
    return 1;
}

static int get_random(ml_tpm2_submit_fn submit, void *context,
                      uint8_t *nonce, size_t nonce_size)
{
    uint8_t request[2], response[ML_TPM2_MAX_RESPONSE_BYTES];
    size_t response_size = 0;
    uint32_t rc = 0;
    tpm_span params;
    if (!nonce || nonce_size == 0 || nonce_size > 32) return 0;
    put_be16(request, (uint16_t)nonce_size);
    if (!transmit(submit, context, TPM_ST_NO_SESSIONS, TPM_CC_GET_RANDOM,
                  NULL, 0, NULL, 0, request, sizeof(request), response,
                  sizeof(response), &response_size, &rc) || rc != 0 ||
        !response_parts(response, response_size, 0, 0, &params) ||
        params.size < 2 || get_be16(params.data) != nonce_size ||
        params.size != nonce_size + 2) {
        wipe(response, sizeof(response));
        return 0;
    }
    copy_bytes(nonce, params.data + 2, nonce_size);
    wipe(response, sizeof(response));
    return 1;
}

static int start_policy_session(ml_tpm2_submit_fn submit, void *context,
                                uint32_t *session)
{
    uint8_t params[64], nonce[16], response[ML_TPM2_MAX_RESPONSE_BYTES];
    uint32_t handles[2] = { TPM_RH_NULL, TPM_RH_NULL };
    size_t used = 0, response_size = 0;
    uint32_t rc = 0;
    tpm_span response_params;
    int ok = 0;
    if (!get_random(submit, context, nonce, sizeof(nonce))) goto done;
    if (!append_u16(params, sizeof(params), &used, sizeof(nonce)) ||
        !append(params, sizeof(params), &used, nonce, sizeof(nonce)) ||
        !append_u16(params, sizeof(params), &used, 0) ||
        !append_u8(params, sizeof(params), &used, TPM_SE_POLICY) ||
        !append_u16(params, sizeof(params), &used, TPM_ALG_AES) ||
        !append_u16(params, sizeof(params), &used, 128) ||
        !append_u16(params, sizeof(params), &used, TPM_ALG_CFB) ||
        !append_u16(params, sizeof(params), &used, TPM_ALG_SHA256)) goto done;
    if (!transmit(submit, context, TPM_ST_NO_SESSIONS,
                  TPM_CC_START_AUTH_SESSION, handles, 2, NULL, 0,
                  params, used, response, sizeof(response), &response_size,
                  &rc) || rc != 0 ||
        !response_parts(response, response_size, 1, 0, &response_params) ||
        response_params.size < 2 ||
        get_be16(response_params.data) != response_params.size - 2) goto done;
    *session = get_be32(response + 10);
    ok = *session != 0;
done:
    wipe(params, sizeof(params));
    wipe(nonce, sizeof(nonce));
    wipe(response, sizeof(response));
    return ok;
}

static int policy_pcr(ml_tpm2_submit_fn submit, void *context,
                      uint32_t session, const ml_tpm2_token *token)
{
    uint8_t params[16];
    size_t used = 0;
    uint32_t handles[1] = { session };
    uint16_t bank = token->pcr_bank;
    if (bank != TPM_ALG_SHA1 && bank != TPM_ALG_SHA256) return 0;
    if (!append_u16(params, sizeof(params), &used, 0) ||
        !append_u32(params, sizeof(params), &used, 1) ||
        !append_u16(params, sizeof(params), &used, bank) ||
        !append_u8(params, sizeof(params), &used, 3) ||
        !append_u8(params, sizeof(params), &used,
                   (uint8_t)token->pcr_mask) ||
        !append_u8(params, sizeof(params), &used,
                   (uint8_t)(token->pcr_mask >> 8)) ||
        !append_u8(params, sizeof(params), &used,
                   (uint8_t)(token->pcr_mask >> 16))) return 0;
    return send_simple(submit, context, TPM_CC_POLICY_PCR, handles, 1,
                       params, used, NULL, NULL);
}

static int policy_digest(ml_tpm2_submit_fn submit, void *context,
                         uint32_t session, uint8_t digest[32])
{
    uint8_t response[ML_TPM2_MAX_RESPONSE_BYTES];
    uint32_t handles[1] = { session };
    size_t response_size = 0;
    uint32_t rc = 0;
    tpm_span params;
    int ok = 0;
    if (!transmit(submit, context, TPM_ST_NO_SESSIONS,
                  TPM_CC_POLICY_GET_DIGEST, handles, 1, NULL, 0,
                  NULL, 0, response, sizeof(response), &response_size, &rc) ||
        rc != 0 || !response_parts(response, response_size, 0, 0, &params) ||
        params.size != 34 || get_be16(params.data) != 32) goto done;
    copy_bytes(digest, params.data + 2, 32);
    ok = 1;
done:
    wipe(response, sizeof(response));
    return ok;
}

static int make_primary_public(uint16_t algorithm, uint8_t *output,
                               size_t capacity, size_t *output_size)
{
    uint8_t area[64];
    size_t used = 0;
    uint32_t attributes = 0x00030072u;
    if (!append_u16(area, sizeof(area), &used, algorithm) ||
        !append_u16(area, sizeof(area), &used, TPM_ALG_SHA256) ||
        !append_u32(area, sizeof(area), &used, attributes) ||
        !append_u16(area, sizeof(area), &used, 0)) return 0;
    if (algorithm == TPM_ALG_ECC) {
        if (!append_u16(area, sizeof(area), &used, TPM_ALG_AES) ||
            !append_u16(area, sizeof(area), &used, 128) ||
            !append_u16(area, sizeof(area), &used, TPM_ALG_CFB) ||
            !append_u16(area, sizeof(area), &used, TPM_ALG_NULL) ||
            !append_u16(area, sizeof(area), &used, TPM_ECC_NIST_P256) ||
            !append_u16(area, sizeof(area), &used, TPM_ALG_NULL) ||
            !append_u16(area, sizeof(area), &used, 0) ||
            !append_u16(area, sizeof(area), &used, 0)) return 0;
    } else if (algorithm == TPM_ALG_RSA) {
        if (!append_u16(area, sizeof(area), &used, TPM_ALG_AES) ||
            !append_u16(area, sizeof(area), &used, 128) ||
            !append_u16(area, sizeof(area), &used, TPM_ALG_CFB) ||
            !append_u16(area, sizeof(area), &used, TPM_ALG_NULL) ||
            !append_u16(area, sizeof(area), &used, 2048) ||
            !append_u32(area, sizeof(area), &used, 0) ||
            !append_u16(area, sizeof(area), &used, 0)) return 0;
    } else return 0;
    if (used > UINT16_MAX || capacity < used + 2) return 0;
    put_be16(output, (uint16_t)used);
    copy_bytes(output + 2, area, used);
    *output_size = used + 2;
    wipe(area, sizeof(area));
    return 1;
}

static int create_primary(ml_tpm2_submit_fn submit, void *context,
                          uint16_t algorithm, uint32_t *primary)
{
    uint8_t params[128], public_area[96];
    uint8_t response[ML_TPM2_MAX_RESPONSE_BYTES];
    uint8_t empty_password_auth[9];
    size_t used = 0, public_size = 0, response_size = 0;
    uint32_t handles[1] = { TPM_RH_OWNER }, rc = 0;
    tpm_span response_params;
    int ok = 0;
    set_bytes(empty_password_auth, 0, sizeof(empty_password_auth));
    put_be32(empty_password_auth, TPM_RS_PW);
    /* TPM2B_SENSITIVE_CREATE: empty userAuth and empty data. */
    if (!append_u16(params, sizeof(params), &used, 4) ||
        !append_u16(params, sizeof(params), &used, 0) ||
        !append_u16(params, sizeof(params), &used, 0) ||
        !make_primary_public(algorithm, public_area, sizeof(public_area),
                             &public_size) ||
        !append(params, sizeof(params), &used, public_area, public_size) ||
        !append_u16(params, sizeof(params), &used, 0) || /* outsideInfo */
        !append_u32(params, sizeof(params), &used, 0)) /* creationPCR */
        goto done;
    if (!transmit(submit, context, TPM_ST_SESSIONS,
                  TPM_CC_CREATE_PRIMARY, handles, 1,
                  empty_password_auth, sizeof(empty_password_auth),
                  params, used, response, sizeof(response), &response_size,
                  &rc) || rc != 0 ||
        !response_parts(response, response_size, 1, 1, &response_params) ||
        response_params.size < 2) goto done;
    *primary = get_be32(response + 10);
    ok = *primary != 0;
done:
    wipe(params, sizeof(params));
    wipe(public_area, sizeof(public_area));
    wipe(response, sizeof(response));
    wipe(empty_password_auth, sizeof(empty_password_auth));
    return ok;
}

static int parse_blob(const ml_tpm2_token *token, tpm_span *private_blob,
                     tpm_span *public_blob)
{
    size_t offset, private_size, public_size, area_offset, area_size;
    const uint8_t *p;
    uint16_t type, name_alg, policy_size, scheme, unique_size;
    uint32_t attributes;
    if (!token || token->blob_size < 2) return 0;
    p = token->blob;
    private_size = get_be16(p);
    if (private_size == 0 || private_size > token->blob_size - 2) return 0;
    offset = 2 + private_size;
    if (token->blob_size - offset < 2) return 0;
    public_size = get_be16(p + offset);
    if (public_size == 0 || public_size != token->blob_size - offset - 2)
        return 0;
    area_offset = offset + 2;
    area_size = public_size;
    if (area_size < 12) return 0;
    type = get_be16(p + area_offset);
    name_alg = get_be16(p + area_offset + 2);
    attributes = get_be32(p + area_offset + 4);
    policy_size = get_be16(p + area_offset + 8);
    if (type != 0x0008 || name_alg != TPM_ALG_SHA256 || attributes != 0x12 ||
        policy_size != 32 || area_size < (size_t)10 + policy_size + 4)
        return 0;
    if (!ct_equal(p + area_offset + 10, token->policy_hash, 32)) return 0;
    scheme = get_be16(p + area_offset + 10 + policy_size);
    unique_size = get_be16(p + area_offset + 12 + policy_size);
    if (scheme != TPM_ALG_NULL || unique_size != 32 ||
        area_size != (size_t)14 + policy_size + unique_size) return 0;
    private_blob->data = p;
    private_blob->size = 2 + private_size;
    public_blob->data = p + offset;
    public_blob->size = 2 + public_size;
    return 1;
}

static int load_sealed_object(ml_tpm2_submit_fn submit, void *context,
                              uint32_t primary, tpm_span private_blob,
                              tpm_span public_blob, uint32_t *object)
{
    uint8_t params[ML_TPM2_MAX_COMMAND_BYTES];
    uint8_t response[ML_TPM2_MAX_RESPONSE_BYTES];
    uint8_t empty_password_auth[9];
    size_t used = 0, response_size = 0;
    uint32_t handles[1] = { primary }, rc = 0;
    tpm_span response_params;
    int ok = 0;
    set_bytes(empty_password_auth, 0, sizeof(empty_password_auth));
    put_be32(empty_password_auth, TPM_RS_PW);
    if (!append(params, sizeof(params), &used, private_blob.data,
                private_blob.size) ||
        !append(params, sizeof(params), &used, public_blob.data,
                public_blob.size)) goto done;
    if (!transmit(submit, context, TPM_ST_SESSIONS, TPM_CC_LOAD,
                  handles, 1, empty_password_auth,
                  sizeof(empty_password_auth), params, used,
                  response, sizeof(response), &response_size, &rc) || rc != 0 ||
        !response_parts(response, response_size, 1, 1, &response_params) ||
        response_params.size < 2) goto done;
    *object = get_be32(response + 10);
    ok = *object != 0;
done:
    wipe(params, sizeof(params));
    wipe(response, sizeof(response));
    wipe(empty_password_auth, sizeof(empty_password_auth));
    return ok;
}

static int unseal_object_result(ml_tpm2_submit_fn submit, void *context,
                                uint32_t object, uint32_t session,
                                uint8_t *secret, size_t capacity,
                                size_t *secret_size)
{
    uint8_t response[ML_TPM2_MAX_RESPONSE_BYTES];
    uint8_t authorization[9];
    uint32_t handles[1] = { object }, rc = 0;
    size_t response_size = 0;
    tpm_span params;
    uint16_t data_size;
    int ok = 0;
    put_be32(authorization, session);
    put_be16(authorization + 4, 0);
    authorization[6] = 0;
    put_be16(authorization + 7, 0);
    if (!transmit(submit, context, TPM_ST_SESSIONS, TPM_CC_UNSEAL,
                  handles, 1, authorization, sizeof(authorization),
                  NULL, 0, response, sizeof(response), &response_size, &rc) ||
        rc != 0 || !response_parts(response, response_size, 0, 1, &params) ||
        params.size < 2) goto done;
    data_size = get_be16(params.data);
    if (data_size == 0 || data_size > params.size - 2 ||
        data_size > capacity || params.size != (size_t)data_size + 2 ||
        data_size > 64) goto done;
    copy_bytes(secret, params.data + 2, data_size);
    *secret_size = data_size;
    ok = 1;
done:
    if (!ok && secret && capacity) wipe(secret, capacity);
    wipe(response, sizeof(response));
    wipe(authorization, sizeof(authorization));
    return ok;
}

static void flush_context(ml_tpm2_submit_fn submit, void *context,
                          uint32_t handle)
{
    uint32_t handles[1] = { handle };
    if (handle) (void)send_simple(submit, context, TPM_CC_FLUSH_CONTEXT,
                                  handles, 1, NULL, 0, NULL, NULL);
}

int ml_tpm2_unseal(ml_tpm2_submit_fn submit, void *context,
                   const ml_tpm2_token *token,
                   uint8_t *secret, size_t secret_capacity,
                   size_t *secret_size)
{
    uint8_t response[ML_TPM2_MAX_RESPONSE_BYTES];
    uint32_t primary = 0, session = 0, object = 0;
    uint32_t rc = 0;
    size_t response_size = 0;
    uint8_t policy[32];
    tpm_span private_blob, public_blob;
    int ok = 0;
    if (secret_size) *secret_size = 0;
    if (!secret || !secret_capacity || !secret_size || !submit || !token ||
        token->pcr_mask == 0 || (token->pcr_mask & 0xff000000u) != 0 ||
        (token->pcr_bank != TPM_ALG_SHA1 && token->pcr_bank != TPM_ALG_SHA256) ||
        (token->primary_algorithm != TPM_ALG_ECC &&
         token->primary_algorithm != TPM_ALG_RSA) ||
        !parse_blob(token, &private_blob, &public_blob)) goto done;
    if (!transmit(submit, context, TPM_ST_NO_SESSIONS, TPM_CC_STARTUP,
                  NULL, 0, NULL, 0, (const uint8_t[]){0, 0}, 2,
                  response, sizeof(response), &response_size, &rc) ||
        (rc != 0 && rc != TPM_RC_INITIALIZE)) goto done;
    if (!start_policy_session(submit, context, &session) ||
        !policy_pcr(submit, context, session, token) ||
        !policy_digest(submit, context, session, policy) ||
        !ct_equal(policy, token->policy_hash, sizeof(policy)) ||
        !create_primary(submit, context, token->primary_algorithm, &primary) ||
        !load_sealed_object(submit, context, primary, private_blob,
                            public_blob, &object) ||
        !unseal_object_result(submit, context, object, session, secret,
                              secret_capacity, secret_size)) goto done;
    ok = 1;
done:
    if (object) flush_context(submit, context, object);
    if (primary) flush_context(submit, context, primary);
    if (session) flush_context(submit, context, session);
    wipe(response, sizeof(response));
    wipe(policy, sizeof(policy));
    if (!ok) {
        if (secret && secret_capacity) wipe(secret, secret_capacity);
        if (secret_size) *secret_size = 0;
    }
    return ok;
}
