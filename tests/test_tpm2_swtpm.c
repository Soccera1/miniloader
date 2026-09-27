/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "ml_tpm2.h"

#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_tcti.h>
#include <tss2/tss2_tcti_swtpm.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    TSS2_TCTI_CONTEXT *tcti;
    ESYS_CONTEXT *esys;
} swtpm_context;

static int submit_to_swtpm(void *context, const uint8_t *command,
                           size_t command_size, uint8_t *response,
                           size_t response_capacity, size_t *response_size)
{
    swtpm_context *swtpm = (swtpm_context *)context;
    TSS2_TCTI_CONTEXT_COMMON_V1 *common =
        (TSS2_TCTI_CONTEXT_COMMON_V1 *)swtpm->tcti;
    size_t size = response_capacity;
    TSS2_RC rc = common->transmit(swtpm->tcti, command_size, command);
    if (rc != TSS2_RC_SUCCESS) return 0;
    rc = common->receive(swtpm->tcti, &size, response,
                         TSS2_TCTI_TIMEOUT_BLOCK);
    if (rc != TSS2_RC_SUCCESS || size > response_capacity) return 0;
    *response_size = size;
    return 1;
}

static int check_rc(TSS2_RC rc, const char *operation)
{
    if (rc == TSS2_RC_SUCCESS) return 1;
    fprintf(stderr, "%s failed: 0x%08x\n", operation, rc);
    return 0;
}

int main(int argc, char **argv)
{
    const char *config = argc > 1 ? argv[1] : "host=127.0.0.1,port=2321";
    int rsa_mode = argc > 2 && strcmp(argv[2], "rsa") == 0;
    int sha1_mode = argc > 2 && strcmp(argv[2], "sha1") == 0;
    uint16_t pcr_bank = sha1_mode ? TPM2_ALG_SHA1 : TPM2_ALG_SHA256;
    size_t tcti_size = 0, blob_size = 0, offset = 0;
    TSS2_ABI_VERSION abi = TSS2_ABI_VERSION_CURRENT;
    TSS2_RC rc;
    swtpm_context context = {0};
    TPM2B_SENSITIVE_CREATE primary_sensitive = {0};
    TPM2B_PUBLIC primary_template = {0}, sealed_template = {0};
    TPM2B_SENSITIVE_CREATE sealed_sensitive = {0};
    TPML_PCR_SELECTION selection = {0}, empty_creation_pcr = {0};
    TPM2B_DATA outside_info = {0};
    TPMT_SYM_DEF session_symmetric = {0};
    TPM2B_PRIVATE *private = NULL;
    TPM2B_PUBLIC *public = NULL;
    TPM2B_DIGEST *policy = NULL;
    ESYS_TR primary = ESYS_TR_NONE, session = ESYS_TR_NONE;
    uint8_t blob[ML_TPM2_MAX_COMMAND_BYTES];
    uint8_t expected[32], actual[64];
    size_t actual_size = 0;
    ml_tpm2_token token = {0};
    size_t i;
    int exit_status = 1;

    rc = Tss2_Tcti_Swtpm_Init(NULL, &tcti_size, config);
    if (rc != TSS2_RC_SUCCESS || tcti_size == 0) {
        fprintf(stderr, "could not query swtpm TCTI size: 0x%08x\n", rc);
        goto done;
    }
    context.tcti = (TSS2_TCTI_CONTEXT *)calloc(1, tcti_size);
    if (!context.tcti) goto done;
    rc = Tss2_Tcti_Swtpm_Init(context.tcti, &tcti_size, config);
    if (!check_rc(rc, "TCTI initialization")) goto done;
    rc = Esys_Initialize(&context.esys, context.tcti, &abi);
    if (!check_rc(rc, "ESAPI initialization")) goto done;
    rc = Esys_Startup(context.esys, TPM2_SU_CLEAR);
    if (rc != TSS2_RC_SUCCESS && rc != TPM2_RC_INITIALIZE) {
        if (!check_rc(rc, "TPM startup")) goto done;
    }

    primary_template.size = sizeof(TPMT_PUBLIC);
    primary_template.publicArea.type = rsa_mode ? TPM2_ALG_RSA : TPM2_ALG_ECC;
    primary_template.publicArea.nameAlg = TPM2_ALG_SHA256;
    primary_template.publicArea.objectAttributes = TPMA_OBJECT_RESTRICTED |
        TPMA_OBJECT_DECRYPT | TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT |
        TPMA_OBJECT_SENSITIVEDATAORIGIN | TPMA_OBJECT_USERWITHAUTH;
    if (rsa_mode) {
        primary_template.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM2_ALG_AES;
        primary_template.publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 128;
        primary_template.publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM2_ALG_CFB;
        primary_template.publicArea.parameters.rsaDetail.scheme.scheme = TPM2_ALG_NULL;
        primary_template.publicArea.parameters.rsaDetail.keyBits = 2048;
    } else {
        primary_template.publicArea.parameters.eccDetail.symmetric.algorithm = TPM2_ALG_AES;
        primary_template.publicArea.parameters.eccDetail.symmetric.keyBits.aes = 128;
        primary_template.publicArea.parameters.eccDetail.symmetric.mode.aes = TPM2_ALG_CFB;
        primary_template.publicArea.parameters.eccDetail.scheme.scheme = TPM2_ALG_NULL;
        primary_template.publicArea.parameters.eccDetail.curveID = TPM2_ECC_NIST_P256;
        primary_template.publicArea.parameters.eccDetail.kdf.scheme = TPM2_ALG_NULL;
    }
    rc = Esys_CreatePrimary(context.esys, ESYS_TR_RH_OWNER,
        ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
        &primary_sensitive, &primary_template, &outside_info,
        &empty_creation_pcr,
        &primary, NULL, NULL, NULL, NULL);
    if (!check_rc(rc, "primary creation")) goto done;

    selection.count = 1;
    selection.pcrSelections[0].hash = pcr_bank;
    selection.pcrSelections[0].sizeofSelect = 3;
    selection.pcrSelections[0].pcrSelect[0] = 1u << 7;
    selection.pcrSelections[0].pcrSelect[1] = 1u << (11 - 8);
    session_symmetric.algorithm = TPM2_ALG_AES;
    session_symmetric.keyBits.aes = 128;
    session_symmetric.mode.aes = TPM2_ALG_CFB;
    rc = Esys_StartAuthSession(context.esys, ESYS_TR_NONE, ESYS_TR_NONE,
        ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, NULL,
        TPM2_SE_POLICY, &session_symmetric, TPM2_ALG_SHA256, &session);
    if (!check_rc(rc, "policy session creation")) goto done;
    rc = Esys_PolicyPCR(context.esys, session, ESYS_TR_NONE, ESYS_TR_NONE,
        ESYS_TR_NONE, NULL, &selection);
    if (!check_rc(rc, "PCR policy setup")) goto done;
    rc = Esys_PolicyGetDigest(context.esys, session, ESYS_TR_NONE,
        ESYS_TR_NONE, ESYS_TR_NONE, &policy);
    if (!check_rc(rc, "PCR policy digest")) goto done;

    for (i = 0; i < sizeof(expected); ++i) expected[i] = (uint8_t)(i + 0x31);
    sealed_sensitive.size = sizeof(TPMS_SENSITIVE_CREATE);
    sealed_sensitive.sensitive.data.size = sizeof(expected);
    memcpy(sealed_sensitive.sensitive.data.buffer, expected, sizeof(expected));
    sealed_template.size = sizeof(TPMT_PUBLIC);
    sealed_template.publicArea.type = TPM2_ALG_KEYEDHASH;
    sealed_template.publicArea.nameAlg = TPM2_ALG_SHA256;
    sealed_template.publicArea.objectAttributes =
        TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT;
    sealed_template.publicArea.authPolicy = *policy;
    sealed_template.publicArea.parameters.keyedHashDetail.scheme.scheme = TPM2_ALG_NULL;
    sealed_template.publicArea.unique.keyedHash.size = 32;
    rc = Esys_Create(context.esys, primary, ESYS_TR_PASSWORD,
        ESYS_TR_NONE, ESYS_TR_NONE, &sealed_sensitive, &sealed_template,
        &outside_info, &empty_creation_pcr, &private, &public, NULL, NULL, NULL);
    if (!check_rc(rc, "sealed key creation")) goto done;

    rc = Tss2_MU_TPM2B_PRIVATE_Marshal(private, blob, sizeof(blob), &offset);
    if (!check_rc(rc, "private blob marshal")) goto done;
    rc = Tss2_MU_TPM2B_PUBLIC_Marshal(public, blob, sizeof(blob), &offset);
    if (!check_rc(rc, "public blob marshal")) goto done;
    blob_size = offset;
    token.pcr_mask = (1u << 7) | (1u << 11);
    token.pcr_bank = pcr_bank;
    token.primary_algorithm = rsa_mode ? ML_TPM2_ALG_RSA : ML_TPM2_ALG_ECC;
    if (policy->size != sizeof(token.policy_hash)) goto done;
    memcpy(token.policy_hash, policy->buffer, sizeof(token.policy_hash));
    memcpy(token.blob, blob, blob_size);
    token.blob_size = blob_size;

    (void)Esys_FlushContext(context.esys, session);
    session = ESYS_TR_NONE;
    (void)Esys_FlushContext(context.esys, primary);
    primary = ESYS_TR_NONE;
    if (!ml_tpm2_unseal(submit_to_swtpm, &context, &token,
                        actual, sizeof(actual), &actual_size) ||
        actual_size != sizeof(expected) ||
        memcmp(actual, expected, sizeof(expected)) != 0) {
        fprintf(stderr, "TPM2 systemd-token unseal did not return the sealed secret\n");
        goto done;
    }

    token.pcr_mask ^= 1u;
    memset(actual, 0xa5, sizeof(actual));
    actual_size = 123;
    if (ml_tpm2_unseal(submit_to_swtpm, &context, &token,
                       actual, sizeof(actual), &actual_size) ||
        actual_size != 0) {
        fprintf(stderr, "TPM2 PCR mismatch was not rejected\n");
        goto done;
    }
    for (i = 0; i < sizeof(actual); ++i)
        if (actual[i] != 0) {
            fprintf(stderr, "TPM2 failure path did not wipe output\n");
            goto done;
        }
    puts("TPM2 systemd-token unseal and PCR mismatch checks passed");
    exit_status = 0;
done:
    if (session != ESYS_TR_NONE) (void)Esys_FlushContext(context.esys, session);
    if (primary != ESYS_TR_NONE) (void)Esys_FlushContext(context.esys, primary);
    if (private) Esys_Free(private);
    if (public) Esys_Free(public);
    if (policy) Esys_Free(policy);
    if (context.esys) Esys_Finalize(&context.esys);
    if (context.tcti) {
        TSS2_TCTI_CONTEXT_COMMON_V1 *common =
            (TSS2_TCTI_CONTEXT_COMMON_V1 *)context.tcti;
        if (common->finalize) common->finalize(context.tcti);
        free(context.tcti);
    }
    memset(expected, 0, sizeof(expected));
    memset(actual, 0, sizeof(actual));
    memset(blob, 0, sizeof(blob));
    memset(&token, 0, sizeof(token));
    return exit_status;
}
