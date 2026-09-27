/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef ML_TPM12_H
#define ML_TPM12_H

#include <stddef.h>
#include <stdint.h>

#define ML_TPM12_MAX_BLOB_BYTES 8192u
#define ML_TPM12_MAX_ENVELOPE_BYTES 32768u
#define ML_TPM12_MAX_CIPHERTEXT_BYTES 4096u
#define ML_TPM12_MAX_SECRET_BYTES 256u

typedef int (*ml_tpm12_submit_fn)(void *context,
                                  const uint8_t *command, size_t command_size,
                                  uint8_t *response, size_t response_capacity,
                                  size_t *response_size);

/* Unseal a tpm-tools 1.3.9.x `tpm_sealdata` envelope and decrypt its payload. */
int ml_tpm12_unseal_envelope(ml_tpm12_submit_fn submit, void *context,
                             const uint8_t *envelope, size_t envelope_size,
                             uint8_t *secret, size_t secret_capacity,
                             size_t *secret_size);

/* Parse MiniLoader's UUID-linked JSON sidecar and unseal the embedded envelope. */
int ml_tpm12_unseal_sidecar(ml_tpm12_submit_fn submit, void *context,
                            const uint8_t *sidecar, size_t sidecar_size,
                            const char *expected_uuid,
                            uint8_t *secret, size_t secret_capacity,
                            size_t *secret_size);

#endif
