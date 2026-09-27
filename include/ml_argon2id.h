/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef ML_ARGON2ID_H
#define ML_ARGON2ID_H

#include <stddef.h>
#include <stdint.h>

typedef int (*ml_argon2_allocate_fn)(void *context, uint8_t **memory,
                                    size_t bytes);
typedef void (*ml_argon2_free_fn)(void *context, uint8_t *memory,
                                  size_t bytes);

int ml_argon2id_derive(const void *password, size_t password_size,
                       const void *salt, size_t salt_size,
                       uint32_t time_cost, uint32_t memory_kib,
                       uint32_t lanes, void *output, size_t output_size,
                       ml_argon2_allocate_fn allocate,
                       ml_argon2_free_fn release, void *allocator_context);

#endif
