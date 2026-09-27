/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * Thin MiniLoader adapter around the Argon2 reference core. The reference
 * implementation and its CC0/Apache notices are kept in this directory.
 */
/*
 * Argon2 reference source code package - reference C implementations
 * Copyright 2015 Daniel Dinu, Dmitry Khovratovich,
 * Jean-Philippe Aumasson, and Samuel Neves.
 * Licensed under CC0 1.0 or Apache License 2.0; see LICENSE in this directory.
 */
#include "argon2.h"
#include "core.h"
#include "ml_argon2id.h"

#include <limits.h>

/* Adapted from upstream src/argon2.c; the wrapper APIs that allocate their
 * own output buffers and encode strings are intentionally omitted. */
int argon2_ctx(argon2_context *context, argon2_type type)
{
    int result = validate_inputs(context);
    uint32_t memory_blocks, segment_length;
    argon2_instance_t instance;
    if (result != ARGON2_OK) return result;
    if (type != Argon2_d && type != Argon2_i && type != Argon2_id)
        return ARGON2_INCORRECT_TYPE;
    memory_blocks = context->m_cost;
    if (memory_blocks < 2 * ARGON2_SYNC_POINTS * context->lanes)
        memory_blocks = 2 * ARGON2_SYNC_POINTS * context->lanes;
    segment_length = memory_blocks / (context->lanes * ARGON2_SYNC_POINTS);
    memory_blocks = segment_length * (context->lanes * ARGON2_SYNC_POINTS);
    instance.version = context->version;
    instance.memory = NULL;
    instance.passes = context->t_cost;
    instance.memory_blocks = memory_blocks;
    instance.segment_length = segment_length;
    instance.lane_length = segment_length * ARGON2_SYNC_POINTS;
    instance.lanes = context->lanes;
    instance.threads = context->threads;
    instance.type = type;
    if (instance.threads > instance.lanes) instance.threads = instance.lanes;
    result = initialize(&instance, context);
    if (result != ARGON2_OK) return result;
    result = fill_memory_blocks(&instance);
    if (result != ARGON2_OK) return result;
    finalize(context, &instance);
    return ARGON2_OK;
}

int ml_argon2id_derive(const void *password, size_t password_size,
                       const void *salt, size_t salt_size,
                       uint32_t time_cost, uint32_t memory_kib,
                       uint32_t lanes, void *output, size_t output_size,
                       ml_argon2_allocate_fn allocate,
                       ml_argon2_free_fn release, void *allocator_context)
{
    argon2_context context;
    int result;
    if (!output || output_size < ARGON2_MIN_OUTLEN ||
        output_size > UINT32_MAX || password_size > UINT32_MAX ||
        salt_size > UINT32_MAX || !allocate || !release) return 0;
    context.out = (uint8_t *)output;
    context.outlen = (uint32_t)output_size;
    context.pwd = (uint8_t *)(uintptr_t)password;
    context.pwdlen = (uint32_t)password_size;
    context.salt = (uint8_t *)(uintptr_t)salt;
    context.saltlen = (uint32_t)salt_size;
    context.secret = NULL;
    context.secretlen = 0;
    context.ad = NULL;
    context.adlen = 0;
    context.t_cost = time_cost;
    context.m_cost = memory_kib;
    context.lanes = lanes;
    context.threads = 1;
    context.version = ARGON2_VERSION_13;
    context.allocate_cbk = allocate;
    context.free_cbk = release;
    context.allocator_context = allocator_context;
    context.flags = ARGON2_DEFAULT_FLAGS;
    result = argon2_ctx(&context, Argon2_id);
    return result == ARGON2_OK;
}
