/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "ml_argon2id.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    size_t allocations;
    size_t releases;
    size_t bytes;
} allocation_stats;

static int allocate_memory(void *context, uint8_t **memory, size_t size)
{
    allocation_stats *stats = (allocation_stats *)context;
    *memory = (uint8_t *)malloc(size);
    if (!*memory) return -1;
    stats->allocations++;
    stats->bytes = size;
    return 0;
}

static void release_memory(void *context, uint8_t *memory, size_t size)
{
    allocation_stats *stats = (allocation_stats *)context;
    size_t i;
    for (i = 0; i < size; ++i) assert(memory[i] == 0);
    stats->releases++;
    free(memory);
}

static void check_vector(uint32_t memory_kib, uint32_t lanes,
                         const uint8_t expected[32], allocation_stats *stats)
{
    uint8_t output[32];
    static const uint8_t password[] = "password";
    static const uint8_t salt[] = "somesalt";
    assert(ml_argon2id_derive(password, sizeof(password) - 1,
        salt, sizeof(salt) - 1, 2, memory_kib, lanes, output,
        sizeof(output), allocate_memory, release_memory, stats));
    assert(memcmp(output, expected, sizeof(output)) == 0);
    assert(stats->allocations == stats->releases);
    memset(output, 0, sizeof(output));
}

int main(void)
{
    static const uint8_t vector_lanes1[32] = {
        0x31,0x11,0x1c,0xc0,0x53,0xba,0x0a,0x79,
        0x9c,0x08,0x84,0x14,0x8f,0xd7,0xec,0x9d,
        0xc3,0x63,0x1f,0x3e,0x8c,0xf4,0x76,0xcc,
        0xa9,0x52,0x1d,0x4c,0xcc,0x51,0x36,0xe8
    };
    static const uint8_t vector_lanes2[32] = {
        0x94,0x38,0x74,0x15,0xdf,0xb8,0x4e,0xd1,
        0x97,0x74,0x65,0xa1,0xe8,0x62,0x60,0x73,
        0xad,0xf4,0x2b,0xd4,0xee,0xae,0x1f,0xaa,
        0x1d,0xd4,0xe2,0x3a,0x1f,0xf6,0x85,0x9f
    };
    allocation_stats stats = {0, 0, 0};
    uint8_t output[32];
    check_vector(32, 1, vector_lanes1, &stats);
    check_vector(64, 2, vector_lanes2, &stats);
    assert(!ml_argon2id_derive("password", 8, "somesalt", 8,
        2, 8, 2, output, sizeof(output), allocate_memory, release_memory,
        &stats));
    assert(stats.allocations == 2 && stats.releases == 2);
    puts("Argon2id reference vectors and secure memory release passed");
    return 0;
}
