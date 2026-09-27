/* SPDX-License-Identifier: GPL-3.0-or-later */
/* C memory primitives needed by the freestanding Argon2 reference core. */
#include <stddef.h>

void *memcpy(void *destination, const void *source, size_t size)
{
    unsigned char *out = (unsigned char *)destination;
    const unsigned char *in = (const unsigned char *)source;
    size_t i;
    for (i = 0; i < size; ++i) out[i] = in[i];
    return destination;
}

void *memset(void *destination, int value, size_t size)
{
    unsigned char *out = (unsigned char *)destination;
    size_t i;
    for (i = 0; i < size; ++i) out[i] = (unsigned char)value;
    return destination;
}
