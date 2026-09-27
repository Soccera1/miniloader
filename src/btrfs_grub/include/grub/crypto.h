/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef ML_GRUB_CRYPTO_H
#define ML_GRUB_CRYPTO_H
#include <grub/types.h>
static inline void grub_crypto_xor(void *out, const void *in1,
                                  const void *in2, grub_size_t size)
{
    grub_uint8_t *o = out;
    const grub_uint8_t *a = in1, *b = in2;
    while (size--) *o++ = *a++ ^ *b++;
}
#endif
