/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef ML_ZFS_GRUB_CRYPTO_H
#define ML_ZFS_GRUB_CRYPTO_H
#include <grub/types.h>
typedef void *grub_crypto_cipher_handle_t;
static inline void grub_crypto_xor(void *out, const void *left,
                                   const void *right, grub_size_t size)
{
  grub_uint8_t *o = out;
  const grub_uint8_t *a = left, *b = right;
  while (size--) *o++ = *a++ ^ *b++;
}
static inline void grub_crypto_cipher_close(grub_crypto_cipher_handle_t cipher)
{
  (void)cipher;
}
#endif
