/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef ML_GRUB_DEFLATE_H
#define ML_GRUB_DEFLATE_H
#include <grub/types.h>
grub_ssize_t grub_zlib_decompress(const char *input, grub_size_t input_size,
                                  grub_off_t offset, char *output,
                                  grub_size_t output_size);
#endif
