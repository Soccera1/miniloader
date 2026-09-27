/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef ML_GRUB_MM_H
#define ML_GRUB_MM_H
#include <grub/types.h>
void *grub_malloc(grub_size_t size);
void *grub_zalloc(grub_size_t size);
void *grub_realloc(void *old, grub_size_t size);
void *grub_calloc(grub_size_t count, grub_size_t size);
void grub_free(void *ptr);
#endif
