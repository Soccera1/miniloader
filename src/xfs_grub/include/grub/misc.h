/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef ML_GRUB_MISC_H
#define ML_GRUB_MISC_H
#include <grub/types.h>
#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))
void *grub_memcpy(void *dst, const void *src, grub_size_t n);
void *grub_memset(void *dst, int c, grub_size_t n);
void *grub_memmove(void *dst, const void *src, grub_size_t n);
int grub_memcmp(const void *a, const void *b, grub_size_t n);
int grub_strncmp(const char *a, const char *b, grub_size_t n);
int grub_strcmp(const char *a, const char *b);
int grub_strcasecmp(const char *a, const char *b);
char *grub_strdup(const char *s);
char *grub_strndup(const char *s, grub_size_t n);
grub_size_t grub_strlen(const char *s);
char *grub_strchr(const char *s, int c);
static inline grub_uint64_t grub_divmod64(grub_uint64_t value,
                                          grub_uint64_t divisor,
                                          grub_uint64_t *remainder)
{
    if (remainder) *remainder = value % divisor;
    return value / divisor;
}
void grub_dprintf(const char *channel, const char *format, ...);
#define N_(x) (x)
#endif
