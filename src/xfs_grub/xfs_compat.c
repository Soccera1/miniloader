/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <grub/disk.h>
#include <grub/err.h>
#include <grub/misc.h>
#include <grub/mm.h>
#include <grub/types.h>
#include "ml_block.h"

#if defined(ML_XFS_UEFI)
#include <efi.h>
#include <efilib.h>
#else
#include <stdlib.h>
#endif

typedef union {
    struct { grub_size_t size; } info;
    grub_uint64_t alignment[2];
} allocation_header;

grub_err_t grub_errno = GRUB_ERR_NONE;

static void *platform_allocate(grub_size_t size)
{
    allocation_header *header;
    if (size > (grub_size_t)-1 - sizeof(*header)) return NULL;
#if defined(ML_XFS_UEFI)
    if (EFI_ERROR(BS->AllocatePool(EfiLoaderData, size + sizeof(*header),
                                   (VOID **)&header))) return NULL;
#else
    header = (allocation_header *)malloc(size + sizeof(*header));
    if (!header) return NULL;
#endif
    header->info.size = size;
    return header + 1;
}

void *grub_malloc(grub_size_t size)
{
    void *result = platform_allocate(size ? size : 1);
    if (!result) grub_errno = GRUB_ERR_OUT_OF_MEMORY;
    return result;
}

void *grub_zalloc(grub_size_t size)
{
    void *result = grub_malloc(size);
    if (result) grub_memset(result, 0, size);
    return result;
}

void *grub_calloc(grub_size_t count, grub_size_t size)
{
    grub_size_t total;
    if (size && count > (grub_size_t)-1 / size) {
        grub_errno = GRUB_ERR_OUT_OF_MEMORY;
        return NULL;
    }
    total = count * size;
    return grub_zalloc(total);
}

void grub_free(void *ptr)
{
    allocation_header *header;
    if (!ptr) return;
    header = ((allocation_header *)ptr) - 1;
#if defined(ML_XFS_UEFI)
    BS->FreePool(header);
#else
    free(header);
#endif
}

void *grub_realloc(void *old, grub_size_t size)
{
    allocation_header *header;
    grub_size_t old_size;
    void *next;
    if (!old) return grub_malloc(size);
    if (!size) { grub_free(old); return NULL; }
    header = ((allocation_header *)old) - 1;
    old_size = header->info.size;
    next = grub_malloc(size);
    if (!next) return NULL;
    grub_memcpy(next, old, old_size < size ? old_size : size);
    grub_free(old);
    return next;
}

void *grub_memcpy(void *dst, const void *src, grub_size_t n)
{
    grub_uint8_t *d = (grub_uint8_t *)dst;
    const grub_uint8_t *s = (const grub_uint8_t *)src;
    grub_size_t i;
    for (i = 0; i < n; ++i) d[i] = s[i];
    return dst;
}

void *grub_memset(void *dst, int c, grub_size_t n)
{
    grub_uint8_t *d = (grub_uint8_t *)dst;
    grub_size_t i;
    for (i = 0; i < n; ++i) d[i] = (grub_uint8_t)c;
    return dst;
}

void *grub_memmove(void *dst, const void *src, grub_size_t n)
{
    grub_uint8_t *d = dst;
    const grub_uint8_t *s = src;
    grub_size_t i;
    if (d == s || !n) return dst;
    if ((grub_addr_t)d < (grub_addr_t)s ||
        (grub_addr_t)d - (grub_addr_t)s >= (grub_addr_t)n) {
        for (i = 0; i < n; ++i) d[i] = s[i];
    } else {
        for (i = n; i > 0; --i) d[i - 1] = s[i - 1];
    }
    return dst;
}

int grub_memcmp(const void *left, const void *right, grub_size_t n)
{
    const grub_uint8_t *a = left, *b = right;
    grub_size_t i;
    for (i = 0; i < n; ++i)
        if (a[i] != b[i]) return (int)a[i] - (int)b[i];
    return 0;
}

grub_size_t grub_strlen(const char *s)
{
    grub_size_t n = 0;
    while (s[n]) ++n;
    return n;
}

char *grub_strchr(const char *s, int c)
{
    unsigned char wanted = (unsigned char)c;
    do {
        if ((unsigned char)*s == wanted) return (char *)s;
    } while (*s++);
    return NULL;
}

int grub_strncmp(const char *a, const char *b, grub_size_t n)
{
    grub_size_t i;
    for (i = 0; i < n; ++i) {
        unsigned char x = (unsigned char)a[i], y = (unsigned char)b[i];
        if (x != y || !x || !y) return (int)x - (int)y;
    }
    return 0;
}

int grub_strcmp(const char *a, const char *b)
{
    while (*a && *a == *b) { ++a; ++b; }
    return (int)(unsigned char)*a - (int)(unsigned char)*b;
}

int grub_strcasecmp(const char *a, const char *b)
{
    while (*a && *b) {
        unsigned char x = (unsigned char)*a++, y = (unsigned char)*b++;
        if (x >= 'A' && x <= 'Z') x = (unsigned char)(x + ('a' - 'A'));
        if (y >= 'A' && y <= 'Z') y = (unsigned char)(y + ('a' - 'A'));
        if (x != y) return (int)x - (int)y;
    }
    return (int)(unsigned char)*a - (int)(unsigned char)*b;
}

char *grub_strndup(const char *s, grub_size_t n)
{
    grub_size_t length = 0;
    char *copy;
    while (length < n && s[length]) ++length;
    copy = grub_malloc(length + 1);
    if (!copy) return NULL;
    grub_memcpy(copy, s, length);
    copy[length] = '\0';
    return copy;
}

char *grub_strdup(const char *s)
{
    grub_size_t length = 0;
    while (s[length]) ++length;
    return grub_strndup(s, length);
}

void grub_dprintf(const char *channel, const char *format, ...)
{
    (void)channel;
    (void)format;
}

void grub_print_error(void) { }

grub_err_t grub_error(grub_err_t code, const char *format, ...)
{
    (void)format;
    grub_errno = code;
    return code;
}

grub_err_t grub_disk_read(grub_disk_t disk, grub_disk_addr_t sector,
                          grub_size_t offset, grub_size_t length, void *buffer)
{
    grub_uint64_t byte_offset;
    if (!disk || !disk->device || !disk->device->read_at ||
        (!buffer && length)) {
        grub_errno = GRUB_ERR_BAD_FS;
        return grub_errno;
    }
    if (sector > ((grub_uint64_t)-1 - offset) / 512u) {
        grub_errno = GRUB_ERR_OUT_OF_RANGE;
        return grub_errno;
    }
    byte_offset = sector * 512u + offset;
    if (ml_block_read(disk->device, byte_offset, buffer, length) != ML_BLOCK_OK) {
        grub_errno = GRUB_ERR_OUT_OF_RANGE;
        return grub_errno;
    }
    if (disk->read_hook)
        disk->read_hook(sector, offset, length, disk->read_hook_data);
    return GRUB_ERR_NONE;
}
