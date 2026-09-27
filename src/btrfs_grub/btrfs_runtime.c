/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <efi.h>
#include <efilib.h>
#include <stddef.h>
#include <stdint.h>

typedef union {
    struct { size_t size; } info;
    uint64_t alignment[2];
} runtime_header;

static void *runtime_allocate(size_t size)
{
    runtime_header *header;
    if (!BS || size > SIZE_MAX - sizeof(*header) ||
        EFI_ERROR(BS->AllocatePool(EfiLoaderData,
                                   size + sizeof(*header), (VOID **)&header)))
        return NULL;
    header->info.size = size;
    return header + 1;
}

void *malloc(size_t size)
{
    return runtime_allocate(size ? size : 1);
}

void *calloc(size_t count, size_t size)
{
    size_t total, i;
    unsigned char *result;
    if (size && count > SIZE_MAX / size) return NULL;
    total = count * size;
    result = runtime_allocate(total ? total : 1);
    if (!result) return NULL;
    for (i = 0; i < total; ++i) result[i] = 0;
    return result;
}

void free(void *pointer)
{
    runtime_header *header;
    if (!pointer || !BS) return;
    header = ((runtime_header *)pointer) - 1;
    (void)BS->FreePool(header);
}

void *realloc(void *pointer, size_t size)
{
    runtime_header *header;
    void *replacement;
    size_t old_size, copy_size, i;
    unsigned char *out, *in;
    if (!pointer) return malloc(size);
    if (!size) { free(pointer); return NULL; }
    header = ((runtime_header *)pointer) - 1;
    old_size = header->info.size;
    replacement = malloc(size);
    if (!replacement) return NULL;
    out = replacement;
    in = pointer;
    copy_size = old_size < size ? old_size : size;
    for (i = 0; i < copy_size; ++i) out[i] = in[i];
    free(pointer);
    return replacement;
}

void *memcpy(void *destination, const void *source, size_t length)
{
    unsigned char *out = destination;
    const unsigned char *in = source;
    size_t i;
    for (i = 0; i < length; ++i) out[i] = in[i];
    return destination;
}

void *memmove(void *destination, const void *source, size_t length)
{
    unsigned char *out = destination;
    const unsigned char *in = source;
    size_t i;
    if ((uintptr_t)out < (uintptr_t)in || (uintptr_t)out - (uintptr_t)in >= length) {
        for (i = 0; i < length; ++i) out[i] = in[i];
    } else {
        for (i = length; i > 0; --i) out[i - 1] = in[i - 1];
    }
    return destination;
}

void *memset(void *destination, int value, size_t length)
{
    unsigned char *out = destination;
    size_t i;
    for (i = 0; i < length; ++i) out[i] = (unsigned char)value;
    return destination;
}

int memcmp(const void *left, const void *right, size_t length)
{
    const unsigned char *a = left, *b = right;
    size_t i;
    for (i = 0; i < length; ++i)
        if (a[i] != b[i]) return (int)a[i] - (int)b[i];
    return 0;
}
