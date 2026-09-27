/* SPDX-License-Identifier: Zlib */
#include <limits.h>
#include <zlib.h>
#include <grub/deflate.h>
#include <grub/mm.h>

voidpf zcalloc(voidpf opaque, unsigned items, unsigned size)
{
    (void)opaque;
    if (size && items > (unsigned)((grub_size_t)-1 / size)) return Z_NULL;
    return grub_zalloc((grub_size_t)items * size);
}

void zcfree(voidpf opaque, voidpf pointer)
{
    (void)opaque;
    grub_free(pointer);
}

/* Decompress a zlib stream while copying only the requested output range. */
grub_ssize_t grub_zlib_decompress(const char *input, grub_size_t input_size,
                                  grub_off_t offset, char *output,
                                  grub_size_t output_size)
{
    z_stream stream;
    unsigned char temporary[4096];
    size_t supplied = 0, skipped = 0, copied = 0;
    int status;
    if ((!input && input_size) || (!output && output_size) || offset < 0 ||
        (uint64_t)offset > (uint64_t)LONG_MAX ||
        output_size > (grub_size_t)LONG_MAX)
        return -1;
    if (!output_size) return 0;
    stream.zalloc = zcalloc;
    stream.zfree = zcfree;
    stream.opaque = Z_NULL;
    stream.avail_in = 0;
    stream.next_in = Z_NULL;
    stream.avail_out = 0;
    stream.next_out = Z_NULL;
    if (inflateInit2(&stream, MAX_WBITS) != Z_OK) return -1;
    status = Z_OK;
    while (status == Z_OK) {
        size_t produced, discard, take;
        if (!stream.avail_in && supplied < input_size) {
            size_t chunk = input_size - supplied;
            if (chunk > UINT_MAX) chunk = UINT_MAX;
            stream.next_in = (Bytef *)(input + supplied);
            stream.avail_in = (uInt)chunk;
            supplied += chunk;
        }
        stream.next_out = temporary;
        stream.avail_out = sizeof(temporary);
        status = inflate(&stream, Z_NO_FLUSH);
        produced = sizeof(temporary) - stream.avail_out;
        discard = (size_t)offset > skipped ? (size_t)offset - skipped : 0;
        if (discard > produced) discard = produced;
        skipped += discard;
        take = produced - discard;
        if (take > output_size - copied) take = output_size - copied;
        if (take) {
            unsigned char *destination = (unsigned char *)output + copied;
            const unsigned char *source = temporary + discard;
            size_t i;
            for (i = 0; i < take; ++i) destination[i] = source[i];
            copied += take;
        }
        if (copied == output_size) {
            inflateEnd(&stream);
            return (grub_ssize_t)copied;
        }
        if (status == Z_STREAM_END) break;
        if (status != Z_OK || (!produced && !stream.avail_in &&
                               supplied == input_size)) break;
    }
    inflateEnd(&stream);
    return -1;
}
