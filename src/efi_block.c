/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "ml_uefi.h"

#define ML_UEFI_BLOCK_BUFFER_BYTES (64u * 1024u)
#define ML_UEFI_MAX_BLOCK_SIZE (1024u * 1024u)

static int is_power_of_two(UINTN value)
{
    return value != 0 && (value & (value - 1)) == 0;
}

static int efi_block_read_at(void *context, uint64_t offset,
                             void *buffer, size_t length)
{
    ml_uefi_block *block = (ml_uefi_block *)context;
    EFI_BLOCK_IO_PROTOCOL *protocol;
    EFI_BLOCK_IO_MEDIA *media;
    UINT8 *destination = (UINT8 *)buffer;
    UINTN block_size, done = 0;
    if (!block || !block->protocol || (!buffer && length != 0)) return -1;
    protocol = block->protocol;
    media = protocol->Media;
    if (!media || !media->MediaPresent || media->BlockSize == 0 ||
        media->BlockSize > ML_UEFI_MAX_BLOCK_SIZE)
        return -1;
    block_size = media->BlockSize;
    while (done < length) {
        uint64_t at = offset + done;
        EFI_LBA lba = at / block_size;
        UINTN within = (UINTN)(at % block_size);
        UINTN amount;
        EFI_STATUS status;
        if (within != 0 || (length - done) < block_size) {
            amount = block_size - within;
            if (amount > length - done) amount = length - done;
            if (lba > media->LastBlock) return -1;
            status = protocol->ReadBlocks(protocol, media->MediaId, lba,
                                          block_size, block->aligned_buffer);
            if (EFI_ERROR(status)) return -1;
            CopyMem(destination + done, block->aligned_buffer + within, amount);
            done += amount;
        } else {
            UINTN full_blocks = (length - done) / block_size;
            UINTN max_blocks = block->buffer_size / block_size;
            UINTN bytes;
            if (full_blocks > max_blocks) full_blocks = max_blocks;
            if (full_blocks == 0 || lba > media->LastBlock ||
                (uint64_t)full_blocks - 1 > media->LastBlock - lba)
                return -1;
            bytes = full_blocks * block_size;
            status = protocol->ReadBlocks(protocol, media->MediaId, lba,
                                          bytes, block->aligned_buffer);
            if (EFI_ERROR(status)) return -1;
            CopyMem(destination + done, block->aligned_buffer, bytes);
            done += bytes;
        }
    }
    return 0;
}

EFI_STATUS ml_uefi_block_init(ml_uefi_block *block,
                              EFI_BLOCK_IO_PROTOCOL *protocol)
{
    EFI_BLOCK_IO_MEDIA *media;
    UINTN alignment, allocation_size, address;
    UINTN buffer_size;
    UINT64 lbas, byte_size;
    EFI_STATUS status;
    if (!block || !protocol || !protocol->Media || !protocol->ReadBlocks)
        return EFI_INVALID_PARAMETER;
    SetMem(block, sizeof(*block), 0);
    media = protocol->Media;
    if (!media->MediaPresent || media->BlockSize == 0 ||
        media->BlockSize > ML_UEFI_MAX_BLOCK_SIZE || media->LastBlock == ~(EFI_LBA)0)
        return EFI_UNSUPPORTED;
    lbas = media->LastBlock + 1;
    if (lbas > (~(UINT64)0) / media->BlockSize) return EFI_UNSUPPORTED;
    byte_size = lbas * media->BlockSize;
    alignment = media->IoAlign;
    if (alignment == 0 || alignment < sizeof(VOID *)) alignment = sizeof(VOID *);
    if (!is_power_of_two(alignment) || alignment > ML_UEFI_MAX_BLOCK_SIZE)
        return EFI_UNSUPPORTED;
    buffer_size = media->BlockSize > ML_UEFI_BLOCK_BUFFER_BYTES
        ? media->BlockSize : ML_UEFI_BLOCK_BUFFER_BYTES;
    buffer_size -= buffer_size % media->BlockSize;
    if (buffer_size == 0) buffer_size = media->BlockSize;
    if (buffer_size > (~(UINTN)0) - alignment) return EFI_OUT_OF_RESOURCES;
    allocation_size = buffer_size + alignment;
    status = BS->AllocatePool(EfiLoaderData, allocation_size, &block->allocation);
    if (EFI_ERROR(status)) return status;
    address = (UINTN)block->allocation;
    block->aligned_buffer = (UINT8 *)((address + alignment - 1) & ~(alignment - 1));
    block->buffer_size = buffer_size;
    block->protocol = protocol;
    block->device.context = block;
    block->device.byte_size = byte_size;
    block->device.logical_block_size = media->BlockSize;
    block->device.read_at = efi_block_read_at;
    return EFI_SUCCESS;
}

void ml_uefi_block_close(ml_uefi_block *block)
{
    if (!block) return;
    if (block->allocation) BS->FreePool(block->allocation);
    SetMem(block, sizeof(*block), 0);
}
