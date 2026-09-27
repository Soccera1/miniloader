/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <efi.h>
#include <efilib.h>

EFI_SYSTEM_TABLE *ST;
EFI_BOOT_SERVICES *BS;

EFI_GUID gEfiDevicePathProtocolGuid = {
    0x09576e91, 0x6d3f, 0x11d2, {0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b}
};
EFI_GUID gEfiLoadedImageProtocolGuid = {
    0x5b1b31a1, 0x9562, 0x11d2, {0x8e, 0x3f, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b}
};
EFI_GUID gEfiSimpleFileSystemProtocolGuid = {
    0x964e5b22, 0x6459, 0x11d2, {0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b}
};
EFI_GUID gEfiBlockIoProtocolGuid = {
    0x964e5b21, 0x6459, 0x11d2, {0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b}
};
EFI_GUID gEfiFileInfoGuid = {
    0x09576e92, 0x6d3f, 0x11d2, {0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b}
};
EFI_GUID gEfiLoadFile2ProtocolGuid = {
    0x4006c0c1, 0xfcb3, 0x403e, {0x99, 0x6d, 0x4a, 0x6c, 0x87, 0x24, 0xe0, 0x6d}
};

VOID EFIAPI SetMem(VOID *buffer, UINTN size, UINT8 value)
{
    UINT8 *bytes = (UINT8 *)buffer;
    UINTN i;
    for (i = 0; i < size; ++i) bytes[i] = value;
}

VOID EFIAPI CopyMem_1(VOID *destination, VOID *source, UINTN length)
{
    UINT8 *dst = (UINT8 *)destination;
    const UINT8 *src = (const UINT8 *)source;
    UINTN i;
    UINTN dst_address = (UINTN)dst;
    UINTN src_address = (UINTN)src;
    if (dst == src || length == 0) return;
    if (dst_address < src_address || dst_address - src_address >= length) {
        for (i = 0; i < length; ++i) dst[i] = src[i];
    } else {
        for (i = length; i > 0; --i) dst[i - 1] = src[i - 1];
    }
}

INTN CompareMem(CONST VOID *first, CONST VOID *second, UINTN length)
{
    const UINT8 *a = (const UINT8 *)first;
    const UINT8 *b = (const UINT8 *)second;
    UINTN i;
    for (i = 0; i < length; ++i) {
        if (a[i] != b[i]) return (INTN)a[i] - (INTN)b[i];
    }
    return 0;
}
