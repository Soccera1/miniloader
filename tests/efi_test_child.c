/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <efi.h>
#include <efilib.h>

static EFI_GUID load_file2_guid = {
    0x4006c0c1, 0xfcb3, 0x403e, {0x99, 0x6d, 0x4a, 0x6c, 0x87, 0x24, 0xe0, 0x6d}
};

typedef struct __attribute__((packed)) {
    EFI_DEVICE_PATH_PROTOCOL header;
    EFI_GUID guid;
    EFI_DEVICE_PATH_PROTOCOL end;
} initrd_path;

static initrd_path request_path = {
    {MEDIA_DEVICE_PATH, MEDIA_VENDOR_DP, {20, 0}},
    {0x5568e427, 0x68fc, 0x4f3d, {0xac, 0x74, 0xca, 0x55, 0x52, 0x31, 0xcc, 0x68}},
    {END_DEVICE_PATH_TYPE, END_ENTIRE_DEVICE_PATH_SUBTYPE, {4, 0}}
};

static EFI_STATUS fail(CHAR16 *message)
{
    ST->ConOut->OutputString(ST->ConOut, message);
    return EFI_LOAD_ERROR;
}

EFI_STATUS EFIAPI efi_main(EFI_HANDLE image_handle, EFI_SYSTEM_TABLE *system_table)
{
    EFI_LOADED_IMAGE_PROTOCOL *loaded = NULL;
    EFI_DEVICE_PATH_PROTOCOL *remaining = (EFI_DEVICE_PATH_PROTOCOL *)&request_path;
    EFI_HANDLE handle = NULL;
    EFI_LOAD_FILE2_PROTOCOL *load_file = NULL;
    UINTN size = 0;
    VOID *bytes = NULL;
    EFI_STATUS status;
    const CHAR16 *options = L"smoke=1";
    static const CHAR8 expected[] = "initrd-ok\n";

    ST = system_table;
    BS = system_table->BootServices;
    status = BS->HandleProtocol(image_handle, &gEfiLoadedImageProtocolGuid, (VOID **)&loaded);
    if (EFI_ERROR(status) || !loaded) return fail(L"MINILOADER_CHILD_FAIL_LOADED_IMAGE\r\n");
    if (!loaded->LoadOptions && loaded->LoadOptionsSize == 0) {
        ST->ConOut->OutputString(ST->ConOut, L"MINILOADER_EFI_CHILD_OK\r\n");
        return EFI_SUCCESS;
    }
    if (!loaded->LoadOptions || loaded->LoadOptionsSize != sizeof(L"smoke=1") ||
        CompareMem(loaded->LoadOptions, (VOID *)options, sizeof(L"smoke=1")) != 0)
        return fail(L"MINILOADER_CHILD_FAIL_OPTIONS\r\n");

    status = BS->LocateDevicePath(&load_file2_guid, &remaining, &handle);
    if (EFI_ERROR(status) || !handle) return fail(L"MINILOADER_CHILD_FAIL_DEVICE_PATH\r\n");
    status = BS->HandleProtocol(handle, &load_file2_guid, (VOID **)&load_file);
    if (EFI_ERROR(status) || !load_file) return fail(L"MINILOADER_CHILD_FAIL_PROTOCOL\r\n");
    status = load_file->LoadFile(load_file, remaining, FALSE, &size, NULL);
    if (status != EFI_BUFFER_TOO_SMALL || size != sizeof(expected) - 1) return fail(L"MINILOADER_CHILD_FAIL_SIZE\r\n");
    status = BS->AllocatePool(EfiLoaderData, size, &bytes);
    if (EFI_ERROR(status)) return fail(L"MINILOADER_CHILD_FAIL_ALLOC\r\n");
    status = load_file->LoadFile(load_file, remaining, FALSE, &size, bytes);
    if (EFI_ERROR(status) || size != sizeof(expected) - 1 ||
        CompareMem(bytes, (VOID *)expected, sizeof(expected) - 1) != 0) {
        BS->FreePool(bytes);
        return fail(L"MINILOADER_CHILD_FAIL_BYTES\r\n");
    }
    BS->FreePool(bytes);
    ST->ConOut->OutputString(ST->ConOut, L"MINILOADER_LINUX_CHILD_OK\r\n");
    return EFI_SUCCESS;
}
