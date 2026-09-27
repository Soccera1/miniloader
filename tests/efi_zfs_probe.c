/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "ml_uefi.h"

#define ML_ZFS_PROBE_MAX_BLOCKS 32u
#define ML_ZFS_PROBE_FILE_SIZE 4096u

static EFI_GUID block_io_protocol_guid = EFI_BLOCK_IO_PROTOCOL_GUID;

static void report(EFI_SYSTEM_TABLE *system_table, const CHAR16 *message)
{
    if (system_table && system_table->ConOut)
        (void)system_table->ConOut->OutputString(
            system_table->ConOut, (CHAR16 *)message);
}

EFI_STATUS EFIAPI efi_main(EFI_HANDLE image_handle,
                           EFI_SYSTEM_TABLE *system_table)
{
    static ml_uefi_block blocks[ML_ZFS_PROBE_MAX_BLOCKS];
    static const ml_block_device *devices[ML_ZFS_PROBE_MAX_BLOCKS];
    EFI_HANDLE *handles = NULL;
    UINTN handle_count = 0, device_count = 0, i;
    EFI_STATUS status;
    ml_zfs filesystem;
    ml_zfs_file file;
    const char *message = NULL;
    UINT8 contents[ML_ZFS_PROBE_FILE_SIZE];
    size_t bytes_read = 0;
    int mounted = 0, file_open = 0, success = 0;
    (void)image_handle;

    ST = system_table;
    BS = system_table ? system_table->BootServices : NULL;
    if (!ST || !BS) {
        report(system_table, L"MINILOADER_ZFS_PROBE_NO_BOOT_SERVICES\r\n");
        return EFI_INVALID_PARAMETER;
    }
    status = BS->LocateHandleBuffer(ByProtocol, &block_io_protocol_guid,
                                    NULL, &handle_count, &handles);
    if (EFI_ERROR(status) || !handles) {
        report(system_table, L"MINILOADER_ZFS_PROBE_NO_BLOCK_IO\r\n");
        return EFI_NOT_FOUND;
    }
    for (i = 0; i < handle_count && device_count < ML_ZFS_PROBE_MAX_BLOCKS;
         ++i) {
        EFI_BLOCK_IO_PROTOCOL *protocol = NULL;
        if (EFI_ERROR(BS->HandleProtocol(handles[i], &block_io_protocol_guid,
                                         (VOID **)&protocol)) ||
            !protocol || !protocol->Media || !protocol->Media->MediaPresent)
            continue;
        if (EFI_ERROR(ml_uefi_block_init(&blocks[device_count], protocol)))
            continue;
        devices[device_count] = &blocks[device_count].device;
        ++device_count;
    }
    (void)BS->FreePool(handles);
    handles = NULL;
    if (device_count == 0) {
        report(system_table, L"MINILOADER_ZFS_PROBE_NO_PRESENT_BLOCKS\r\n");
        return EFI_NOT_FOUND;
    }

    ml_zfs_set_devices(devices, device_count);
    for (i = 0; i < device_count; ++i) {
        if (ml_zfs_mount(&filesystem, devices[i], &message) != ML_ZFS_OK)
            continue;
        mounted = 1;
        if (ml_zfs_open(&file, &filesystem, "fs@/L3F1", &message) !=
            ML_ZFS_OK)
            goto cleanup;
        file_open = 1;
        if (file.size != ML_ZFS_PROBE_FILE_SIZE ||
            ml_zfs_read(&file, 0, contents, sizeof(contents), &bytes_read,
                        &message) != ML_ZFS_OK ||
            bytes_read != sizeof(contents))
            goto cleanup;
        for (i = 0; i < sizeof(contents); ++i) {
            if (contents[i] != 0) goto cleanup;
        }
        success = 1;
        break;
    }

cleanup:
    if (file_open) ml_zfs_close_file(&file);
    if (mounted) ml_zfs_unmount(&filesystem);
    ml_zfs_set_devices(NULL, 0);
    for (i = 0; i < device_count; ++i)
        ml_uefi_block_close(&blocks[i]);
    if (success) {
        report(system_table, L"MINILOADER_ZFS_BLOCK_IO_READ_OK\r\n");
        return EFI_SUCCESS;
    }
    report(system_table, L"MINILOADER_ZFS_BLOCK_IO_READ_FAILED\r\n");
    return EFI_DEVICE_ERROR;
}
