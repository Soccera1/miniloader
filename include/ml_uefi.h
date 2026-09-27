/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef ML_UEFI_H
#define ML_UEFI_H

#include <efi.h>
#include <efilib.h>
#include "ml_config.h"
#include "ml_block.h"
#include "ml_extfs.h"
#include "ml_lvm.h"
#include "ml_luks1.h"
#include "ml_luks2.h"
#include "ml_vfat.h"
#include "ml_xfs.h"
#include "ml_btrfs.h"
#include "ml_zfs.h"

#define ML_MAX_VOLUMES 512u
#define ML_MAX_BLOCK_DEVICES 256u
#define ML_MAX_STACK_DEVICES 512u
#define ML_MAX_LUKS_DEVICES 256u
#define ML_MAX_IMAGE_BYTES (1024ull * 1024ull * 1024ull)

typedef struct {
    EFI_HANDLE handle;
    EFI_BLOCK_IO_PROTOCOL *protocol;
    VOID *allocation;
    UINT8 *aligned_buffer;
    UINTN buffer_size;
    ml_block_device device;
} ml_uefi_block;

typedef enum {
    ML_VOLUME_UEFI_FS = 0,
    ML_VOLUME_EXT_FS = 1,
    ML_VOLUME_VFAT_FS = 2,
    ML_VOLUME_XFS_FS = 3,
    ML_VOLUME_BTRFS_FS = 4,
    ML_VOLUME_ZFS_FS = 5
} ml_uefi_volume_kind;

typedef struct {
    EFI_HANDLE handle;
    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *fs;
    EFI_FILE_HANDLE root;
    CHAR16 partition_guid[37];
    char filesystem_uuid[37];
    ml_uefi_volume_kind kind;
    ml_extfs extfs;
    ml_vfat vfat;
    ml_xfs xfs;
    ml_btrfs btrfs;
    ml_zfs zfs;
} ml_uefi_volume;

typedef struct {
    ml_uefi_volume *volumes;
    UINTN volume_count;
    UINTN unsupported_ext_count;
    UINTN unsupported_lvm_count;
    UINTN unsupported_vfat_count;
    UINTN unsupported_xfs_count;
    UINTN unsupported_btrfs_count;
    UINTN unsupported_zfs_count;
    ml_uefi_volume *config_volume;
    ml_uefi_block *block_devices;
    UINTN block_device_count;
#if ML_ENABLE_FS_BTRFS
    const ml_block_device **btrfs_devices;
    UINTN btrfs_device_count;
#endif
#if ML_ENABLE_FS_ZFS
    const ml_block_device **zfs_devices;
    UINTN zfs_device_count;
#endif
#if ML_ENABLE_LVM
    ml_lvm_vg *lvm_vgs;
    UINTN lvm_vg_count;
    VOID *lvm_scratch;
#endif
#if ML_ENABLE_LUKS1
    ml_luks1_volume *luks_volumes;
    UINTN luks_volume_count;
    VOID *luks_scratch;
#endif
#if ML_ENABLE_LUKS2
    ml_luks2_volume *luks2_volumes;
    UINTN luks2_volume_count;
    VOID *luks2_scratch;
#endif
#if ML_ENABLE_LUKS1 || ML_ENABLE_LUKS2
    UINTN unsupported_luks_count;
#endif
    VOID *extfs_scratch;
} ml_uefi_storage;

EFI_STATUS ml_storage_init(ml_uefi_storage *storage, EFI_HANDLE image_handle,
                           ml_config *config, ml_config_error *parse_error);
EFI_STATUS ml_storage_read(ml_uefi_volume *volume, const char *path,
                           VOID **buffer, UINTN *size);
ml_uefi_volume *ml_storage_find_volume(ml_uefi_storage *storage,
                                      const char *fs_uuid);
void ml_storage_close(ml_uefi_storage *storage);
EFI_STATUS ml_boot_menu(const ml_config *config, UINTN *selected);
EFI_STATUS ml_boot_entry(EFI_HANDLE image_handle, ml_uefi_volume *volume,
                         const ml_entry *entry);
void ml_console_ascii(const char *text);
EFI_STATUS ml_uefi_block_init(ml_uefi_block *block,
                              EFI_BLOCK_IO_PROTOCOL *protocol);
void ml_uefi_block_close(ml_uefi_block *block);

#endif
