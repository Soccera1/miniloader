/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef ML_GRUB_DISK_H
#define ML_GRUB_DISK_H
#include <grub/types.h>
#include <grub/err.h>
#include "ml_block.h"
#define GRUB_DISK_SECTOR_BITS 9
#define GRUB_DISK_SECTOR_SIZE (1u << GRUB_DISK_SECTOR_BITS)
#define GRUB_DISK_SIZE_UNKNOWN ((grub_disk_addr_t)-1)
typedef void (*grub_disk_read_hook_t)(grub_disk_addr_t sector,
                                      grub_size_t offset,
                                      grub_size_t length, void *data);
struct grub_disk {
  const ml_block_device *device;
  grub_disk_read_hook_t read_hook;
  void *read_hook_data;
};
typedef struct grub_disk *grub_disk_t;
static inline grub_disk_addr_t grub_disk_native_sectors(grub_disk_t disk)
{
  if (!disk || !disk->device || disk->device->byte_size == GRUB_DISK_SIZE_UNKNOWN)
    return GRUB_DISK_SIZE_UNKNOWN;
  return disk->device->byte_size >> GRUB_DISK_SECTOR_BITS;
}
grub_err_t grub_disk_read(grub_disk_t disk, grub_disk_addr_t sector,
                          grub_size_t offset, grub_size_t length, void *buffer);
#endif
