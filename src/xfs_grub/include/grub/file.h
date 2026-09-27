/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef ML_GRUB_FILE_H
#define ML_GRUB_FILE_H
#include <grub/disk.h>
struct grub_device { grub_disk_t disk; };
typedef struct grub_device *grub_device_t;
struct grub_file {
  grub_device_t device;
  grub_off_t offset;
  grub_off_t size;
  void *data;
  grub_disk_read_hook_t read_hook;
  void *read_hook_data;
};
typedef struct grub_file *grub_file_t;
grub_device_t grub_device_open(const char *name);
void grub_device_close(grub_device_t device);
typedef int (*grub_device_iterate_hook_t)(const char *name, void *data);
int grub_device_iterate(grub_device_iterate_hook_t hook, void *data);
#endif
