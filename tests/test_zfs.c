/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _POSIX_C_SOURCE 200809L
#include "ml_zfs.h"
#include <grub/types.h>
#include <grub/zfs/zio.h>
#include <grub/zfs/vdev_impl.h>

#include <assert.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

typedef struct {
  uint8_t *bytes;
  size_t size;
} test_disk;

typedef struct {
  int descriptor;
  uint64_t size;
} fixture_disk;

static int read_at(void *context, uint64_t offset, void *buffer, size_t length)
{
  test_disk *disk = context;
  if (!disk || offset > disk->size || length > disk->size - (size_t)offset)
    return ML_BLOCK_RANGE;
  memcpy(buffer, disk->bytes + (size_t)offset, length);
  return ML_BLOCK_OK;
}

static int fixture_read_at(void *context, uint64_t offset,
                           void *buffer, size_t length)
{
  fixture_disk *disk = context;
  ssize_t amount;
  if (!disk || offset > disk->size || length > disk->size - offset ||
      offset > (uint64_t)INT64_MAX || length > (size_t)INT64_MAX)
    return ML_BLOCK_RANGE;
  amount = pread(disk->descriptor, buffer, length, (off_t)offset);
  return amount == (ssize_t)length ? ML_BLOCK_OK : ML_BLOCK_IO;
}

static uint64_t label_magic_offset(const test_disk *disk, unsigned label)
{
  const uint64_t label_size = sizeof(vdev_label_t);
  const uint64_t magic_in_label = VDEV_SKIP_SIZE + VDEV_BOOT_HEADER_SIZE
      + VDEV_PHYS_SIZE - sizeof(zio_eck_t);
  uint64_t aligned_size = disk->size & ~(label_size - 1);
  if (label < 2) return (uint64_t)label * label_size + magic_in_label;
  return aligned_size - (4 - label) * label_size + magic_in_label;
}

static void test_missing_label(void)
{
  test_disk backing;
  ml_block_device device;
  ml_zfs filesystem;
  const char *message = NULL;

  backing.size = 4u * 1024u * 1024u;
  backing.bytes = calloc(1, backing.size);
  assert(backing.bytes);
  device.context = &backing;
  device.byte_size = backing.size;
  device.logical_block_size = 512;
  device.read_at = read_at;

  assert(ml_zfs_mount(&filesystem, &device, &message) == ML_ZFS_NOT_FOUND);
  assert(message == NULL);
  free(backing.bytes);
}

static void test_all_label_positions(void)
{
  test_disk backing;
  ml_block_device device;
  unsigned label;

  backing.size = 4u * 1024u * 1024u;
  backing.bytes = calloc(1, backing.size);
  assert(backing.bytes);
  device.context = &backing;
  device.byte_size = backing.size;
  device.logical_block_size = 512;
  device.read_at = read_at;

  for (label = 0; label < 4; ++label) {
    ml_zfs filesystem;
    const char *message = NULL;
    uint64_t magic = ZEC_MAGIC;
    uint64_t offset = label_magic_offset(&backing, label);
    memcpy(backing.bytes + offset, &magic, sizeof(magic));

    /* A label signature at each standard location must reach metadata
       validation rather than being mistaken for an absent pool. */
    assert(ml_zfs_mount(&filesystem, &device, &message) != ML_ZFS_NOT_FOUND);
    assert(message != NULL);
    memset(backing.bytes + offset, 0, sizeof(magic));
  }
  free(backing.bytes);
}

static void test_reference_pool(char **paths)
{
  fixture_disk disks[4];
  ml_block_device block_devices[4];
  const ml_block_device *device_list[4];
  ml_zfs filesystem;
  ml_zfs_file file;
  uint8_t contents[4096];
  size_t bytes_read = 0, i;
  const char *message = NULL;

  memset(disks, 0, sizeof(disks));
  for (i = 0; i < 4; ++i) {
    struct stat info;
    disks[i].descriptor = open(paths[i], O_RDONLY);
    assert(disks[i].descriptor >= 0);
    assert(fstat(disks[i].descriptor, &info) == 0 && info.st_size > 0);
    disks[i].size = (uint64_t)info.st_size;
    block_devices[i].context = &disks[i];
    block_devices[i].byte_size = disks[i].size;
    block_devices[i].logical_block_size = 512;
    block_devices[i].read_at = fixture_read_at;
    device_list[i] = &block_devices[i];
  }

  ml_zfs_set_devices(device_list, 4);
  assert(ml_zfs_mount(&filesystem, &block_devices[0], &message) == ML_ZFS_OK);
  assert(strlen(filesystem.uuid) == 16);
  assert(ml_zfs_open(&file, &filesystem, "fs@/L3F1", &message) == ML_ZFS_OK);
  assert(file.size == sizeof(contents));
  assert(ml_zfs_read(&file, 0, contents, sizeof(contents), &bytes_read,
                     &message) == ML_ZFS_OK);
  assert(bytes_read == sizeof(contents));
  for (i = 0; i < sizeof(contents); ++i) assert(contents[i] == 0);
  ml_zfs_close_file(&file);
  ml_zfs_unmount(&filesystem);
  ml_zfs_set_devices(NULL, 0);
  for (i = 0; i < 4; ++i) close(disks[i].descriptor);
}

int main(int argc, char **argv)
{
  test_missing_label();
  test_all_label_positions();
  if (argc == 5) {
    test_reference_pool(argv + 1);
    puts("ZFS absent/malformed-label and positive RAID-Z file-read checks passed");
  } else {
    assert(argc == 1);
    puts("ZFS absent and malformed label checks passed");
  }
  return 0;
}
