/* MiniLoader adapter for the read-only Btrfs reader. */
#include "ml_btrfs.h"

struct ml_btrfs_state {
  struct grub_disk disk;
  struct grub_device device;
};

static ml_btrfs_result ml_btrfs_translate(grub_err_t error)
{
  if (error == GRUB_ERR_OUT_OF_RANGE) return ML_BTRFS_RANGE;
  if (error == GRUB_ERR_FILE_NOT_FOUND) return ML_BTRFS_NOT_FOUND;
  if (error == GRUB_ERR_BAD_FILE_TYPE) return ML_BTRFS_NOT_FILE;
  if (error == GRUB_ERR_NOT_IMPLEMENTED_YET) return ML_BTRFS_UNSUPPORTED;
  if (error == GRUB_ERR_BAD_FS) return ML_BTRFS_BAD_FORMAT;
  return ML_BTRFS_IO;
}

static void ml_btrfs_format_uuid(const struct grub_btrfs_superblock *sblock,
                                 char output[37])
{
  static const char hex[] = "0123456789abcdef";
  grub_size_t out = 0;
  unsigned i;
  for (i = 0; i < 8; ++i) {
    grub_uint16_t value = grub_be_to_cpu16(sblock->uuid[i]);
    if (i == 2 || i == 3 || i == 4 || i == 5) output[out++] = '-';
    output[out++] = hex[value >> 12];
    output[out++] = hex[(value >> 8) & 15];
    output[out++] = hex[(value >> 4) & 15];
    output[out++] = hex[value & 15];
  }
  output[out] = '\0';
}

ml_btrfs_result ml_btrfs_mount(ml_btrfs *filesystem,
                               const ml_block_device *device,
                               const char **error_message)
{
  static const grub_uint8_t signature[] = "_BHRfS_M";
  grub_uint8_t found[sizeof(signature) - 1];
  grub_uint8_t superblock[4096];
  grub_uint32_t checksum;
  grub_uint16_t checksum_type;
  struct ml_btrfs_state *state;
  struct grub_btrfs_data *data;
  if (error_message) *error_message = NULL;
  if (!filesystem || !device || !device->read_at) {
    if (error_message) *error_message = "invalid Btrfs mount arguments";
    return ML_BTRFS_INVALID;
  }
  {
    int probe = ml_block_read(device, 0x10040, found, sizeof(found));
    if (probe != ML_BLOCK_OK)
      return probe == ML_BLOCK_RANGE || probe == ML_BLOCK_NOT_FOUND
        ? ML_BTRFS_NOT_FOUND : ML_BTRFS_IO;
  }
  if (grub_memcmp(found, signature, sizeof(found)) != 0)
    return ML_BTRFS_NOT_FOUND;
  if (ml_block_read(device, 0x10000, superblock, sizeof(superblock)) !=
      ML_BLOCK_OK) {
    if (error_message) *error_message = "could not read the Btrfs superblock";
    return ML_BTRFS_IO;
  }
  checksum_type = grub_get_unaligned16(superblock + 0xc4);
  if (checksum_type != 0) {
    if (error_message)
      *error_message = "Btrfs checksum type is unsupported; CRC32C is required";
    return ML_BTRFS_UNSUPPORTED;
  }
  checksum = grub_le_to_cpu32(grub_get_unaligned32(superblock));
  if (checksum != grub_getcrc32c(0, superblock + 0x20, 4096 - 0x20)) {
    if (error_message) *error_message = "Btrfs superblock checksum is invalid";
    return ML_BTRFS_BAD_FORMAT;
  }

  grub_errno = GRUB_ERR_NONE;
  grub_memset(filesystem, 0, sizeof(*filesystem));
  state = grub_zalloc(sizeof(*state));
  if (!state) {
    if (error_message) *error_message = "not enough memory for Btrfs mount";
    return ML_BTRFS_IO;
  }
  state->disk.device = device;
  state->device.disk = &state->disk;
  data = grub_btrfs_mount(&state->device);
  if (!data || grub_errno != GRUB_ERR_NONE) {
    grub_err_t error = grub_errno;
    if (data) grub_btrfs_unmount(data);
    grub_free(state);
    if (error_message)
      *error_message = "Btrfs metadata is malformed, unsupported, or unreadable";
    return ml_btrfs_translate(error);
  }
  if (grub_le_to_cpu64(data->sblock.this_device.size) > device->byte_size) {
    grub_btrfs_unmount(data);
    grub_free(state);
    if (error_message)
      *error_message = "Btrfs superblock device size exceeds the read-only block device";
    return ML_BTRFS_BAD_FORMAT;
  }
  if (grub_le_to_cpu64(data->sblock.this_device.size) < 0x11000) {
    grub_btrfs_unmount(data);
    grub_free(state);
    if (error_message)
      *error_message = "Btrfs superblock device size is smaller than its superblock";
    return ML_BTRFS_BAD_FORMAT;
  }
  if (!grub_le_to_cpu64(data->sblock.root_tree) ||
      !grub_le_to_cpu64(data->sblock.chunk_tree)) {
    grub_btrfs_unmount(data);
    grub_free(state);
    if (error_message)
      *error_message = "Btrfs superblock has invalid tree root addresses";
    return ML_BTRFS_BAD_FORMAT;
  }
  ml_btrfs_format_uuid(&data->sblock, filesystem->uuid);
  grub_btrfs_unmount(data);
  filesystem->device = device;
  filesystem->state = state;
  return ML_BTRFS_OK;
}

ml_btrfs_result ml_btrfs_open(ml_btrfs_file *file,
                              const ml_btrfs *filesystem,
                              const char *path,
                              const char **error_message)
{
  struct ml_btrfs_state *state;
  struct grub_file *handle;
  grub_err_t error;
  if (error_message) *error_message = NULL;
  if (!file || !filesystem || !filesystem->state || !path) {
    if (error_message) *error_message = "invalid Btrfs open arguments";
    return ML_BTRFS_INVALID;
  }
  grub_memset(file, 0, sizeof(*file));
  state = filesystem->state;
  handle = grub_zalloc(sizeof(*handle));
  if (!handle) {
    if (error_message) *error_message = "not enough memory for Btrfs file handle";
    return ML_BTRFS_IO;
  }
  handle->device = &state->device;
  grub_errno = GRUB_ERR_NONE;
  if (grub_btrfs_open(handle, path) != GRUB_ERR_NONE) {
    error = grub_errno;
    grub_free(handle);
    if (error_message)
      *error_message = error == GRUB_ERR_FILE_NOT_FOUND
        ? "file was not found on Btrfs volume"
        : "Btrfs path is invalid, unsupported, or unreadable";
    return ml_btrfs_translate(error);
  }
  file->filesystem = filesystem;
  file->handle = handle;
  file->size = (uint64_t)handle->size;
  return ML_BTRFS_OK;
}

ml_btrfs_result ml_btrfs_read(const ml_btrfs_file *file, uint64_t offset,
                              void *buffer, size_t length,
                              size_t *bytes_read,
                              const char **error_message)
{
  struct grub_file *handle;
  grub_ssize_t result;
  if (error_message) *error_message = NULL;
  if (bytes_read) *bytes_read = 0;
  if (!file || !file->filesystem || !file->filesystem->state || !file->handle ||
      (!buffer && length) || !bytes_read)
    return ML_BTRFS_INVALID;
  if (offset > (uint64_t)INT64_MAX || length > (size_t)INT64_MAX ||
      offset > (uint64_t)INT64_MAX - length)
    return ML_BTRFS_RANGE;
  handle = file->handle;
  handle->offset = (grub_off_t)offset;
  grub_errno = GRUB_ERR_NONE;
  result = grub_btrfs_read(handle, (char *)buffer, (grub_size_t)length);
  if (result < 0 || grub_errno != GRUB_ERR_NONE) {
    if (error_message) *error_message = "Btrfs file read failed";
    return ml_btrfs_translate(grub_errno);
  }
  *bytes_read = (size_t)result;
  return ML_BTRFS_OK;
}

void ml_btrfs_close_file(ml_btrfs_file *file)
{
  struct grub_file *handle;
  if (!file || !file->handle) return;
  handle = file->handle;
  (void)grub_btrfs_close(handle);
  grub_free(handle);
  grub_memset(file, 0, sizeof(*file));
}

void ml_btrfs_unmount(ml_btrfs *filesystem)
{
  if (!filesystem || !filesystem->state) return;
  grub_free(filesystem->state);
  grub_memset(filesystem, 0, sizeof(*filesystem));
}
