/* MiniLoader adapter for the standalone, read-only GRUB ZFS reader. */
#include "ml_zfs.h"

struct ml_zfs_state {
  struct grub_disk disk;
  struct grub_device device;
};

struct ml_zfs_registry_device {
  struct grub_device device;
  struct grub_disk disk;
};

static const ml_block_device *const *ml_zfs_registry;
static size_t ml_zfs_registry_count;

void ml_zfs_set_devices(const ml_block_device *const *devices, size_t count)
{
  ml_zfs_registry = devices;
  ml_zfs_registry_count = count;
}

grub_device_t ml_zfs_device_open(const char *name)
{
  static const char prefix[] = "mlzfs";
  size_t i = 0, index = 0;
  struct ml_zfs_registry_device *item;
  if (!name) return NULL;
  while (prefix[i] && name[i] == prefix[i]) ++i;
  if (prefix[i] || !name[i]) return NULL;
  for (; name[i]; ++i) {
    unsigned digit;
    if (name[i] < '0' || name[i] > '9') return NULL;
    digit = (unsigned)(name[i] - '0');
    if (index > ((size_t)-1 - digit) / 10) return NULL;
    index = index * 10 + digit;
  }
  if (index >= ml_zfs_registry_count || !ml_zfs_registry[index]) return NULL;
  item = grub_zalloc(sizeof(*item));
  if (!item) return NULL;
  item->disk.device = ml_zfs_registry[index];
  item->device.disk = &item->disk;
  return &item->device;
}

void ml_zfs_device_close(grub_device_t device)
{
  struct ml_zfs_registry_device *item;
  if (!device) return;
  item = (struct ml_zfs_registry_device *)((char *)device -
      __builtin_offsetof(struct ml_zfs_registry_device, device));
  grub_free(item);
}

int ml_zfs_device_iterate(grub_device_iterate_hook_t hook, void *data)
{
  size_t i;
  if (!hook) return 0;
  for (i = 0; i < ml_zfs_registry_count; ++i) {
    char name[sizeof("mlzfs") + 3 * sizeof(size_t) + 1];
    char digits[3 * sizeof(size_t) + 1];
    size_t n = 0, p = 0, value = i;
    static const char prefix[] = "mlzfs";
    while (prefix[p]) { name[p] = prefix[p]; ++p; }
    do {
      digits[n++] = (char)('0' + value % 10);
      value /= 10;
    } while (value);
    while (n) name[p++] = digits[--n];
    name[p] = '\0';
    if (hook(name, data)) return 1;
  }
  return 0;
}

static ml_zfs_result ml_zfs_translate(grub_err_t error)
{
  if (error == GRUB_ERR_OUT_OF_RANGE) return ML_ZFS_RANGE;
  if (error == GRUB_ERR_OUT_OF_MEMORY) return ML_ZFS_IO;
  if (error == GRUB_ERR_FILE_NOT_FOUND) return ML_ZFS_NOT_FOUND;
  if (error == GRUB_ERR_BAD_FILE_TYPE) return ML_ZFS_NOT_FILE;
  if (error == GRUB_ERR_NOT_IMPLEMENTED_YET) return ML_ZFS_UNSUPPORTED;
  if (error == GRUB_ERR_BAD_FS) return ML_ZFS_BAD_FORMAT;
  return ML_ZFS_IO;
}

static int ml_zfs_has_label(const ml_block_device *device)
{
  grub_uint64_t magic;
  unsigned i;
  const grub_uint64_t label_size = sizeof(vdev_label_t);
  const grub_uint64_t magic_offset = VDEV_SKIP_SIZE + VDEV_BOOT_HEADER_SIZE +
      VDEV_PHYS_SIZE - sizeof(zio_eck_t);
  grub_uint64_t aligned_size;
  grub_uint64_t offsets[VDEV_LABELS];
  grub_uint64_t swapped;
  offsets[0] = magic_offset;
  offsets[1] = label_size + magic_offset;
  aligned_size = device->byte_size & ~(label_size - 1);
  if (aligned_size >= 2 * label_size) {
    offsets[2] = aligned_size - 2 * label_size + magic_offset;
    offsets[3] = aligned_size - label_size + magic_offset;
  } else {
    offsets[2] = offsets[3] = device->byte_size;
  }
  for (i = 0; i < VDEV_LABELS; ++i) {
    if (offsets[i] > device->byte_size ||
        device->byte_size - offsets[i] < sizeof(magic)) continue;
    if (ml_block_read(device, offsets[i], &magic, sizeof(magic)) != ML_BLOCK_OK)
      continue;
    swapped = __builtin_bswap64(magic);
    if (magic == ZEC_MAGIC || swapped == ZEC_MAGIC) return 1;
  }
  return 0;
}

static void ml_zfs_pool_uuid(grub_uint64_t guid, char output[37])
{
  static const char hex[] = "0123456789abcdef";
  int i;
  for (i = 15; i >= 0; --i) {
    output[i] = hex[guid & 0xf];
    guid >>= 4;
  }
  output[16] = '\0';
}

ml_zfs_result ml_zfs_mount(ml_zfs *filesystem,
                           const ml_block_device *device,
                           const char **error_message)
{
  struct ml_zfs_state *state;
  struct grub_zfs_data *data;
  if (error_message) *error_message = NULL;
  if (!filesystem || !device || !device->read_at) {
    if (error_message) *error_message = "invalid ZFS mount arguments";
    return ML_ZFS_INVALID;
  }
  if (!ml_zfs_has_label(device)) return ML_ZFS_NOT_FOUND;
  grub_errno = GRUB_ERR_NONE;
  grub_memset(filesystem, 0, sizeof(*filesystem));
  state = grub_zalloc(sizeof(*state));
  if (!state) {
    if (error_message) *error_message = "not enough memory for ZFS mount";
    return ML_ZFS_IO;
  }
  state->disk.device = device;
  state->device.disk = &state->disk;
  data = zfs_mount(&state->device);
  if (!data || grub_errno != GRUB_ERR_NONE) {
    grub_err_t error = grub_errno;
    if (data) zfs_unmount(data);
    grub_free(state);
    if (error_message)
      *error_message = error == GRUB_ERR_NOT_IMPLEMENTED_YET
        ? "ZFS pool uses an unsupported feature or vdev layout"
        : "ZFS pool metadata is malformed, unsupported, or unreadable";
    return ml_zfs_translate(error);
  }
  ml_zfs_pool_uuid(data->guid, filesystem->uuid);
  zfs_unmount(data);
  filesystem->device = device;
  filesystem->state = state;
  return ML_ZFS_OK;
}

ml_zfs_result ml_zfs_open(ml_zfs_file *file, const ml_zfs *filesystem,
                          const char *path, const char **error_message)
{
  struct ml_zfs_state *state;
  struct grub_file *handle;
  grub_err_t error;
  if (error_message) *error_message = NULL;
  if (!file || !filesystem || !filesystem->state || !path) {
    if (error_message) *error_message = "invalid ZFS open arguments";
    return ML_ZFS_INVALID;
  }
  grub_memset(file, 0, sizeof(*file));
  state = filesystem->state;
  handle = grub_zalloc(sizeof(*handle));
  if (!handle) {
    if (error_message) *error_message = "not enough memory for ZFS file handle";
    return ML_ZFS_IO;
  }
  handle->device = &state->device;
  grub_errno = GRUB_ERR_NONE;
  if (grub_zfs_open(handle, path) != GRUB_ERR_NONE) {
    error = grub_errno;
    grub_free(handle);
    if (error_message)
      *error_message = error == GRUB_ERR_FILE_NOT_FOUND
        ? "file was not found on ZFS volume"
        : error == GRUB_ERR_BAD_FILE_TYPE
          ? "ZFS path does not name a regular file"
          : "ZFS path is invalid, unsupported, or unreadable";
    return ml_zfs_translate(error);
  }
  file->filesystem = filesystem;
  file->handle = handle;
  file->size = (uint64_t)handle->size;
  return ML_ZFS_OK;
}

ml_zfs_result ml_zfs_read(const ml_zfs_file *file, uint64_t offset,
                          void *buffer, size_t length, size_t *bytes_read,
                          const char **error_message)
{
  struct grub_file *handle;
  grub_ssize_t result;
  if (error_message) *error_message = NULL;
  if (bytes_read) *bytes_read = 0;
  if (!file || !file->filesystem || !file->filesystem->state || !file->handle ||
      (!buffer && length) || !bytes_read)
    return ML_ZFS_INVALID;
  if (offset > file->size) return ML_ZFS_RANGE;
  if (length > file->size - offset) length = (size_t)(file->size - offset);
  if (offset > (uint64_t)INT64_MAX || length > (size_t)INT64_MAX ||
      offset > (uint64_t)INT64_MAX - length)
    return ML_ZFS_RANGE;
  handle = file->handle;
  handle->offset = (grub_off_t)offset;
  grub_errno = GRUB_ERR_NONE;
  result = grub_zfs_read(handle, (char *)buffer, (grub_size_t)length);
  if (result < 0 || grub_errno != GRUB_ERR_NONE) {
    if (error_message) *error_message = "ZFS file read failed";
    return ml_zfs_translate(grub_errno);
  }
  *bytes_read = (size_t)result;
  return ML_ZFS_OK;
}

void ml_zfs_close_file(ml_zfs_file *file)
{
  struct grub_file *handle;
  if (!file || !file->handle) return;
  handle = file->handle;
  (void)grub_zfs_close(handle);
  grub_free(handle);
  grub_memset(file, 0, sizeof(*file));
}

void ml_zfs_unmount(ml_zfs *filesystem)
{
  if (!filesystem || !filesystem->state) return;
  grub_free(filesystem->state);
  grub_memset(filesystem, 0, sizeof(*filesystem));
}
