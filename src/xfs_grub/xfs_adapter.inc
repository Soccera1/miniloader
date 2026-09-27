/* MiniLoader adapter. The code above is the read-only XFS filesystem reader
 * ported from GRUB 2.14; GRUB device/module registration was omitted.
 */
#include "ml_xfs.h"

struct ml_xfs_state {
  struct grub_disk disk;
  struct grub_xfs_data *data;
};

static ml_xfs_result ml_xfs_translate_error(grub_err_t error)
{
  if (error == GRUB_ERR_OUT_OF_RANGE) return ML_XFS_RANGE;
  if (error == GRUB_ERR_OUT_OF_MEMORY) return ML_XFS_IO;
  if (error == GRUB_ERR_FILE_NOT_FOUND) return ML_XFS_NOT_FOUND;
  if (error == GRUB_ERR_BAD_FILE_TYPE) return ML_XFS_NOT_FILE;
  if (error == GRUB_ERR_NOT_IMPLEMENTED_YET) return ML_XFS_UNSUPPORTED;
  if (error == GRUB_ERR_BAD_FS) return ML_XFS_BAD_FORMAT;
  return ML_XFS_IO;
}

static void ml_xfs_format_uuid(const struct grub_xfs_sblock *sblock,
                               char output[37])
{
  static const char hex[] = "0123456789abcdef";
  const grub_uint8_t *bytes = (const grub_uint8_t *)sblock->uuid;
  grub_size_t out = 0, i;
  for (i = 0; i < 16; ++i) {
    if (i == 4 || i == 6 || i == 8 || i == 10) output[out++] = '-';
    output[out++] = hex[bytes[i] >> 4];
    output[out++] = hex[bytes[i] & 15];
  }
  output[out] = '\0';
}

ml_xfs_result ml_xfs_mount(ml_xfs *filesystem,
                           const ml_block_device *device,
                           const char **error_message)
{
  struct ml_xfs_state *state;
  grub_uint8_t magic[4];
  if (error_message) *error_message = NULL;
  if (!filesystem || !device || !device->read_at) {
    if (error_message) *error_message = "invalid XFS mount arguments";
    return ML_XFS_INVALID;
  }
  if (ml_block_read(device, 0, magic, sizeof(magic)) != ML_BLOCK_OK) {
    if (error_message) *error_message = "could not read XFS probe sector";
    return ML_XFS_IO;
  }
  if (magic[0] != 'X' || magic[1] != 'F' || magic[2] != 'S' || magic[3] != 'B')
    return ML_XFS_NOT_FOUND;
  grub_errno = GRUB_ERR_NONE;
  grub_memset(filesystem, 0, sizeof(*filesystem));
  state = grub_zalloc(sizeof(*state));
  if (!state) {
    if (error_message) *error_message = "not enough memory for XFS mount";
    return ML_XFS_IO;
  }
  state->disk.device = device;
  state->data = grub_xfs_mount(&state->disk);
  if (!state->data || grub_errno != GRUB_ERR_NONE) {
    grub_err_t error = grub_errno;
    if (state->data) grub_free(state->data);
    grub_free(state);
    if (error_message)
      *error_message = "XFS metadata is malformed, unsupported, or unreadable";
    return error == GRUB_ERR_BAD_FS ? ML_XFS_UNSUPPORTED :
           ml_xfs_translate_error(error);
  }
  filesystem->device = device;
  filesystem->state = state;
  filesystem->block_size = (uint32_t)state->data->bsize;
  ml_xfs_format_uuid(&state->data->sblock, filesystem->uuid);
  return ML_XFS_OK;
}

ml_xfs_result ml_xfs_open(ml_xfs_file *file, const ml_xfs *filesystem,
                          const char *path, const char **error_message)
{
  struct ml_xfs_state *state;
  struct grub_fshelp_node *node = NULL, *copy;
  grub_size_t node_size;
  grub_err_t error;
  if (error_message) *error_message = NULL;
  if (!file || !filesystem || !filesystem->state || !path) {
    if (error_message) *error_message = "invalid XFS open arguments";
    return ML_XFS_INVALID;
  }
  grub_memset(file, 0, sizeof(*file));
  state = (struct ml_xfs_state *)filesystem->state;
  grub_errno = GRUB_ERR_NONE;
  if (grub_fshelp_find_file(path, &state->data->diropen, &node,
                            grub_xfs_iterate_dir, grub_xfs_read_symlink,
                            GRUB_FSHELP_REG) != GRUB_ERR_NONE) {
    error = grub_errno;
    if (error_message)
      *error_message = error == GRUB_ERR_FILE_NOT_FOUND
        ? "file was not found on XFS volume"
        : "XFS path is invalid or does not name a regular file";
    return ml_xfs_translate_error(error);
  }
  node_size = grub_xfs_fshelp_size(state->data);
  copy = grub_malloc(node_size);
  if (!copy) {
    if (node != &state->data->diropen) grub_free(node);
    if (error_message) *error_message = "not enough memory for XFS file handle";
    return ML_XFS_IO;
  }
  grub_memcpy(copy, node, node_size);
  if (node != &state->data->diropen) grub_free(node);
  file->filesystem = filesystem;
  file->node = copy;
  file->size = grub_be_to_cpu64(copy->inode.size);
  return ML_XFS_OK;
}

ml_xfs_result ml_xfs_read(const ml_xfs_file *file, uint64_t offset,
                          void *buffer, size_t length, size_t *bytes_read,
                          const char **error_message)
{
  grub_ssize_t result;
  if (error_message) *error_message = NULL;
  if (bytes_read) *bytes_read = 0;
  if (!file || !file->filesystem || !file->filesystem->state ||
      !file->node || (!buffer && length) || !bytes_read)
    return ML_XFS_INVALID;
  if (offset > (uint64_t)INT64_MAX || length > (size_t)INT64_MAX ||
      offset > (uint64_t)INT64_MAX - length) return ML_XFS_RANGE;
  grub_errno = GRUB_ERR_NONE;
  result = grub_xfs_read_file((struct grub_fshelp_node *)file->node,
                              NULL, NULL, (grub_off_t)offset,
                              (grub_size_t)length, (char *)buffer, 0);
  if (result < 0 || grub_errno != GRUB_ERR_NONE) {
    if (error_message) *error_message = "XFS file read failed";
    return ml_xfs_translate_error(grub_errno);
  }
  *bytes_read = (size_t)result;
  return ML_XFS_OK;
}

void ml_xfs_close_file(ml_xfs_file *file)
{
  if (!file) return;
  grub_free(file->node);
  grub_memset(file, 0, sizeof(*file));
}

void ml_xfs_unmount(ml_xfs *filesystem)
{
  struct ml_xfs_state *state;
  if (!filesystem || !filesystem->state) return;
  state = (struct ml_xfs_state *)filesystem->state;
  grub_free(state->data);
  grub_free(state);
  grub_memset(filesystem, 0, sizeof(*filesystem));
}
