/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef ML_GRUB_ERR_H
#define ML_GRUB_ERR_H
#include <stdarg.h>
typedef int grub_err_t;
enum { GRUB_ERR_NONE, GRUB_ERR_BAD_FS, GRUB_ERR_OUT_OF_RANGE,
       GRUB_ERR_OUT_OF_MEMORY, GRUB_ERR_BAD_FILE_TYPE, GRUB_ERR_BAD_FILENAME,
       GRUB_ERR_FILE_NOT_FOUND, GRUB_ERR_SYMLINK_LOOP,
       GRUB_ERR_NOT_IMPLEMENTED_YET, GRUB_ERR_READ_ERROR,
       GRUB_ERR_BAD_COMPRESSED_DATA, GRUB_ERR_BUG, GRUB_ERR_BAD_DEVICE };
extern grub_err_t grub_errno;
grub_err_t grub_error(grub_err_t code, const char *format, ...);
void grub_print_error(void);
#endif
