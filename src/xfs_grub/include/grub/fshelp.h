/* MiniLoader's small adapter for GRUB's filesystem helper API.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
#ifndef ML_GRUB_FSHELP_H
#define ML_GRUB_FSHELP_H
#include <grub/disk.h>
typedef struct grub_fshelp_node *grub_fshelp_node_t;
#define GRUB_FSHELP_TYPE_MASK 0xff
#define GRUB_FSHELP_CASE_INSENSITIVE 0x100
enum grub_fshelp_filetype { GRUB_FSHELP_UNKNOWN, GRUB_FSHELP_REG,
                            GRUB_FSHELP_DIR, GRUB_FSHELP_SYMLINK };
typedef int (*grub_fshelp_iterate_dir_hook_t)(const char *,
    enum grub_fshelp_filetype, grub_fshelp_node_t, void *);
grub_err_t grub_fshelp_find_file(const char *, grub_fshelp_node_t,
    grub_fshelp_node_t *, int (*)(grub_fshelp_node_t,
    grub_fshelp_iterate_dir_hook_t, void *), char *(*)(grub_fshelp_node_t),
    enum grub_fshelp_filetype);
grub_ssize_t grub_fshelp_read_file(grub_disk_t, grub_fshelp_node_t,
    grub_disk_read_hook_t, void *, grub_off_t, grub_size_t, char *,
    grub_disk_addr_t (*)(grub_fshelp_node_t, grub_disk_addr_t),
    grub_off_t, int, grub_disk_addr_t);
#endif
