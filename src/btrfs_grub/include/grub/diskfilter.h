/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef ML_GRUB_DISKFILTER_H
#define ML_GRUB_DISKFILTER_H
#include <grub/types.h>
#include <grub/err.h>
typedef grub_err_t (*raid_recover_read_t)(void *, int, grub_uint64_t,
                                          void *, grub_size_t);
grub_err_t grub_raid6_recover_gen(void *data, grub_uint64_t nstripes,
                                  int disknr, int p, char *buf,
                                  grub_uint64_t sector, grub_size_t size,
                                  int layout, raid_recover_read_t read_func);
#define GRUB_RAID_LAYOUT_MUL_FROM_POS 4
#endif
