/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef ML_ZFS_GRUB_SAFEMATH_H
#define ML_ZFS_GRUB_SAFEMATH_H
#include <stdbool.h>
#define grub_add(a, b, res) __builtin_add_overflow((a), (b), (res))
#define grub_mul(a, b, res) __builtin_mul_overflow((a), (b), (res))
#endif
