/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef ML_GRUB_SAFEMATH_H
#define ML_GRUB_SAFEMATH_H
#define grub_add(a, b, out) __builtin_add_overflow((a), (b), (out))
#define grub_mul(a, b, out) __builtin_mul_overflow((a), (b), (out))
#define grub_sub(a, b, out) __builtin_sub_overflow((a), (b), (out))
#endif
