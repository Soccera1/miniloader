/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef ML_GRUB_DL_H
#define ML_GRUB_DL_H
typedef void *grub_dl_t;
#define GRUB_MOD_LICENSE(x)
#define GRUB_MOD_INIT(x) static void grub_mod_init_##x(void)
#define GRUB_MOD_FINI(x) static void grub_mod_fini_##x(void)
#define GRUB_MOD_LICENSE(x)
static inline void grub_dl_ref(grub_dl_t module) { (void)module; }
static inline void grub_dl_unref(grub_dl_t module) { (void)module; }
#endif
