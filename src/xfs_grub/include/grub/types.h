/* MiniLoader compatibility types for the upstream read-only GRUB XFS driver.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
#ifndef ML_GRUB_TYPES_H
#define ML_GRUB_TYPES_H
#include <stddef.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>
typedef uint8_t grub_uint8_t;
typedef uint16_t grub_uint16_t;
typedef uint32_t grub_uint32_t;
typedef uint64_t grub_uint64_t;
typedef int64_t grub_int64_t;
typedef size_t grub_size_t;
typedef intptr_t grub_addr_t;
typedef uint64_t grub_disk_addr_t;
typedef int64_t grub_off_t;
typedef long grub_ssize_t;
#define GRUB_PACKED __attribute__((packed))
#define GRUB_INT32_MIN INT32_MIN
#define PRIuGRUB_UINT64_T PRIu64
#define PRIxGRUB_UINT64_T PRIx64
#define PRIuGRUB_UINT32_T PRIu32
#define PRIxGRUB_UINT32_T PRIx32
#define PRIuGRUB_SIZE "zu"
#define PRIxGRUB_SIZE "zx"
#define PRIdGRUB_SSIZE "zd"
#define GRUB_CPU_SIZEOF_VOID_P 8
typedef union { uint64_t u64; void *ptr; } grub_properly_aligned_t;
#define grub_cpu_to_be16_compile_time(x) ((grub_uint16_t)((((x) & 0xffu) << 8) | (((x) >> 8) & 0xffu)))
#define grub_cpu_to_be32_compile_time(x) __builtin_bswap32((grub_uint32_t)(x))
#define grub_cpu_to_be64_compile_time(x) __builtin_bswap64((grub_uint64_t)(x))
static inline grub_uint16_t grub_cpu_to_be16(grub_uint16_t x) { return grub_cpu_to_be16_compile_time(x); }
static inline grub_uint32_t grub_cpu_to_be32(grub_uint32_t x) { return __builtin_bswap32(x); }
static inline grub_uint64_t grub_cpu_to_be64(grub_uint64_t x) { return __builtin_bswap64(x); }
#define grub_be_to_cpu16(x) grub_cpu_to_be16_compile_time(x)
#define grub_be_to_cpu32(x) grub_cpu_to_be32_compile_time(x)
#define grub_be_to_cpu64(x) grub_cpu_to_be64_compile_time(x)
#define grub_cpu_to_le16(x) ((grub_uint16_t)(x))
#define grub_cpu_to_le32(x) ((grub_uint32_t)(x))
#define grub_cpu_to_le64(x) ((grub_uint64_t)(x))
#define grub_cpu_to_le64_compile_time(x) ((grub_uint64_t)(x))
#define grub_le_to_cpu16(x) ((grub_uint16_t)(x))
#define grub_le_to_cpu32(x) ((grub_uint32_t)(x))
#define grub_le_to_cpu64(x) ((grub_uint64_t)(x))
static inline grub_uint16_t grub_get_unaligned16(const void *p) {
  const grub_uint8_t *b = p; return (grub_uint16_t)b[0] | ((grub_uint16_t)b[1] << 8);
}
static inline grub_uint64_t grub_get_unaligned64(const void *p) {
  const grub_uint8_t *b = p; grub_uint64_t v = 0; unsigned i;
  for (i = 0; i < 8; ++i) v |= (grub_uint64_t)b[i] << (i * 8);
  return v;
}
static inline grub_uint32_t grub_get_unaligned32(const void *p) {
  const grub_uint8_t *b = p; return (grub_uint32_t)b[0] |
    ((grub_uint32_t)b[1] << 8) | ((grub_uint32_t)b[2] << 16) |
    ((grub_uint32_t)b[3] << 24);
}
#define ALIGN_UP(v, a) (((v) + ((a) - 1)) & ~((a) - 1))
#define ALIGN_DOWN(v, a) ((v) & ~((a) - 1))
#define grub_toupper(c) (((unsigned char)(c) >= 'a' && (unsigned char)(c) <= 'z') ? ((unsigned char)(c) - ('a' - 'A')) : (unsigned char)(c))
#endif
