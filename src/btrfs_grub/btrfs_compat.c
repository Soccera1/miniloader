/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <grub/disk.h>
#include <grub/diskfilter.h>
#include <grub/crypto.h>
#include <grub/err.h>
#include <grub/file.h>
#include <grub/misc.h>
#include <grub/mm.h>
#include "ml_btrfs.h"

struct registry_device {
    struct grub_device device;
    struct grub_disk disk;
};

static const ml_block_device *const *registry_devices;
static size_t registry_device_count;

void ml_btrfs_set_devices(const ml_block_device *const *devices, size_t count)
{
    registry_devices = devices;
    registry_device_count = count;
}

grub_device_t grub_device_open(const char *name)
{
    static const char prefix[] = "mlbtrfs";
    size_t i = 0, index = 0;
    struct registry_device *item;
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
    if (index >= registry_device_count || !registry_devices[index]) return NULL;
    item = grub_zalloc(sizeof(*item));
    if (!item) return NULL;
    item->disk.device = registry_devices[index];
    item->device.disk = &item->disk;
    return &item->device;
}

void grub_device_close(grub_device_t device)
{
    struct registry_device *item;
    if (!device) return;
    item = (struct registry_device *)((char *)device -
        __builtin_offsetof(struct registry_device, device));
    grub_free(item);
}

int grub_device_iterate(grub_device_iterate_hook_t hook, void *data)
{
    size_t i;
    if (!hook) return 0;
    for (i = 0; i < registry_device_count; ++i) {
        char name[sizeof("mlbtrfs") + 3 * sizeof(size_t) + 1];
        char digits[3 * sizeof(size_t) + 1];
        size_t n = 0, p = 0, value = i;
        static const char prefix[] = "mlbtrfs";
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

static grub_uint8_t raid_powx[255 * 2];
static unsigned raid_powx_inv[256];
static int raid_tables_ready;
static const grub_uint8_t raid_poly = 0x1d;

static void raid6_init_table(void)
{
    unsigned i;
    grub_uint8_t current = 1;
    if (raid_tables_ready) return;
    for (i = 0; i < 255; ++i) {
        raid_powx[i] = current;
        raid_powx[i + 255] = current;
        raid_powx_inv[current] = i;
        current = (current & 0x80) ? (grub_uint8_t)((current << 1) ^ raid_poly)
                                  : (grub_uint8_t)(current << 1);
    }
    raid_tables_ready = 1;
}

static void raid6_mulx(unsigned mul, char *buffer, grub_size_t size)
{
    grub_uint8_t *p = (grub_uint8_t *)buffer;
    grub_size_t i;
    for (i = 0; i < size; ++i, ++p)
        if (*p) *p = raid_powx[mul + raid_powx_inv[*p]];
}

static unsigned raid_mod_255(unsigned value)
{
    while (value > 0xff) value = (value >> 8) + (value & 0xff);
    return value == 0xff ? 0 : value;
}

grub_err_t grub_raid6_recover_gen(void *data, grub_uint64_t nstripes,
                                  int disknr, int p, char *buf,
                                  grub_uint64_t sector, grub_size_t size,
                                  int layout, raid_recover_read_t read_func)
{
    int i, q, pos, bad1 = -1, bad2 = -1;
    char *pbuf = NULL, *qbuf = NULL;
    raid6_init_table();
    grub_errno = GRUB_ERR_NONE;
    pbuf = grub_zalloc(size);
    if (!pbuf) goto done;
    qbuf = grub_zalloc(size);
    if (!qbuf) goto done;
    q = p + 1;
    if (q == (int)nstripes) q = 0;
    pos = q + 1;
    if (pos == (int)nstripes) pos = 0;
    for (i = 0; i < (int)nstripes - 2; ++i) {
        int coefficient = (layout & GRUB_RAID_LAYOUT_MUL_FROM_POS) ? pos : i;
        if (pos == disknr) bad1 = coefficient;
        else if (!read_func(data, pos, sector, buf, size)) {
            grub_crypto_xor(pbuf, pbuf, buf, size);
            raid6_mulx((unsigned)coefficient, buf, size);
            grub_crypto_xor(qbuf, qbuf, buf, size);
        } else {
            if (bad2 >= 0) goto done;
            bad2 = coefficient;
            grub_errno = GRUB_ERR_NONE;
        }
        if (++pos == (int)nstripes) pos = 0;
    }
    if (bad1 < 0) goto done;
    if (bad2 < 0) {
        if (!read_func(data, p, sector, buf, size)) {
            grub_crypto_xor(buf, buf, pbuf, size);
            goto done;
        }
        grub_errno = GRUB_ERR_NONE;
        if (read_func(data, q, sector, buf, size)) goto done;
        grub_crypto_xor(buf, buf, qbuf, size);
        raid6_mulx(255 - (unsigned)bad1, buf, size);
    } else {
        unsigned coefficient;
        if (read_func(data, p, sector, buf, size)) goto done;
        grub_crypto_xor(pbuf, pbuf, buf, size);
        if (read_func(data, q, sector, buf, size)) goto done;
        grub_crypto_xor(qbuf, qbuf, buf, size);
        coefficient = raid_mod_255((255u ^ (unsigned)bad1) +
            (255u ^ raid_powx_inv[raid_powx[(unsigned)bad2 +
                ((unsigned)bad1 ^ 255u)] ^ 1]));
        raid6_mulx(coefficient, qbuf, size);
        coefficient = raid_mod_255((unsigned)bad2 + coefficient);
        raid6_mulx(coefficient, pbuf, size);
        grub_crypto_xor(pbuf, pbuf, qbuf, size);
        grub_memcpy(buf, pbuf, size);
    }
    grub_errno = GRUB_ERR_NONE;
done:
    grub_free(pbuf);
    grub_free(qbuf);
    return grub_errno;
}
