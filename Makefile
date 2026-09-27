# SPDX-License-Identifier: GPL-3.0-or-later
ARCH            ?= x86_64
EFI_CC          ?= x86_64-w64-mingw32-gcc
EFI_INCLUDEDIR  ?= /usr/include/efi
BUILD_DIR       ?= build

ENABLE_FS_EXT2       ?= 0
ENABLE_FS_EXT4       ?= 0
ENABLE_FS_XFS        ?= 0
ENABLE_FS_BTRFS      ?= 0
ENABLE_FS_ZFS        ?= 0
ENABLE_FS_VFAT       ?= 0
ENABLE_LVM           ?= 0
ENABLE_LUKS1         ?= 0
ENABLE_LUKS2         ?= 0
ENABLE_KDF_PBKDF2    ?= 0
ENABLE_KDF_ARGON2ID  ?= 0
ENABLE_TPM12         ?= 0
ENABLE_TPM2          ?= 0
ENABLE_CIPHER_AES_XTS ?= 0
ENABLE_CIPHER_AES_CBC_ESSIV ?= 0
ENABLE_CIPHER_SERPENT_XTS ?= 0
ENABLE_CIPHER_TWOFISH_XTS ?= 0

ifeq ($(ENABLE_LUKS1),1)
ifneq ($(ENABLE_KDF_PBKDF2),1)
$(error ENABLE_LUKS1 requires ENABLE_KDF_PBKDF2=1)
endif
ifeq ($(filter 1,$(ENABLE_CIPHER_AES_XTS) $(ENABLE_CIPHER_AES_CBC_ESSIV) $(ENABLE_CIPHER_SERPENT_XTS) $(ENABLE_CIPHER_TWOFISH_XTS)),)
$(error ENABLE_LUKS1 requires at least one supported cipher profile)
endif
endif

ifeq ($(ENABLE_LUKS2),1)
ifeq ($(filter 1,$(ENABLE_KDF_PBKDF2) $(ENABLE_KDF_ARGON2ID)),)
$(error ENABLE_LUKS2 requires ENABLE_KDF_PBKDF2=1 or ENABLE_KDF_ARGON2ID=1)
endif
ifeq ($(filter 1,$(ENABLE_CIPHER_AES_XTS) $(ENABLE_CIPHER_AES_CBC_ESSIV) $(ENABLE_CIPHER_SERPENT_XTS) $(ENABLE_CIPHER_TWOFISH_XTS)),)
$(error ENABLE_LUKS2 requires at least one supported cipher profile)
endif
endif

ifeq ($(ENABLE_KDF_ARGON2ID),1)
ifneq ($(ENABLE_LUKS2),1)
$(error ENABLE_KDF_ARGON2ID requires ENABLE_LUKS2=1)
endif
endif

# Do not silently produce an image that advertises storage or crypto support
# without linking the corresponding driver.


ifeq ($(ENABLE_TPM12),1)
ifneq ($(ENABLE_LUKS1),1)
$(error ENABLE_TPM12 requires ENABLE_LUKS1=1)
endif
endif
ifeq ($(ENABLE_TPM2),1)
ifneq ($(ENABLE_LUKS2),1)
$(error ENABLE_TPM2 requires ENABLE_LUKS2=1)
endif
endif

EFI_CFLAGS := -I$(EFI_INCLUDEDIR) -I$(EFI_INCLUDEDIR)/$(ARCH) \
	-DGNU_EFI_USE_MS_ABI -std=gnu11 -O2 -Wall -Wextra -Werror -Wno-pointer-sign \
	-DML_ENABLE_FS_EXT2=$(ENABLE_FS_EXT2) -DML_ENABLE_FS_EXT4=$(ENABLE_FS_EXT4) \
	-DML_ENABLE_FS_VFAT=$(ENABLE_FS_VFAT) \
	-DML_ENABLE_FS_XFS=$(ENABLE_FS_XFS) \
	-DML_ENABLE_FS_BTRFS=$(ENABLE_FS_BTRFS) \
	-DML_ENABLE_FS_ZFS=$(ENABLE_FS_ZFS) \
	-DML_ENABLE_LVM=$(ENABLE_LVM) \
	-DML_ENABLE_LUKS1=$(ENABLE_LUKS1) \
	-DML_ENABLE_LUKS2=$(ENABLE_LUKS2) \
	-DML_ENABLE_TPM2=$(ENABLE_TPM2) \
	-DML_ENABLE_TPM12=$(ENABLE_TPM12) \
	-DML_ENABLE_KDF_PBKDF2=$(ENABLE_KDF_PBKDF2) \
	-DML_ENABLE_KDF_ARGON2ID=$(ENABLE_KDF_ARGON2ID) \
	-DML_ENABLE_CIPHER_AES_XTS=$(ENABLE_CIPHER_AES_XTS) \
	-DML_ENABLE_CIPHER_AES_CBC_ESSIV=$(ENABLE_CIPHER_AES_CBC_ESSIV) \
	-DML_ENABLE_CIPHER_SERPENT_XTS=$(ENABLE_CIPHER_SERPENT_XTS) \
	-DML_ENABLE_CIPHER_TWOFISH_XTS=$(ENABLE_CIPHER_TWOFISH_XTS) \
	-fshort-wchar -fno-strict-aliasing \
	-fno-stack-protector -fno-stack-check -ffreestanding \
	-mno-red-zone -maccumulate-outgoing-args
EFI_OBJECTS := $(BUILD_DIR)/config.o $(BUILD_DIR)/efi_main.o \
	$(BUILD_DIR)/efi_storage.o $(BUILD_DIR)/efi_boot.o $(BUILD_DIR)/efi_runtime.o
ifneq ($(filter 1,$(ENABLE_FS_EXT2) $(ENABLE_FS_EXT4) $(ENABLE_FS_VFAT) $(ENABLE_FS_XFS) $(ENABLE_FS_BTRFS) $(ENABLE_FS_ZFS) $(ENABLE_LVM) $(ENABLE_LUKS1) $(ENABLE_LUKS2)),)
EFI_OBJECTS += $(BUILD_DIR)/block.o $(BUILD_DIR)/efi_block.o
endif
ifneq ($(filter 1,$(ENABLE_FS_EXT2) $(ENABLE_FS_EXT4)),)
EFI_OBJECTS += $(BUILD_DIR)/fs_ext.o
endif
ifeq ($(ENABLE_FS_VFAT),1)
EFI_OBJECTS += $(BUILD_DIR)/vfat.o
endif
ifeq ($(ENABLE_FS_XFS),1)
EFI_OBJECTS += $(BUILD_DIR)/xfs.o $(BUILD_DIR)/xfs_fshelp.o $(BUILD_DIR)/xfs_compat.o
endif
ifeq ($(ENABLE_FS_BTRFS),1)
EFI_CFLAGS += -Isrc/btrfs_grub/minilzo
EFI_OBJECTS += $(BUILD_DIR)/btrfs.o $(BUILD_DIR)/btrfs_compat.o \
	$(BUILD_DIR)/btrfs_crc.o $(BUILD_DIR)/btrfs_minilzo.o
endif
ifneq ($(filter 1,$(ENABLE_FS_BTRFS) $(ENABLE_FS_ZFS)),)
EFI_CFLAGS += -Isrc/btrfs_grub/include -Isrc/xfs_grub/include \
	-Isrc/btrfs_grub -Isrc/btrfs_grub/zstd -Isrc/btrfs_grub/zlib \
	-DML_XFS_UEFI=1
EFI_OBJECTS += $(BUILD_DIR)/btrfs_runtime.o $(BUILD_DIR)/xfs_compat.o \
	$(BUILD_DIR)/btrfs_zlib_compat.o $(BUILD_DIR)/btrfs_zlib_adler32.o \
	$(BUILD_DIR)/btrfs_zlib_crc32.o $(BUILD_DIR)/btrfs_zlib_inflate.o $(BUILD_DIR)/btrfs_zlib_inffast.o \
	$(BUILD_DIR)/btrfs_zlib_inftrees.o $(BUILD_DIR)/btrfs_zlib_zutil.o \
	$(BUILD_DIR)/btrfs_zstd_debug.o $(BUILD_DIR)/btrfs_zstd_entropy_common.o \
	$(BUILD_DIR)/btrfs_zstd_error_private.o $(BUILD_DIR)/btrfs_zstd_fse_decompress.o \
	$(BUILD_DIR)/btrfs_zstd_huf_decompress.o $(BUILD_DIR)/btrfs_zstd_module.o \
	$(BUILD_DIR)/btrfs_zstd_xxhash.o $(BUILD_DIR)/btrfs_zstd_zstd_common.o \
	$(BUILD_DIR)/btrfs_zstd_zstd_decompress.o
endif
ifeq ($(ENABLE_FS_ZFS),1)
EFI_CFLAGS := -Isrc/zfs_grub/include $(EFI_CFLAGS)
EFI_OBJECTS += $(BUILD_DIR)/zfs.o $(BUILD_DIR)/zfs_fletcher.o \
	$(BUILD_DIR)/zfs_lz4.o $(BUILD_DIR)/zfs_lzjb.o $(BUILD_DIR)/zfs_sha256.o
endif
ifeq ($(ENABLE_LVM),1)
EFI_OBJECTS += $(BUILD_DIR)/lvm.o
endif
ifneq ($(filter 1,$(ENABLE_LUKS1) $(ENABLE_LUKS2)),)
EFI_OBJECTS += $(BUILD_DIR)/crypto.o
endif
ifeq ($(ENABLE_LUKS1),1)
EFI_OBJECTS += $(BUILD_DIR)/luks1.o
endif
ifeq ($(ENABLE_LUKS2),1)
EFI_OBJECTS += $(BUILD_DIR)/luks2.o
endif
ifeq ($(ENABLE_TPM2),1)
EFI_OBJECTS += $(BUILD_DIR)/tpm2.o
endif
ifeq ($(ENABLE_TPM12),1)
EFI_OBJECTS += $(BUILD_DIR)/tpm12.o
endif
ifeq ($(ENABLE_KDF_ARGON2ID),1)
EFI_OBJECTS += $(BUILD_DIR)/argon2id.o $(BUILD_DIR)/argon2_core.o \
	$(BUILD_DIR)/argon2_ref.o $(BUILD_DIR)/argon2_blake2b.o
ifeq ($(filter 1,$(ENABLE_FS_BTRFS) $(ENABLE_FS_ZFS)),)
EFI_OBJECTS += $(BUILD_DIR)/argon2_memory.o
endif
endif
NETTLE_OBJECTS :=
ifneq ($(ENABLE_CIPHER_SERPENT_XTS),0)
EFI_CFLAGS += -Isrc/nettle
NETTLE_OBJECTS += $(BUILD_DIR)/serpent_set_key.o $(BUILD_DIR)/serpent_encrypt.o $(BUILD_DIR)/serpent_decrypt.o
endif
ifeq ($(ENABLE_CIPHER_TWOFISH_XTS),1)
EFI_CFLAGS += -Isrc/nettle
NETTLE_OBJECTS += $(BUILD_DIR)/twofish.o
endif
EFI_OBJECTS += $(NETTLE_OBJECTS)
EFI_OBJECTS := $(sort $(EFI_OBJECTS))

ARGON2_CFLAGS := -Isrc/argon2 -Isrc/argon2/blake2 \
	-DARGON2_NO_THREADS=1 -DML_ARGON2_EXTERNAL_ALLOCATOR_ONLY=1 \
	-DML_ARGON2_FREESTANDING=1 -Wno-type-limits

BTRFS_HOST_CFLAGS := -DZ_SOLO=1 -Isrc/btrfs_grub/include \
	-Isrc/xfs_grub/include -Isrc/btrfs_grub -Isrc/btrfs_grub/minilzo \
	-Isrc/btrfs_grub/zstd -Isrc/btrfs_grub/zlib -Iinclude \
	-Wno-sign-compare -Wno-unused-parameter -Wno-unused-function
BTRFS_HOST_SOURCES := src/block.c src/btrfs_grub/btrfs.c \
	src/btrfs_grub/btrfs_compat.c src/xfs_grub/xfs_compat.c \
	src/btrfs_grub/crc.c src/btrfs_grub/zlib_compat.c \
	$(wildcard src/btrfs_grub/zlib/*.c) \
	$(wildcard src/btrfs_grub/minilzo/*.c) \
	$(wildcard src/btrfs_grub/zstd/*.c)
ZFS_HOST_CFLAGS := -DGRUB_UTIL=1 -DZ_SOLO=1 \
	-Isrc/zfs_grub/include -Isrc/btrfs_grub/include -Isrc/xfs_grub/include \
	-Isrc/btrfs_grub -Isrc/btrfs_grub/zstd -Isrc/btrfs_grub/zlib -Iinclude \
	-Wno-sign-compare -Wno-unused-parameter -Wno-unused-function
ZFS_HOST_SOURCES := src/block.c src/zfs_grub/zfs.c src/zfs_grub/zfs_fletcher.c \
	src/zfs_grub/zfs_lz4.c src/zfs_grub/zfs_lzjb.c src/zfs_grub/zfs_sha256.c \
	src/xfs_grub/xfs_compat.c \
	src/btrfs_grub/zlib_compat.c $(wildcard src/btrfs_grub/zlib/*.c) \
	$(wildcard src/btrfs_grub/zstd/*.c)

.PHONY: all clean test test-tpm12 test-tpm2-swtpm check-deps show-features efi-smoke qemu-ovmf-smoke qemu-ovmf-tpm2-smoke qemu-ovmf-tpm12-smoke qemu-ovmf-ext-smoke qemu-ovmf-vfat-smoke qemu-ovmf-xfs-smoke qemu-ovmf-btrfs-smoke qemu-ovmf-zfs-smoke qemu-ovmf-zfs-read-smoke qemu-ovmf-lvm-smoke qemu-ovmf-luks1-smoke qemu-ovmf-luks2-smoke FORCE
all: $(BUILD_DIR)/BOOTX64.EFI

check-deps:
	@test -f "$(EFI_INCLUDEDIR)/efi.h" || { echo "GNU-EFI headers not found at $(EFI_INCLUDEDIR)" >&2; exit 1; }
	@command -v "$(EFI_CC)" >/dev/null || { echo "EFI compiler not found: $(EFI_CC)" >&2; exit 1; }

$(BUILD_DIR):
	mkdir -p "$@"

$(BUILD_DIR)/config.o: src/config.c include/ml_config.h | $(BUILD_DIR)
	$(EFI_CC) $(EFI_CFLAGS) -Iinclude -c "$<" -o "$@"

$(BUILD_DIR)/efi_main.o: src/efi_main.c include/ml_config.h include/ml_uefi.h | $(BUILD_DIR)
	$(EFI_CC) $(EFI_CFLAGS) -Iinclude -c "$<" -o "$@"

$(BUILD_DIR)/efi_storage.o: src/efi_storage.c include/ml_config.h include/ml_uefi.h \
	include/ml_block.h include/ml_extfs.h include/ml_vfat.h include/ml_xfs.h include/ml_btrfs.h include/ml_zfs.h include/ml_lvm.h include/ml_luks1.h include/ml_luks2.h | $(BUILD_DIR)
	$(EFI_CC) $(EFI_CFLAGS) -Iinclude -c "$<" -o "$@"

# These sources depend on feature switches passed on the make command line.
$(BUILD_DIR)/efi_storage.o $(BUILD_DIR)/fs_ext.o $(BUILD_DIR)/vfat.o $(BUILD_DIR)/xfs.o $(BUILD_DIR)/xfs_fshelp.o $(BUILD_DIR)/xfs_compat.o $(BUILD_DIR)/btrfs.o $(BUILD_DIR)/btrfs_compat.o $(BUILD_DIR)/btrfs_runtime.o $(BUILD_DIR)/btrfs_crc.o $(BUILD_DIR)/btrfs_zlib_compat.o $(BUILD_DIR)/btrfs_zlib_adler32.o $(BUILD_DIR)/btrfs_zlib_crc32.o $(BUILD_DIR)/btrfs_zlib_inflate.o $(BUILD_DIR)/btrfs_zlib_inffast.o $(BUILD_DIR)/btrfs_zlib_inftrees.o $(BUILD_DIR)/btrfs_zlib_zutil.o $(BUILD_DIR)/btrfs_minilzo.o $(BUILD_DIR)/btrfs_zstd_debug.o $(BUILD_DIR)/btrfs_zstd_entropy_common.o $(BUILD_DIR)/btrfs_zstd_error_private.o $(BUILD_DIR)/btrfs_zstd_fse_decompress.o $(BUILD_DIR)/btrfs_zstd_huf_decompress.o $(BUILD_DIR)/btrfs_zstd_module.o $(BUILD_DIR)/btrfs_zstd_xxhash.o $(BUILD_DIR)/btrfs_zstd_zstd_common.o $(BUILD_DIR)/btrfs_zstd_zstd_decompress.o $(BUILD_DIR)/zfs.o $(BUILD_DIR)/zfs_fletcher.o $(BUILD_DIR)/zfs_lz4.o $(BUILD_DIR)/zfs_lzjb.o $(BUILD_DIR)/zfs_sha256.o $(BUILD_DIR)/lvm.o $(BUILD_DIR)/crypto.o $(BUILD_DIR)/luks1.o $(BUILD_DIR)/luks2.o $(BUILD_DIR)/argon2id.o $(BUILD_DIR)/argon2_core.o $(BUILD_DIR)/argon2_ref.o $(BUILD_DIR)/argon2_blake2b.o $(BUILD_DIR)/argon2_memory.o $(BUILD_DIR)/serpent_set_key.o $(BUILD_DIR)/serpent_encrypt.o $(BUILD_DIR)/serpent_decrypt.o $(BUILD_DIR)/twofish.o: FORCE

FORCE:

$(BUILD_DIR)/efi_boot.o: src/efi_boot.c include/ml_config.h include/ml_uefi.h | $(BUILD_DIR)
	$(EFI_CC) $(EFI_CFLAGS) -Iinclude -c "$<" -o "$@"

$(BUILD_DIR)/efi_runtime.o: src/efi_runtime.c | $(BUILD_DIR)
	$(EFI_CC) $(EFI_CFLAGS) -Iinclude -c "$<" -o "$@"

$(BUILD_DIR)/fs_ext.o: src/fs_ext.c include/ml_extfs.h include/ml_block.h | $(BUILD_DIR)
	$(EFI_CC) $(EFI_CFLAGS) -Iinclude -c "$<" -o "$@"

$(BUILD_DIR)/vfat.o: src/vfat.c include/ml_vfat.h include/ml_block.h | $(BUILD_DIR)
	$(EFI_CC) $(EFI_CFLAGS) -Iinclude -c "$<" -o "$@"

$(BUILD_DIR)/xfs.o: src/xfs_grub/xfs.c src/xfs_grub/xfs_adapter.inc include/ml_xfs.h include/ml_block.h | $(BUILD_DIR)
	$(EFI_CC) $(EFI_CFLAGS) -Wno-sign-compare -DML_XFS_UEFI=1 -Isrc/xfs_grub/include -Iinclude -c "$<" -o "$@"

$(BUILD_DIR)/xfs_fshelp.o: src/xfs_grub/fshelp.c | $(BUILD_DIR)
	$(EFI_CC) $(EFI_CFLAGS) -Wno-sign-compare -DML_XFS_UEFI=1 -Isrc/xfs_grub/include -Iinclude -c "$<" -o "$@"

$(BUILD_DIR)/xfs_compat.o: src/xfs_grub/xfs_compat.c | $(BUILD_DIR)
	$(EFI_CC) $(EFI_CFLAGS) -DML_XFS_UEFI=1 -Isrc/xfs_grub/include -Iinclude -c "$<" -o "$@"

$(BUILD_DIR)/btrfs.o: src/btrfs_grub/btrfs.c src/btrfs_grub/btrfs_adapter.inc include/ml_btrfs.h | $(BUILD_DIR)
	$(EFI_CC) $(EFI_CFLAGS) -mno-stack-arg-probe -Wno-sign-compare -Wno-unused-parameter -Iinclude -c "$<" -o "$@"

$(BUILD_DIR)/btrfs_compat.o: src/btrfs_grub/btrfs_compat.c include/ml_btrfs.h | $(BUILD_DIR)
	$(EFI_CC) $(EFI_CFLAGS) -Iinclude -c "$<" -o "$@"

$(BUILD_DIR)/btrfs_runtime.o: src/btrfs_grub/btrfs_runtime.c | $(BUILD_DIR)
	$(EFI_CC) $(EFI_CFLAGS) -fno-builtin -c "$<" -o "$@"

$(BUILD_DIR)/btrfs_crc.o: src/btrfs_grub/crc.c | $(BUILD_DIR)
	$(EFI_CC) $(EFI_CFLAGS) -Isrc/xfs_grub/include -Isrc/btrfs_grub/include -c "$<" -o "$@"

$(BUILD_DIR)/btrfs_zlib_compat.o: src/btrfs_grub/zlib_compat.c | $(BUILD_DIR)
	$(EFI_CC) $(EFI_CFLAGS) -mno-stack-arg-probe -DZ_SOLO=1 -Isrc/btrfs_grub/include -Isrc/btrfs_grub/zlib -Isrc/xfs_grub/include -c "$<" -o "$@"

$(BUILD_DIR)/btrfs_zlib_adler32.o: src/btrfs_grub/zlib/adler32.c | $(BUILD_DIR)
	$(EFI_CC) $(EFI_CFLAGS) -DZ_SOLO=1 -Isrc/btrfs_grub/zlib -c "$<" -o "$@"

$(BUILD_DIR)/btrfs_zlib_crc32.o: src/btrfs_grub/zlib/crc32.c | $(BUILD_DIR)
	$(EFI_CC) $(EFI_CFLAGS) -DZ_SOLO=1 -Isrc/btrfs_grub/zlib -c "$<" -o "$@"

$(BUILD_DIR)/btrfs_zlib_inflate.o: src/btrfs_grub/zlib/inflate.c | $(BUILD_DIR)
	$(EFI_CC) $(EFI_CFLAGS) -DZ_SOLO=1 -Isrc/btrfs_grub/zlib -c "$<" -o "$@"

$(BUILD_DIR)/btrfs_zlib_inffast.o: src/btrfs_grub/zlib/inffast.c | $(BUILD_DIR)
	$(EFI_CC) $(EFI_CFLAGS) -DZ_SOLO=1 -Isrc/btrfs_grub/zlib -c "$<" -o "$@"

$(BUILD_DIR)/btrfs_zlib_inftrees.o: src/btrfs_grub/zlib/inftrees.c | $(BUILD_DIR)
	$(EFI_CC) $(EFI_CFLAGS) -DZ_SOLO=1 -Isrc/btrfs_grub/zlib -c "$<" -o "$@"

$(BUILD_DIR)/btrfs_zlib_zutil.o: src/btrfs_grub/zlib/zutil.c | $(BUILD_DIR)
	$(EFI_CC) $(EFI_CFLAGS) -DZ_SOLO=1 -Isrc/btrfs_grub/zlib -c "$<" -o "$@"

$(BUILD_DIR)/btrfs_minilzo.o: src/btrfs_grub/minilzo/minilzo.c | $(BUILD_DIR)
	$(EFI_CC) $(EFI_CFLAGS) -Isrc/btrfs_grub/minilzo -c "$<" -o "$@"

$(BUILD_DIR)/btrfs_zstd_%.o: src/btrfs_grub/zstd/%.c | $(BUILD_DIR)
	$(EFI_CC) $(EFI_CFLAGS) -mno-stack-arg-probe -Isrc/btrfs_grub/zstd -c "$<" -o "$@"

$(BUILD_DIR)/zfs.o: src/zfs_grub/zfs.c src/zfs_grub/zfs_adapter.inc include/ml_zfs.h | $(BUILD_DIR)
	$(EFI_CC) $(EFI_CFLAGS) -mno-stack-arg-probe -Wno-sign-compare -Wno-unused-function \
		-Isrc/zfs_grub/include -Isrc/btrfs_grub/include -Isrc/xfs_grub/include \
		-Isrc/btrfs_grub/zstd -Isrc/btrfs_grub/zlib -Isrc/btrfs_grub -Iinclude \
		-DGRUB_UTIL=1 -DML_XFS_UEFI=1 -c "$<" -o "$@"

$(BUILD_DIR)/zfs_%.o: src/zfs_grub/zfs_%.c | $(BUILD_DIR)
	$(EFI_CC) $(EFI_CFLAGS) -Wno-sign-compare -Isrc/zfs_grub/include \
		-Isrc/btrfs_grub/include -Isrc/xfs_grub/include -Iinclude -c "$<" -o "$@"

$(BUILD_DIR)/lvm.o: src/lvm.c include/ml_lvm.h include/ml_block.h | $(BUILD_DIR)
	$(EFI_CC) $(EFI_CFLAGS) -Iinclude -c "$<" -o "$@"

$(BUILD_DIR)/crypto.o: src/crypto.c include/ml_crypto.h | $(BUILD_DIR)
	$(EFI_CC) $(EFI_CFLAGS) -Iinclude -c "$<" -o "$@"

$(BUILD_DIR)/serpent_set_key.o: src/nettle/serpent-set-key.c src/nettle/serpent.h src/nettle/serpent-internal.h src/nettle/macros.h src/nettle/nettle-types.h | $(BUILD_DIR)
	$(EFI_CC) $(EFI_CFLAGS) -Isrc/nettle -DNDEBUG -c "$<" -o "$@"

$(BUILD_DIR)/serpent_encrypt.o: src/nettle/serpent-encrypt.c src/nettle/serpent.h src/nettle/serpent-internal.h src/nettle/macros.h src/nettle/nettle-types.h | $(BUILD_DIR)
	$(EFI_CC) $(EFI_CFLAGS) -Isrc/nettle -DNDEBUG -c "$<" -o "$@"

$(BUILD_DIR)/serpent_decrypt.o: src/nettle/serpent-decrypt.c src/nettle/serpent.h src/nettle/serpent-internal.h src/nettle/macros.h src/nettle/nettle-types.h | $(BUILD_DIR)
	$(EFI_CC) $(EFI_CFLAGS) -Isrc/nettle -DNDEBUG -c "$<" -o "$@"

$(BUILD_DIR)/twofish.o: src/nettle/twofish.c src/nettle/twofish.h src/nettle/macros.h src/nettle/nettle-types.h | $(BUILD_DIR)
	$(EFI_CC) $(EFI_CFLAGS) -Isrc/nettle -DNDEBUG -c "$<" -o "$@"


$(BUILD_DIR)/luks1.o: src/luks1.c include/ml_luks1.h include/ml_crypto.h include/ml_block.h | $(BUILD_DIR)
	$(EFI_CC) $(EFI_CFLAGS) -Iinclude -c "$<" -o "$@"

$(BUILD_DIR)/luks2.o: src/luks2.c include/ml_luks2.h include/ml_crypto.h include/ml_block.h | $(BUILD_DIR)
	$(EFI_CC) $(EFI_CFLAGS) -Iinclude -c "$<" -o "$@"

$(BUILD_DIR)/tpm2.o: src/tpm2.c include/ml_tpm2.h | $(BUILD_DIR)
	$(EFI_CC) $(EFI_CFLAGS) -mno-stack-arg-probe -Iinclude -c "$<" -o "$@"

$(BUILD_DIR)/tpm12.o: src/tpm12.c include/ml_tpm12.h include/ml_crypto.h | $(BUILD_DIR)
	$(EFI_CC) $(EFI_CFLAGS) -mno-stack-arg-probe -Iinclude -c "$<" -o "$@"

$(BUILD_DIR)/argon2id.o: src/argon2/argon2id.c include/ml_argon2id.h src/argon2/argon2.h src/argon2/core.h | $(BUILD_DIR)
	$(EFI_CC) $(EFI_CFLAGS) $(ARGON2_CFLAGS) -Iinclude -c "$<" -o "$@"

$(BUILD_DIR)/argon2_core.o: src/argon2/core.c src/argon2/core.h src/argon2/argon2.h src/argon2/thread.h src/argon2/blake2/blake2.h src/argon2/blake2/blake2-impl.h | $(BUILD_DIR)
	$(EFI_CC) $(EFI_CFLAGS) $(ARGON2_CFLAGS) -Iinclude -c "$<" -o "$@"

$(BUILD_DIR)/argon2_ref.o: src/argon2/ref.c src/argon2/core.h src/argon2/argon2.h src/argon2/blake2/blamka-round-ref.h src/argon2/blake2/blake2.h src/argon2/blake2/blake2-impl.h | $(BUILD_DIR)
	$(EFI_CC) $(EFI_CFLAGS) $(ARGON2_CFLAGS) -Iinclude -c "$<" -o "$@"

$(BUILD_DIR)/argon2_blake2b.o: src/argon2/blake2/blake2b.c src/argon2/blake2/blake2.h src/argon2/blake2/blake2-impl.h src/argon2/argon2.h src/argon2/core.h | $(BUILD_DIR)
	$(EFI_CC) $(EFI_CFLAGS) $(ARGON2_CFLAGS) -Iinclude -c "$<" -o "$@"

$(BUILD_DIR)/argon2_memory.o: src/argon2/memory.c | $(BUILD_DIR)
	$(EFI_CC) $(EFI_CFLAGS) -c "$<" -o "$@"

$(BUILD_DIR)/block.o: src/block.c include/ml_block.h | $(BUILD_DIR)
	$(EFI_CC) $(EFI_CFLAGS) -Iinclude -c "$<" -o "$@"

$(BUILD_DIR)/efi_block.o: src/efi_block.c include/ml_uefi.h include/ml_block.h | $(BUILD_DIR)
	$(EFI_CC) $(EFI_CFLAGS) -Iinclude -c "$<" -o "$@"

$(BUILD_DIR)/BOOTX64.EFI: $(EFI_OBJECTS) | check-deps
	$(EFI_CC) -nostdlib -Wl,-e,efi_main -Wl,--subsystem,10 \
		-Wl,--enable-reloc-section -Wl,--no-insert-timestamp $(EFI_OBJECTS) -o "$@"

$(BUILD_DIR)/efi_test_child.o: tests/efi_test_child.c | $(BUILD_DIR)
	$(EFI_CC) $(EFI_CFLAGS) -Iinclude -c "$<" -o "$@"

$(BUILD_DIR)/TEST-CHILD.EFI: $(BUILD_DIR)/efi_test_child.o $(BUILD_DIR)/efi_runtime.o | check-deps
	$(EFI_CC) -nostdlib -Wl,-e,efi_main -Wl,--subsystem,10 \
		-Wl,--enable-reloc-section -Wl,--no-insert-timestamp $^ -o "$@"

$(BUILD_DIR)/efi_tpm2_probe.o: tests/efi_tpm2_probe.c | $(BUILD_DIR)
	$(EFI_CC) $(EFI_CFLAGS) -c "$<" -o "$@"

$(BUILD_DIR)/TPM2-PROBE.EFI: $(BUILD_DIR)/efi_tpm2_probe.o | check-deps
	$(EFI_CC) -nostdlib -Wl,-e,efi_main -Wl,--subsystem,10 \
		-Wl,--enable-reloc-section -Wl,--no-insert-timestamp $^ -o "$@"

$(BUILD_DIR)/efi_tpm12_probe.o: tests/efi_tpm12_probe.c | $(BUILD_DIR)
	$(EFI_CC) $(EFI_CFLAGS) -c "$<" -o "$@"

$(BUILD_DIR)/TPM12-PROBE.EFI: $(BUILD_DIR)/efi_tpm12_probe.o | check-deps
	$(EFI_CC) -nostdlib -Wl,-e,efi_main -Wl,--subsystem,10 \
		-Wl,--enable-reloc-section -Wl,--no-insert-timestamp $^ -o "$@"

$(BUILD_DIR)/efi_zfs_probe.o: tests/efi_zfs_probe.c include/ml_uefi.h include/ml_zfs.h | $(BUILD_DIR)
	$(EFI_CC) $(EFI_CFLAGS) -mno-stack-arg-probe -Iinclude -c "$<" -o "$@"

ZFS_PROBE_OBJECTS := $(BUILD_DIR)/efi_zfs_probe.o \
	$(filter-out $(BUILD_DIR)/config.o $(BUILD_DIR)/efi_main.o \
		$(BUILD_DIR)/efi_storage.o $(BUILD_DIR)/efi_boot.o,$(EFI_OBJECTS))

$(BUILD_DIR)/ZFS-PROBE.EFI: $(ZFS_PROBE_OBJECTS) | check-deps
	$(EFI_CC) -nostdlib -Wl,-e,efi_main -Wl,--subsystem,10 \
		-Wl,--enable-reloc-section -Wl,--no-insert-timestamp $(ZFS_PROBE_OBJECTS) -o "$@"

efi-smoke: $(BUILD_DIR)/BOOTX64.EFI $(BUILD_DIR)/TEST-CHILD.EFI

qemu-ovmf-smoke: efi-smoke
	bash tests/qemu-ovmf-smoke.sh

qemu-ovmf-tpm2-smoke: $(BUILD_DIR)/TPM2-PROBE.EFI
	bash tests/qemu-ovmf-tpm2-smoke.sh $(BUILD_DIR)

qemu-ovmf-tpm12-smoke: $(BUILD_DIR)/TPM12-PROBE.EFI
	bash tests/qemu-ovmf-tpm12-smoke.sh $(BUILD_DIR)

qemu-ovmf-ext-smoke:
	$(MAKE) BUILD_DIR=$(BUILD_DIR)/ext4 ENABLE_FS_EXT4=1 efi-smoke
	MINILOADER_BUILD_DIR=$(BUILD_DIR)/ext4 ENABLE_FS_EXT4=1 bash tests/qemu-ovmf-smoke.sh

qemu-ovmf-vfat-smoke:
	$(MAKE) BUILD_DIR=$(BUILD_DIR)/vfat ENABLE_FS_VFAT=1 efi-smoke
	MINILOADER_BUILD_DIR=$(BUILD_DIR)/vfat ENABLE_FS_VFAT=1 bash tests/qemu-ovmf-smoke.sh

qemu-ovmf-xfs-smoke:
	$(MAKE) BUILD_DIR=$(BUILD_DIR)/xfs ENABLE_FS_XFS=1 efi-smoke
	MINILOADER_BUILD_DIR=$(BUILD_DIR)/xfs ENABLE_FS_XFS=1 bash tests/qemu-ovmf-smoke.sh

qemu-ovmf-btrfs-smoke:
	$(MAKE) BUILD_DIR=$(BUILD_DIR)/btrfs ENABLE_FS_BTRFS=1 efi-smoke
	MINILOADER_BUILD_DIR=$(BUILD_DIR)/btrfs ENABLE_FS_BTRFS=1 bash tests/qemu-ovmf-smoke.sh

qemu-ovmf-zfs-smoke:
	$(MAKE) BUILD_DIR=$(BUILD_DIR)/zfs ENABLE_FS_ZFS=1 efi-smoke
	MINILOADER_BUILD_DIR=$(BUILD_DIR)/zfs ENABLE_FS_ZFS=1 bash tests/qemu-ovmf-smoke.sh
	$(MAKE) BUILD_DIR=$(BUILD_DIR) qemu-ovmf-zfs-read-smoke

qemu-ovmf-zfs-read-smoke:
	$(MAKE) BUILD_DIR=$(BUILD_DIR)/zfs ENABLE_FS_ZFS=1 $(BUILD_DIR)/zfs/ZFS-PROBE.EFI
	bash tests/qemu-ovmf-zfs-read-smoke.sh $(BUILD_DIR)/zfs

qemu-ovmf-lvm-smoke:
	$(MAKE) BUILD_DIR=$(BUILD_DIR)/lvm ENABLE_FS_EXT4=1 ENABLE_LVM=1 efi-smoke
	MINILOADER_BUILD_DIR=$(BUILD_DIR)/lvm bash tests/qemu-ovmf-lvm-smoke.sh

qemu-ovmf-luks1-smoke:
	$(MAKE) BUILD_DIR=$(BUILD_DIR)/luks1 ENABLE_FS_EXT4=1 ENABLE_LVM=1 ENABLE_LUKS1=1 \
		ENABLE_KDF_PBKDF2=1 ENABLE_CIPHER_AES_XTS=1 \
		ENABLE_CIPHER_AES_CBC_ESSIV=1 ENABLE_CIPHER_SERPENT_XTS=1 \
		ENABLE_CIPHER_TWOFISH_XTS=1 efi-smoke
	MINILOADER_BUILD_DIR=$(BUILD_DIR)/luks1 bash tests/qemu-ovmf-luks1-smoke.sh

qemu-ovmf-luks2-smoke:
	$(MAKE) BUILD_DIR=$(BUILD_DIR)/luks2 ENABLE_FS_EXT4=1 ENABLE_LVM=1 ENABLE_LUKS2=1 \
		ENABLE_KDF_PBKDF2=1 ENABLE_KDF_ARGON2ID=1 ENABLE_CIPHER_AES_XTS=1 \
		ENABLE_CIPHER_AES_CBC_ESSIV=1 \
		ENABLE_CIPHER_SERPENT_XTS=1 ENABLE_CIPHER_TWOFISH_XTS=1 efi-smoke
	MINILOADER_BUILD_DIR=$(BUILD_DIR)/luks2 bash tests/qemu-ovmf-luks2-smoke.sh

show-features:
	@echo "Enabled: firmware Simple File System, UEFI EFI image services, EFI_LOAD_FILE2"
	@echo "Enabled: ext2/3 reader=$(ENABLE_FS_EXT2), ext4 reader=$(ENABLE_FS_EXT4)"
	@echo "Enabled: standalone VFAT reader=$(ENABLE_FS_VFAT)"
	@echo "Enabled: LVM linear/striped reader=$(ENABLE_LVM)"
	@echo "Enabled: LUKS1=$(ENABLE_LUKS1), LUKS2=$(ENABLE_LUKS2), PBKDF2 SHA-1/SHA-256/SHA-512/RIPEMD160/Whirlpool=$(ENABLE_KDF_PBKDF2), Argon2id=$(ENABLE_KDF_ARGON2ID)"
	@echo "Enabled: AES-XTS=$(ENABLE_CIPHER_AES_XTS), AES-CBC-ESSIV:sha256=$(ENABLE_CIPHER_AES_CBC_ESSIV), Serpent-XTS=$(ENABLE_CIPHER_SERPENT_XTS), Twofish-XTS=$(ENABLE_CIPHER_TWOFISH_XTS)"
	@echo "Enabled: read-only XFS reader=$(ENABLE_FS_XFS)"
	@echo "Enabled: read-only Btrfs reader=$(ENABLE_FS_BTRFS)"
	@echo "Enabled: read-only ZFS reader=$(ENABLE_FS_ZFS)"
	@echo "Enabled: firmware TPM 1.2 LUKS1 unsealing=$(ENABLE_TPM12)"
	@echo "Enabled: firmware TPM2 systemd-token unsealing=$(ENABLE_TPM2)"

test: $(BUILD_DIR)
	$(CC) -std=c11 -Wall -Wextra -Werror -Iinclude src/config.c tests/test_config.c -o $(BUILD_DIR)/test_config
	$(BUILD_DIR)/test_config
	$(CC) -std=c11 -Wall -Wextra -Werror -Iinclude src/block.c tests/test_block.c -o $(BUILD_DIR)/test_block
	$(BUILD_DIR)/test_block
	$(CC) -std=c11 -Wall -Wextra -Werror -Iinclude src/block.c src/lvm.c tests/test_lvm.c -o $(BUILD_DIR)/test_lvm
	$(BUILD_DIR)/test_lvm
	$(CC) -std=c11 -Wall -Wextra -Werror -Iinclude src/block.c src/vfat.c tests/test_vfat.c -o $(BUILD_DIR)/test_vfat
	python3 tests/test_vfat.py $(BUILD_DIR)/test_vfat
	$(CC) -std=c11 -Wall -Wextra -Werror -DML_ENABLE_CIPHER_SERPENT_XTS=1 -DML_ENABLE_CIPHER_TWOFISH_XTS=1 -Isrc/nettle -Iinclude src/crypto.c src/nettle/serpent-set-key.c src/nettle/serpent-encrypt.c src/nettle/serpent-decrypt.c src/nettle/twofish.c tests/test_crypto.c -o $(BUILD_DIR)/test_crypto
	$(BUILD_DIR)/test_crypto
	$(CC) -std=c11 -Wall -Wextra -Werror -DML_ENABLE_KDF_PBKDF2=1 -DML_ENABLE_CIPHER_AES_XTS=1 -DML_ENABLE_CIPHER_AES_CBC_ESSIV=1 -DML_ENABLE_CIPHER_SERPENT_XTS=1 -DML_ENABLE_CIPHER_TWOFISH_XTS=1 -Isrc/nettle -Iinclude src/block.c src/crypto.c src/luks1.c src/nettle/serpent-set-key.c src/nettle/serpent-encrypt.c src/nettle/serpent-decrypt.c src/nettle/twofish.c tests/test_luks1.c -o $(BUILD_DIR)/test_luks1
	$(CC) -std=c11 -Wall -Wextra -Werror -DML_ENABLE_CIPHER_SERPENT_XTS=1 -DML_ENABLE_CIPHER_TWOFISH_XTS=1 -Isrc/nettle -Iinclude src/crypto.c src/nettle/serpent-set-key.c src/nettle/serpent-encrypt.c src/nettle/serpent-decrypt.c src/nettle/twofish.c tests/make_xts_payload.c -o $(BUILD_DIR)/make_xts_payload
	python3 tests/test_luks1.py $(BUILD_DIR)/test_luks1 $(BUILD_DIR)/make_xts_payload
	$(CC) -std=c11 -Wall -Wextra -Werror -Wno-type-limits -DARGON2_NO_THREADS=1 -Isrc/argon2 -Isrc/argon2/blake2 -Iinclude src/argon2/argon2id.c src/argon2/core.c src/argon2/ref.c src/argon2/blake2/blake2b.c tests/test_argon2id.c -o $(BUILD_DIR)/test_argon2id
	$(BUILD_DIR)/test_argon2id
	$(CC) -std=c11 -Wall -Wextra -Werror -Wno-type-limits -DARGON2_NO_THREADS=1 -DML_ENABLE_TPM2=1 -DML_ENABLE_KDF_ARGON2ID=1 -DML_ENABLE_KDF_PBKDF2=1 -DML_ENABLE_CIPHER_AES_XTS=1 -DML_ENABLE_CIPHER_AES_CBC_ESSIV=1 -DML_ENABLE_CIPHER_SERPENT_XTS=1 -DML_ENABLE_CIPHER_TWOFISH_XTS=1 -Isrc/nettle -Isrc/argon2 -Isrc/argon2/blake2 -Iinclude src/block.c src/crypto.c src/luks2.c src/nettle/serpent-set-key.c src/nettle/serpent-encrypt.c src/nettle/serpent-decrypt.c src/nettle/twofish.c src/argon2/argon2id.c src/argon2/core.c src/argon2/ref.c src/argon2/blake2/blake2b.c tests/test_luks2.c -o $(BUILD_DIR)/test_luks2
	python3 tests/test_luks2.py $(BUILD_DIR)/test_luks2 $(BUILD_DIR)/make_xts_payload
	$(CC) -std=c11 -Wall -Wextra -Werror -Iinclude \
		-DML_ENABLE_FS_EXT2=1 -DML_ENABLE_FS_EXT4=0 \
		src/block.c src/fs_ext.c tests/test_extfs.c -o $(BUILD_DIR)/test_extfs_ext2
	$(CC) -std=c11 -Wall -Wextra -Werror -Iinclude \
		-DML_ENABLE_FS_EXT2=1 -DML_ENABLE_FS_EXT4=1 \
		src/block.c src/fs_ext.c tests/test_extfs.c -o $(BUILD_DIR)/test_extfs_ext4
	python3 tests/test_extfs.py $(BUILD_DIR)/test_extfs_ext2 $(BUILD_DIR)/test_extfs_ext4
	$(CC) -std=c11 -Wall -Wextra -Werror -Wno-sign-compare -Isrc/xfs_grub/include -Iinclude \
		src/block.c src/xfs_grub/xfs.c src/xfs_grub/fshelp.c \
		src/xfs_grub/xfs_compat.c tests/test_xfs.c -o $(BUILD_DIR)/test_xfs
	python3 tests/test_xfs.py $(BUILD_DIR)/test_xfs
	$(CC) -std=c11 -O2 -Wall -Wextra $(BTRFS_HOST_CFLAGS) \
		$(BTRFS_HOST_SOURCES) tests/test_btrfs.c -o $(BUILD_DIR)/test_btrfs
	python3 tests/test_btrfs.py $(BUILD_DIR)/test_btrfs
	$(CC) -std=c11 -O2 -Wall -Wextra $(ZFS_HOST_CFLAGS) \
		$(ZFS_HOST_SOURCES) tests/test_zfs.c -o $(BUILD_DIR)/test_zfs
	python3 tests/test_zfs.py $(BUILD_DIR)/test_zfs
	python3 -m unittest discover -s tests -p 'test_enroll.py' -v
	$(MAKE) BUILD_DIR=$(BUILD_DIR) test-tpm12
	$(MAKE) BUILD_DIR=$(BUILD_DIR) test-tpm2-swtpm

test-tpm12: $(BUILD_DIR)
	$(CC) -std=c11 -Wall -Wextra -Werror -Iinclude \
		src/crypto.c src/tpm12.c tests/test_tpm12.c -o $(BUILD_DIR)/test_tpm12
	$(BUILD_DIR)/test_tpm12

test-tpm2-swtpm: $(BUILD_DIR)
	@if command -v swtpm >/dev/null && pkg-config --exists tss2-esys tss2-mu tss2-tcti-swtpm; then \
		$(CC) -std=c11 -Wall -Wextra -Werror -Iinclude \
			src/tpm2.c tests/test_tpm2_swtpm.c \
			$$(pkg-config --cflags --libs tss2-esys tss2-mu tss2-tcti-swtpm) \
			-o $(BUILD_DIR)/test_tpm2_swtpm && \
		bash tests/test_tpm2_swtpm.sh $(BUILD_DIR)/test_tpm2_swtpm; \
	else echo "TPM2 swtpm test skipped (swtpm or TSS2 development libraries unavailable)"; fi

clean:
	rm -rf "$(BUILD_DIR)"
