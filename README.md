# MiniLoader

MiniLoader is a small x86-64 UEFI boot manager. It shows a timed text menu for
Linux EFI-stub kernels and other EFI applications. It loads EFI images through
UEFI and gives Linux its initrd through `EFI_LOAD_FILE2`.

The default build uses the firmware's Simple File System protocol, usually for
the EFI System Partition (ESP). Optional build switches add read-only storage,
LVM, encryption, and TPM support. MiniLoader only reads storage; the Linux
initramfs remains responsible for unlocking an encrypted root filesystem.

## Build

Install GNU-EFI development headers and an x86-64 MinGW cross compiler, then
run:

```sh
make check-deps
make
```

The EFI application is `build/BOOTX64.EFI`. If GNU-EFI headers are installed
outside the default `/usr/include/efi` directory, set `EFI_INCLUDEDIR`:

```sh
make EFI_INCLUDEDIR=/path/to/gnu-efi/include
```

`make show-features` prints the selected modules. Every optional module below
defaults to off; combine the switches you need.

| Feature | Build switch |
| --- | --- |
| ext2, ext3, ext4 | `ENABLE_FS_EXT2=1`, `ENABLE_FS_EXT4=1` |
| VFAT | `ENABLE_FS_VFAT=1` |
| XFS | `ENABLE_FS_XFS=1` |
| Btrfs | `ENABLE_FS_BTRFS=1` |
| ZFS | `ENABLE_FS_ZFS=1` |
| LVM2 | `ENABLE_LVM=1` |
| LUKS1 / LUKS2 | `ENABLE_LUKS1=1` / `ENABLE_LUKS2=1` |
| PBKDF2 / Argon2id | `ENABLE_KDF_PBKDF2=1` / `ENABLE_KDF_ARGON2ID=1` |
| AES-XTS | `ENABLE_CIPHER_AES_XTS=1` |
| AES-CBC-ESSIV:sha256 | `ENABLE_CIPHER_AES_CBC_ESSIV=1` |
| Serpent-XTS / Twofish-XTS | `ENABLE_CIPHER_SERPENT_XTS=1` / `ENABLE_CIPHER_TWOFISH_XTS=1` |
| TPM 1.2 / TPM 2 | `ENABLE_TPM12=1` / `ENABLE_TPM2=1` |

For example, build an ext4 reader with LVM support:

```sh
make ENABLE_FS_EXT4=1 ENABLE_LVM=1
```

LUKS1 requires PBKDF2 and at least one cipher. LUKS2 requires at least one
KDF and one cipher. Argon2id and TPM 2 require LUKS2; TPM 1.2 requires LUKS1.
These examples enable AES-XTS:

```sh
make ENABLE_FS_EXT4=1 ENABLE_LVM=1 ENABLE_LUKS1=1 \
    ENABLE_KDF_PBKDF2=1 ENABLE_CIPHER_AES_XTS=1

make ENABLE_FS_EXT4=1 ENABLE_LVM=1 ENABLE_LUKS2=1 \
    ENABLE_KDF_PBKDF2=1 ENABLE_KDF_ARGON2ID=1 \
    ENABLE_CIPHER_AES_XTS=1
```

To include TPM 2 unsealing in that LUKS2 build, add `ENABLE_TPM2=1`. For TPM
1.2, add `ENABLE_TPM12=1` to the LUKS1 build. Builds with LUKS2 can enable
`ENABLE_CIPHER_AES_CBC_ESSIV=1`, `ENABLE_CIPHER_SERPENT_XTS=1`, and
`ENABLE_CIPHER_TWOFISH_XTS=1` for those additional profiles.

## Install and boot

Mount the ESP and copy the application to a path on it. For example:

```sh
sudo install -D build/BOOTX64.EFI /mnt/esp/EFI/MiniLoader/BOOTX64.EFI
```

Then configure the UEFI boot manager to start `\EFI\MiniLoader\BOOTX64.EFI`,
or select MiniLoader from the firmware's boot menu. The fallback path is
`\EFI\BOOT\BOOTX64.EFI`; firmware may use it when no earlier boot entry takes
precedence.

When booting a disk with OVMF, the OVMF variable store controls the boot order.
An existing entry can still start a Linux EFI-stub directly, even when
MiniLoader is installed on the disk. Select or prioritize the MiniLoader boot
entry in OVMF. No QEMU `-kernel` option is needed: `-kernel` bypasses the usual
UEFI application boot path.

## Configuration

Put `/boot/miniloader.conf` on exactly one volume MiniLoader can read. At
startup, MiniLoader searches the volume it was loaded from first, then other
enabled volumes. It refuses to boot if the file is missing or found more than
once. Encrypted candidates use the configured TPM flow first, then prompt for
a passphrase when needed.

The file is ASCII INI-style text. Global keys are `timeout` and `default`;
comments start with `#` or `;`. Every named entry needs `type` and `fs_uuid`.
Linux entries also need `kernel`, `initrd`, and `cmdline`. EFI entries need
`path`.

```ini
timeout=5
default=linux

[linux]
type=linux
fs_uuid=boot
kernel=\EFI\Linux\vmlinuz.efi
initrd=\EFI\Linux\initrd.img
cmdline=root=UUID=11111111-2222-3333-4444-555555555555 ro quiet

[firmware-setup]
type=efi
fs_uuid=boot
path=\EFI\Tools\setup.efi
```

Use the volume identifier understood by its reader: for a firmware Simple File
System volume, `fs_uuid` is its GPT partition GUID in canonical form; for ext
volumes, it is the filesystem UUID. The `partuuid:<GUID>` form selects an ext
volume by GPT partition GUID. ZFS uses its pool GUID as a 16-digit hexadecimal
identifier. The aliases `boot` and `*` select the volume containing the unique
configuration file. Paths may use either slash style.

The menu defaults to five seconds and the first entry. `timeout=0` boots the
default immediately; values may be from 0 to 3600 seconds. The parser rejects
unknown or duplicate keys, malformed entries, missing fields, unknown defaults,
and files larger than 64 KiB.

## Storage support and limits

Firmware Simple File System access is always available. The following readers
are included only when enabled at build time.

### VFAT

Reads FAT12/16/32 volumes, with ASCII lookup including VFAT long-name records.

### ext2/3/4

Reads classic indirect blocks and ext4 extents. Ext4 mode also reads ext2 and
ext3. Unsupported features are rejected, including journal recovery, `meta_bg`,
encryption, casefold, bigalloc, verity, pending orphan metadata, and symbolic
links. Metadata checksums are not verified.

### XFS

Reads XFS v4/v5, inline, extent, and btree file mappings, and symbolic links.
Volumes needing repair and unsupported incompatibility features are rejected.
MiniLoader does not replay the log or verify v5 metadata checksums. Data blocks
are limited to 64 KiB and directory blocks to 1 MiB.

### Btrfs

Reads the default filesystem root, including inline and regular extents
compressed with zlib, LZO, or Zstandard. The superblock CRC32C is checked;
tree-block addresses and filesystem UUIDs are checked. Tree and file-data
checksums are not verified. Unsupported checksum types, extent encodings, and
compression types are rejected.

### ZFS

Reads unencrypted pools with supported GRUB-compatible on-disk features on
disk, mirror, and RAID-Z vdevs. Compression support includes LZJB, gzip/zlib,
zle, LZ4, and Zstandard. MiniLoader checks all four vdev labels and pool
metadata, and rejects unsupported active features and encrypted data.

### LVM2

Maps linear and striped logical volumes only. Each VG can contain up to 16 PVs
and 32 LVs; each LV can have up to 32 segments, with up to 8 stripes per
segment. Thin, snapshot, RAID, mirror, cache, and other segment types are
unsupported. LVM metadata checksums are not verified.

LUKS readers support PBKDF2 with SHA-1, SHA-256, SHA-512, RIPEMD160, or
Whirlpool. LUKS2 also supports Argon2id, capped at 1 GiB of memory, time cost
100, and 32 lanes. LUKS2 metadata is checksum-validated; metadata is limited
to 64 KiB, keyslots to 32, PBKDF2 iterations to 10 million, and AF material to
256 KiB. Multiple data segments and reencryption metadata are unsupported.

Supported cipher profiles are AES-XTS-plain64, AES-CBC-ESSIV:sha256,
Serpent-XTS-plain64, and Twofish-XTS-plain64, subject to build switches. LUKS2
supports one data segment with 512-byte or 4096-byte sectors. LUKS1 accepts
hidden printable-ASCII passphrases up to 127 bytes and retries three times.
Unsupported ciphers, KDF settings, and layouts produce an error. Storage
layering supports both LUKS → LVM → filesystem and LVM → LUKS → filesystem,
as well as unencrypted filesystems and LVM volumes.

## TPM enrollment

`tools/miniloader-enroll` creates systemd-compatible TPM 2 tokens for LUKS2 or
UUID-linked sidecars for TPM 1.2 and LUKS1. Run it as root and provide the PCR
indices to bind enrollment to:

```sh
sudo tools/miniloader-enroll add --device /dev/nvme0n1p3 --tpm 2 --pcrs 7
sudo tools/miniloader-enroll remove --device /dev/nvme0n1p3 --tpm 2
```

PCR lists accept commas or plus signs. TPM 2 enrollment delegates to
`systemd-cryptenroll`; MiniLoader supports SHA-1 and SHA-256 PCR banks and ECC
or RSA primary keys. PIN-protected tokens are unsupported. If TPM access,
token parsing, or PCR validation fails, MiniLoader asks for the LUKS
passphrase.

For TPM 1.2, `add` prompts for the LUKS passphrase and uses TrouSerS
`tpm_sealdata` to seal it to the selected PCRs. The default sidecar path is
`/boot/miniloader/tpm12/<LUKS-UUID>.json`; use `--metadata-dir` to place it on
an unencrypted volume MiniLoader can read. `remove` deletes that sidecar. TPM
1.2 builds use the UEFI `EFI_TCG` interface; TPM 2 builds use the UEFI TCG2
command interface.

## Tests and QEMU

Run the host-side parser, filesystem, block-device, LVM, LUKS, crypto, TPM, and
enrollment checks with:

```sh
make test
```

The QEMU/OVMF smoke targets exercise the UEFI boot path. OVMF firmware and the
relevant host utilities are required; set `OVMF_CODE` and `OVMF_VARS` if the
firmware files are not in the default locations.

- `make qemu-ovmf-smoke` — menu, missing/duplicate config handling, and
  EFI/initrd handoff.
- `make qemu-ovmf-vfat-smoke` — menu and config discovery with VFAT enabled.
- `make qemu-ovmf-ext-smoke`, `make qemu-ovmf-xfs-smoke`, and
  `make qemu-ovmf-btrfs-smoke` — EFI image and initrd reads from ext4, XFS, or
  Btrfs.
- `make qemu-ovmf-zfs-smoke` and `make qemu-ovmf-zfs-read-smoke` — ZFS boot
  path and file reads through UEFI Block I/O.
- `make qemu-ovmf-lvm-smoke` — EFI image and initrd reads from ext4 on a
  linear LVM volume.
- `make qemu-ovmf-luks1-smoke` — LUKS1 cipher profiles and both LUKS/LVM layer
  orders.
- `make qemu-ovmf-luks2-smoke` — LUKS2 KDF/cipher profiles and both LUKS/LVM
  layer orders.
- `make qemu-ovmf-tpm2-smoke` and `make qemu-ovmf-tpm12-smoke` — TPM 2 TCG2
  and TPM 1.2 EFI_TCG paths using `swtpm`.

Secure Boot is outside the current scope.
