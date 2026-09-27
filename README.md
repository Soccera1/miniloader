# MiniLoader

MiniLoader is an x86_64 UEFI application built with GNU-EFI protocol headers
and a MinGW PE/COFF linker. It has a timed text menu, EFI image loading through
`LoadImage`/`StartImage`, and Linux EFI-stub initrd handoff through
`EFI_LOAD_FILE2`.

The default build uses firmware Simple File System access. Optional builds can
also read VFAT, ext2, ext3, ext4, XFS, and Btrfs volumes through UEFI Block I/O. The VFAT
reader supports FAT12/16/32 and ASCII lookup through VFAT long filenames. The
ext reader supports classic indirect blocks and ext4 extents, and accepts
filesystem UUIDs as `fs_uuid`. Unsupported ext features are rejected instead of being
interpreted as a different layout. Current limits include journal recovery,
`meta_bg`, encryption, casefold, bigalloc, verity, pending orphan metadata, and
symbolic links. Metadata checksums are not verified.

The optional XFS reader is ported from GRUB's standalone read-only XFS driver.
It reads XFS v4 and v5 filesystems, follows symbolic links, and supports inline,
extent, and btree file mappings. Unsupported incompatibility features and
volumes marked as needing repair are rejected. It does not replay the XFS log
or verify v5 metadata checksums. Data blocks are limited to 64 KiB and
directory blocks to 1 MiB.

The optional Btrfs reader is ported from GRUB's standalone read-only Btrfs
driver. It reads files from the default filesystem root, including inline and
regular extents compressed with zlib, LZO, or Zstandard. MiniLoader validates
the superblock's CRC32C checksum type and checksum; tree blocks are checked for
their logical address and filesystem UUID, but their metadata checksums and
file data checksums are not verified. Other Btrfs superblock checksum types
and unsupported extent encodings or compression types are rejected. Btrfs
filesystems can be discovered on raw Block I/O devices, unlocked LUKS volumes,
and LVM logical volumes when those layers are enabled.

An optional LVM2 reader discovers multiple volume groups and maps linear and
striped logical volumes. It supports at most 16 PVs per VG, 16 VGs, 32 LVs per
VG, 32 segments per LV, and 8 stripes per segment. It does not support thin,
snapshot, RAID, mirror, cache, or other non-linear segment types. LVM metadata
checksums are not verified. Combine it with a filesystem reader to load files
from logical volumes.

The optional LUKS1 reader supports PBKDF2 with SHA-1, SHA-256, SHA-512,
RIPEMD160, or Whirlpool, and the AES-XTS-plain64, AES-CBC-ESSIV:sha256,
Serpent-XTS-plain64, and Twofish-XTS-plain64 profiles. Serpent and Twofish
are separate build-time options. It prompts for a hidden, printable ASCII
passphrase (up to 127 bytes) and retries three times. It can read plain LUKS1
volumes, LUKS1 over LVM, and LUKS1 inside an LVM logical volume. It never
writes to encrypted storage.

An optional LUKS2 reader supports PBKDF2 with SHA-1, SHA-256, SHA-512,
RIPEMD160, or Whirlpool, and Argon2id. Argon2 memory use is capped at 1 GiB;
time cost is capped at 100 and lane count at 32. It supports LUKS1 AF stripes,
raw selected-cipher key areas, and one AES-CBC-ESSIV:sha256 or AES, Serpent,
or Twofish XTS data segment with 512-byte or 4096-byte sectors. It validates the metadata checksum and reads
the newer valid metadata copy. The parser caps metadata at 64 KiB, keyslots at
32, PBKDF2 iterations at 10 million, and AF material at 256 KiB. Multiple data
segments and reencryption metadata are rejected. Unsupported layouts and
parameters are reported; encrypted root storage continues to be unlocked by
the Linux initramfs.

The optional ZFS reader is ported from GRUB's standalone read-only ZFS driver.
It reads unencrypted pools with GRUB-compatible read features on disk, mirror,
and RAID-Z vdevs; supported compression includes LZJB, gzip/zlib, zle,
LZ4, and Zstandard. MiniLoader checks all four vdev labels, validates pool
metadata, and rejects unsupported active pool features and encrypted data.
The pool GUID is exposed as a 16-digit hexadecimal fs_uuid. The host fixture
checks absent labels, malformed signatures in each label position, and a
positive read of `fs@/L3F1` from the upstream four-vdev RAID-Z fixture. The
OVMF ZFS smoke target checks loader boot paths with ZFS enabled and mounts the
same four-vdev pool through UEFI Block I/O to read that file in firmware.
A firmware-provided Simple File System driver can also expose FAT volumes.

## Build

Install GNU-EFI development headers and an x86_64 MinGW cross compiler, then run:

```sh
make
```

The output is `build/BOOTX64.EFI`. On installations that keep GNU-EFI headers
under a different prefix, set `EFI_INCLUDEDIR`, for example:

```sh
make EFI_INCLUDEDIR=/usr/include/efi
```

To include the custom ext readers, enable the desired filesystems at build
time. Ext4 mode also reads ext2 and ext3 volumes:

```sh
make ENABLE_FS_EXT2=1 ENABLE_FS_EXT4=1
```

To include the read-only VFAT12/16/32 reader:

```sh
make ENABLE_FS_VFAT=1
```

To include the optional read-only XFS reader:

```sh
make ENABLE_FS_XFS=1
```

To include the optional read-only Btrfs reader:

```sh
make ENABLE_FS_BTRFS=1
```

To load an ext4 filesystem from an LVM linear or striped logical volume:

```sh
make ENABLE_FS_EXT4=1 ENABLE_LVM=1
```

To enable LUKS1 with ext4 and optional LVM discovery:

```sh
make ENABLE_FS_EXT4=1 ENABLE_LVM=1 ENABLE_LUKS1=1 \
    ENABLE_KDF_PBKDF2=1 ENABLE_CIPHER_AES_XTS=1
```

To enable LUKS2 PBKDF2 and Argon2id volumes with ext4 and optional LVM discovery:

```sh
make ENABLE_FS_EXT4=1 ENABLE_LVM=1 ENABLE_LUKS2=1 \
    ENABLE_KDF_PBKDF2=1 ENABLE_KDF_ARGON2ID=1 ENABLE_CIPHER_AES_XTS=1
```

LUKS1 requires PBKDF2 and at least one enabled cipher profile. LUKS2 requires
at least one of PBKDF2 or Argon2id and at least one enabled cipher profile. Add
`ENABLE_CIPHER_SERPENT_XTS=1` and/or `ENABLE_CIPHER_TWOFISH_XTS=1` to include
those optional implementations. LUKS2 keyslots and data segments can use any
enabled XTS cipher. Config discovery prompts for encrypted candidates so it
can check for a unique
`/boot/miniloader.conf` across all readable volumes.

Firmware TPM2 unsealing for systemd-compatible LUKS2 tokens is an additional
build option. It requires LUKS2 support and uses the UEFI TCG2 command
interface; no TPM userspace library is linked into the EFI image:

```sh
make ENABLE_FS_EXT4=1 ENABLE_LUKS2=1 ENABLE_KDF_PBKDF2=1 \
    ENABLE_CIPHER_AES_XTS=1 ENABLE_TPM2=1
```

MiniLoader tries a matching token before showing the LUKS2 passphrase prompt.
An unavailable TPM, an unsupported token, or a PCR policy mismatch falls back
to that prompt. It supports SHA-1 and SHA-256 PCR banks and ECC or RSA primary
keys. PIN-protected tokens are not supported.

TPM 1.2 unsealing for LUKS1 sidecars is optional as well. It requires LUKS1
support and uses the UEFI EFI_TCG pass-through interface:

```sh
make ENABLE_LUKS1=1 ENABLE_KDF_PBKDF2=1 \
    ENABLE_CIPHER_AES_XTS=1 ENABLE_TPM12=1
```

`make show-features` reports selected reader modules. The default image omits
custom filesystem, LVM, and crypto code.

## Configuration

Place `/boot/miniloader.conf` on exactly one enabled read-only volume.
Configuration is ASCII INI-style text with comments starting with `#` or `;`.
Each entry has a section name, a `type`, and `fs_uuid`. For a firmware Simple
File System volume, `fs_uuid` is its GPT partition GUID in canonical form. For
ext2/3/4 it is the filesystem UUID. The `partuuid:` prefix can select an ext
volume by GPT partition GUID. The aliases `boot` and `*` select the volume
containing the unique configuration file.

```ini
timeout=5
default=linux

[linux]
type=linux
fs_uuid=01234567-89ab-cdef-0123-456789abcdef
kernel=\EFI\Linux\vmlinuz.efi
initrd=\EFI\Linux\initrd.img
cmdline=root=UUID=11111111-2222-3333-4444-555555555555 ro quiet

[firmware-setup]
type=efi
fs_uuid=boot
path=\EFI\Tools\setup.efi
```

Linux entries require `kernel`, `initrd`, and `cmdline`. EFI entries require
`path`. Paths may use either slash style. The parser rejects unknown keys,
duplicate keys, malformed sections, missing fields, an unknown default entry,
and files over 64 KiB. The menu timeout defaults to five seconds; `timeout=0`
boots the selected default immediately.

The UEFI file API and Block I/O protocol are only used in read mode. Encrypted
root storage continues to be unlocked by Linux initramfs.

## Enrollment helper

`tools/miniloader-enroll` wraps `systemd-cryptenroll` for TPM2 tokens on LUKS2
volumes:

```sh
sudo tools/miniloader-enroll add --device /dev/nvme0n1p3 --tpm 2 --pcrs 7
sudo tools/miniloader-enroll remove --device /dev/nvme0n1p3 --tpm 2
```

TPM2 enrollment delegates passphrase prompting and token creation to
`systemd-cryptenroll`; a TPM or PCR failure is handled by the Linux initramfs
unlock flow. PCR lists may be comma or plus separated; the helper passes the
plus-separated format expected by systemd. `remove` clears systemd TPM2 token
slots on that device.

For TPM 1.2 and LUKS1, `add` prompts for the LUKS passphrase and uses
TrouSerS `tpm_sealdata` to seal it to the selected PCRs. Enrollment uses the
TPM's well-known SRK secret so firmware can load the sealed key without a
second interactive secret. The default UUID-linked sidecar is
`/boot/miniloader/tpm12/<LUKS-UUID>.json`; use `--metadata-dir` to place it on
the unencrypted boot filesystem MiniLoader can read. `remove` deletes the
sidecar for that LUKS UUID. Builds with `ENABLE_TPM12=1` and `ENABLE_LUKS1=1`
read that envelope through the UEFI EFI_TCG protocol. TPM unseal or PCR
failures fall back to the LUKS1 passphrase prompt. TPM2 tokens can be used by
firmware builds with `ENABLE_TPM2=1` as described above.

## Verification

Run parser, block/GPT, VFAT, XFS, Btrfs image, ZFS absent/malformed-label and
positive RAID-Z file-read,
LVM linear/striped, ext filesystem image, LUKS1, LUKS2, cryptographic primitive,
TPM 1.2 envelope/authorization, and enrollment helper checks with `make test`.
The TPM 1.2 software-transport test checks OIAP authorization HMACs, malformed
sidecars, unavailable TPMs, and PCR mismatch fallback. When `swtpm` and TSS2 development
libraries are installed, this also exercises ECC and RSA systemd-style tokens,
SHA-1/SHA-256 PCR policy handling, and PCR mismatch fallback. Run
`make qemu-ovmf-tpm2-smoke` to verify OVMF's TCG2 command interface with
`swtpm`, and `make qemu-ovmf-tpm12-smoke` to check OVMF's EFI_TCG pass-through
interface with a TPM 1.2 `swtpm`. Run the general QEMU/OVMF smoke path with
`make qemu-ovmf-smoke`. Run
`make qemu-ovmf-vfat-smoke` to repeat the menu checks with VFAT block discovery
enabled. Run `make qemu-ovmf-xfs-smoke` to boot the EFI child and initrd from a
populated XFS partition. Run `make qemu-ovmf-btrfs-smoke` to boot those files
from a generated Btrfs filesystem. Run `make qemu-ovmf-zfs-smoke` to launch
the ZFS-enabled image under OVMF and read a file from a RAID-Z pool through
UEFI Block I/O. With `mkfs.xfs` and `mke2fs`
and `sgdisk` installed, run
`make qemu-ovmf-ext-smoke` to boot an EFI child and initrd from a GPT ext4
partition through UEFI Block I/O. Run `make qemu-ovmf-lvm-smoke` to boot those
files from an ext4 filesystem on a linear LVM logical volume. Run
`make qemu-ovmf-luks1-smoke` to type a test passphrase through QMP and verify
config, EFI image, and initrd reads from AES-XTS, Serpent-XTS, Twofish-XTS,
and AES-CBC-ESSIV LUKS1,
LUKS1-over-LVM, and LVM-over-LUKS1 ext4 volumes. Set `OVMF_CODE` and
`OVMF_VARS` if your firmware files are in a different directory. The LUKS1
OVMF target also needs Python `cryptography` to prepare a CBC-ESSIV disk image.
Run `make qemu-ovmf-luks2-smoke` to boot from PBKDF2, Argon2id, AES-XTS,
AES-CBC-ESSIV, Serpent-XTS, and Twofish-XTS LUKS2 volumes, plus LUKS2-over-LVM and
LVM-over-LUKS2 ext4 volumes. Secure Boot is outside this implementation.
