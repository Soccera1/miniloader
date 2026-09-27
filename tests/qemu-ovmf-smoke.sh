#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
set -euo pipefail

root_dir="$(cd "$(dirname "$0")/.." && pwd)"
build_dir="${MINILOADER_BUILD_DIR:-$root_dir/build}"
esp_dir="$build_dir/ovmf-esp"
code_file="${OVMF_CODE:-/usr/share/edk2/OvmfX64/OVMF_CODE.fd}"
vars_template="${OVMF_VARS:-/usr/share/edk2/OvmfX64/OVMF_VARS.fd}"
vars_file="$build_dir/OVMF_VARS.test.fd"

test -f "$code_file" || { echo "OVMF code image not found: $code_file" >&2; exit 2; }
test -f "$vars_template" || { echo "OVMF vars image not found: $vars_template" >&2; exit 2; }
test -f "$build_dir/BOOTX64.EFI" || { echo "run make first" >&2; exit 2; }
test -f "$build_dir/TEST-CHILD.EFI" || { echo "run make efi-smoke first" >&2; exit 2; }

rm -rf "$esp_dir"
mkdir -p "$esp_dir/EFI/BOOT" "$esp_dir/boot"
cp "$build_dir/BOOTX64.EFI" "$esp_dir/EFI/BOOT/BOOTX64.EFI"
cp "$build_dir/TEST-CHILD.EFI" "$esp_dir/EFI/BOOT/TEST-CHILD.EFI"
cp "$root_dir/tests/fixtures/initrd.bin" "$esp_dir/EFI/BOOT/initrd.bin"

run_case() {
    local config_file="$1"
    local expected_marker="$2"
    local case_name="$3"
    local log_file="$build_dir/qemu-ovmf-$case_name.log"
    local qemu_status
    local duplicate_dir="$build_dir/ovmf-esp-duplicate"
    local -a extra_drives=()

    if [[ "$config_file" == "missing" ]]; then
        rm -f "$esp_dir/boot/miniloader.conf"
    else
        cp "$config_file" "$esp_dir/boot/miniloader.conf"
    fi
    if [[ "$case_name" == "duplicate" ]]; then
        rm -rf "$duplicate_dir"
        mkdir -p "$duplicate_dir/boot"
        cp "$config_file" "$duplicate_dir/boot/miniloader.conf"
        extra_drives=(-drive "format=raw,file=fat:rw:$duplicate_dir")
    fi
    cp "$vars_template" "$vars_file"
    set +e
    timeout 5s qemu-system-x86_64 \
        -machine q35,accel=tcg -m 512 \
        -drive if=pflash,format=raw,unit=0,readonly=on,file="$code_file" \
        -drive if=pflash,format=raw,unit=1,file="$vars_file" \
        -drive format=raw,file="fat:rw:$esp_dir" \
        "${extra_drives[@]}" \
        -nographic -serial stdio -monitor none -no-reboot >"$log_file" 2>&1
    qemu_status=$?
    set -e

    if python3 - "$log_file" "$expected_marker" <<'PY'
from pathlib import Path
import sys
log = Path(sys.argv[1]).read_bytes().replace(b"\x1b", b"")
marker = sys.argv[2].encode()
if marker not in log:
    print(log.decode("utf-8", errors="replace"))
    raise SystemExit(1)
PY
    then
        echo "OVMF $case_name boot passed (QEMU exit status: $qemu_status)"
    else
        echo "OVMF $case_name boot failed; captured QEMU output is in $log_file" >&2
        exit 1
    fi
}

run_case "$root_dir/tests/fixtures/miniloader.conf" MINILOADER_LINUX_CHILD_OK linux
run_case "$root_dir/tests/fixtures/miniloader-efi.conf" MINILOADER_EFI_CHILD_OK efi
run_case missing "MiniLoader: /boot/miniloader.conf was not found" missing-config
run_case "$root_dir/tests/fixtures/miniloader-efi.conf" "more than one /boot/miniloader.conf was found" duplicate

run_ext_case() {
    local ext_root="$build_dir/ovmf-ext-root"
    local ext_partition="$build_dir/ovmf-ext-partition.img"
    local ext_disk="$build_dir/ovmf-ext-disk.img"
    local config_file="$build_dir/ovmf-ext-miniloader.conf"
    local ext_uuid
    local log_file="$build_dir/qemu-ovmf-ext4.log"
    local qemu_status

    command -v mke2fs >/dev/null || { echo "mke2fs is required for ext4 OVMF smoke" >&2; exit 2; }
    command -v sgdisk >/dev/null || { echo "sgdisk is required for ext4 OVMF smoke" >&2; exit 2; }
    rm -rf "$ext_root"
    mkdir -p "$ext_root/boot"
    cp "$build_dir/TEST-CHILD.EFI" "$ext_root/boot/TEST-CHILD.EFI"
    cp "$root_dir/tests/fixtures/initrd.bin" "$ext_root/boot/initrd.bin"
    truncate -s 48M "$ext_partition"
    mke2fs -q -F -t ext4 -d "$ext_root" "$ext_partition"

    truncate -s 64M "$ext_disk"
    sgdisk --clear --new=1:2048:+98304 --typecode=1:8300 "$ext_disk" >/dev/null
    dd if="$ext_partition" of="$ext_disk" bs=512 seek=2048 conv=notrunc status=none
    ext_uuid="$(python3 - "$ext_partition" <<'PY'
from pathlib import Path
import sys
data = Path(sys.argv[1]).read_bytes()[1024 + 104:1024 + 120]
raw = data.hex()
print(f"{raw[:8]}-{raw[8:12]}-{raw[12:16]}-{raw[16:20]}-{raw[20:]}")
PY
)"
    cat >"$config_file" <<EOF
timeout=1
default=ext4-smoke

[ext4-smoke]
type=linux
fs_uuid=$ext_uuid
kernel=/boot/TEST-CHILD.EFI
initrd=/boot/initrd.bin
cmdline=smoke=1
EOF
    cp "$config_file" "$esp_dir/boot/miniloader.conf"
    cp "$vars_template" "$vars_file"
    set +e
    timeout 8s qemu-system-x86_64 \
        -machine q35,accel=tcg -m 512 \
        -drive if=pflash,format=raw,unit=0,readonly=on,file="$code_file" \
        -drive if=pflash,format=raw,unit=1,file="$vars_file" \
        -drive format=raw,file="fat:rw:$esp_dir" \
        -drive format=raw,file="$ext_disk" \
        -nographic -serial stdio -monitor none -no-reboot >"$log_file" 2>&1
    qemu_status=$?
    set -e
    if python3 - "$log_file" MINILOADER_LINUX_CHILD_OK <<'PY'
from pathlib import Path
import sys
log = Path(sys.argv[1]).read_bytes().replace(b"\x1b", b"")
if sys.argv[2].encode() not in log:
    print(log.decode("utf-8", errors="replace"))
    raise SystemExit(1)
PY
    then
        echo "OVMF ext4 Block I/O boot passed (QEMU exit status: $qemu_status)"
    else
        echo "OVMF ext4 Block I/O boot failed; captured QEMU output is in $log_file" >&2
        exit 1
    fi
}

if [[ "${ENABLE_FS_EXT4:-0}" == "1" ]]; then
    run_ext_case
fi

run_xfs_case() {
    local xfs_root="$build_dir/ovmf-xfs-root"
    local xfs_partition="$build_dir/ovmf-xfs-partition.img"
    local xfs_disk="$build_dir/ovmf-xfs-disk.img"
    local config_file="$build_dir/ovmf-xfs-miniloader.conf"
    local xfs_uuid
    local log_file="$build_dir/qemu-ovmf-xfs.log"
    local qemu_status

    command -v mkfs.xfs >/dev/null || { echo "mkfs.xfs is required for XFS OVMF smoke" >&2; exit 2; }
    command -v sgdisk >/dev/null || { echo "sgdisk is required for XFS OVMF smoke" >&2; exit 2; }
    rm -rf "$xfs_root"
    mkdir -p "$xfs_root/boot"
    cp "$build_dir/TEST-CHILD.EFI" "$xfs_root/boot/TEST-CHILD.EFI"
    cp "$root_dir/tests/fixtures/initrd.bin" "$xfs_root/boot/initrd.bin"
    xfs_uuid="$(python3 -c 'import uuid; print(uuid.uuid4())')"
    cat >"$config_file" <<EOF
timeout=1
default=xfs-smoke

[xfs-smoke]
type=linux
fs_uuid=$xfs_uuid
kernel=/boot/TEST-CHILD.EFI
initrd=/boot/initrd.bin
cmdline=smoke=1
EOF
    cp "$config_file" "$xfs_root/boot/miniloader.conf"
    truncate -s 512M "$xfs_partition"
    mkfs.xfs -f -q -m "uuid=$xfs_uuid" -p "$xfs_root" "$xfs_partition"

    truncate -s 530M "$xfs_disk"
    sgdisk --clear --new=1:2048:+1048576 --typecode=1:8300 "$xfs_disk" >/dev/null
    dd if="$xfs_partition" of="$xfs_disk" bs=512 seek=2048 conv=notrunc status=none
    rm -f "$esp_dir/boot/miniloader.conf"
    cp "$vars_template" "$vars_file"
    set +e
    timeout 10s qemu-system-x86_64 \
        -machine q35,accel=tcg -m 512 \
        -drive if=pflash,format=raw,unit=0,readonly=on,file="$code_file" \
        -drive if=pflash,format=raw,unit=1,file="$vars_file" \
        -drive format=raw,file="fat:rw:$esp_dir" \
        -drive format=raw,file="$xfs_disk" \
        -nographic -serial stdio -monitor none -no-reboot >"$log_file" 2>&1
    qemu_status=$?
    set -e
    if python3 - "$log_file" MINILOADER_LINUX_CHILD_OK <<'PY'
from pathlib import Path
import sys
log = Path(sys.argv[1]).read_bytes().replace(b"\x1b", b"")
if sys.argv[2].encode() not in log:
    print(log.decode("utf-8", errors="replace"))
    raise SystemExit(1)
PY
    then
        echo "OVMF XFS Block I/O boot passed (QEMU exit status: $qemu_status)"
    else
        echo "OVMF XFS Block I/O boot failed; captured QEMU output is in $log_file" >&2
        exit 1
    fi
}

if [[ "${ENABLE_FS_XFS:-0}" == "1" ]]; then
    run_xfs_case
fi

run_btrfs_case() {
    local btrfs_root="$build_dir/ovmf-btrfs-root"
    local btrfs_disk="$build_dir/ovmf-btrfs-disk.img"
    local config_file="$build_dir/ovmf-btrfs-miniloader.conf"
    local btrfs_uuid="4b1f3ed4-0dd0-4aac-9c8f-5a881de1724c"
    local log_file="$build_dir/qemu-ovmf-btrfs.log"
    local qemu_status

    rm -rf "$btrfs_root"
    mkdir -p "$btrfs_root/boot"
    cp "$build_dir/TEST-CHILD.EFI" "$btrfs_root/boot/TEST-CHILD.EFI"
    cp "$root_dir/tests/fixtures/initrd.bin" "$btrfs_root/boot/initrd.bin"
    cat >"$config_file" <<EOF
timeout=1
default=btrfs-smoke

[btrfs-smoke]
type=linux
fs_uuid=$btrfs_uuid
kernel=/boot/TEST-CHILD.EFI
initrd=/boot/initrd.bin
cmdline=smoke=1
EOF
    cp "$config_file" "$btrfs_root/boot/miniloader.conf"
    python3 "$root_dir/tests/make_btrfs_image.py" \
        --root "$btrfs_root" --output "$btrfs_disk" --uuid "$btrfs_uuid"
    rm -f "$esp_dir/boot/miniloader.conf"
    cp "$vars_template" "$vars_file"
    set +e
    timeout 15s qemu-system-x86_64 \
        -machine q35,accel=tcg -m 512 \
        -drive if=pflash,format=raw,unit=0,readonly=on,file="$code_file" \
        -drive if=pflash,format=raw,unit=1,file="$vars_file" \
        -drive format=raw,file="fat:rw:$esp_dir" \
        -drive format=raw,file="$btrfs_disk" \
        -nographic -serial stdio -monitor none -no-reboot >"$log_file" 2>&1
    qemu_status=$?
    set -e
    if python3 - "$log_file" MINILOADER_LINUX_CHILD_OK <<'PY'
from pathlib import Path
import sys
log = Path(sys.argv[1]).read_bytes().replace(b"\x1b", b"")
if sys.argv[2].encode() not in log:
    print(log.decode("utf-8", errors="replace"))
    raise SystemExit(1)
PY
    then
        echo "OVMF Btrfs Block I/O boot passed (QEMU exit status: $qemu_status)"
    else
        echo "OVMF Btrfs Block I/O boot failed; captured QEMU output is in $log_file" >&2
        exit 1
    fi
}

if [[ "${ENABLE_FS_BTRFS:-0}" == "1" ]]; then
    run_btrfs_case
fi
