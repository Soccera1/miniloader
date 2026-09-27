#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
set -euo pipefail

root_dir="$(cd "$(dirname "$0")/.." && pwd)"
build_dir="${MINILOADER_BUILD_DIR:-$root_dir/build/lvm}"
esp_dir="$build_dir/ovmf-lvm-esp"
root_dir_data="$build_dir/ovmf-lvm-root"
lv_image="$build_dir/ovmf-lvm-lv.img"
disk_image="$build_dir/ovmf-lvm-disk.img"
code_file="${OVMF_CODE:-/usr/share/edk2/OvmfX64/OVMF_CODE.fd}"
vars_template="${OVMF_VARS:-/usr/share/edk2/OvmfX64/OVMF_VARS.fd}"
vars_file="$build_dir/OVMF_VARS.lvm-test.fd"
log_file="$build_dir/qemu-ovmf-lvm.log"
fs_uuid="12345678-1234-1234-1234-123456789abc"

for command in qemu-system-x86_64 mke2fs sgdisk python3; do
    command -v "$command" >/dev/null || { echo "$command is required for LVM OVMF smoke" >&2; exit 2; }
done
test -f "$code_file" || { echo "OVMF code image not found: $code_file" >&2; exit 2; }
test -f "$vars_template" || { echo "OVMF vars image not found: $vars_template" >&2; exit 2; }
test -f "$build_dir/BOOTX64.EFI" || { echo "run the LVM feature build first" >&2; exit 2; }
test -f "$build_dir/TEST-CHILD.EFI" || { echo "run make efi-smoke first" >&2; exit 2; }

rm -rf "$esp_dir" "$root_dir_data"
mkdir -p "$esp_dir/EFI/BOOT" "$root_dir_data/boot"
cp "$build_dir/BOOTX64.EFI" "$esp_dir/EFI/BOOT/BOOTX64.EFI"
cp "$build_dir/TEST-CHILD.EFI" "$root_dir_data/boot/TEST-CHILD.EFI"
cp "$root_dir/tests/fixtures/initrd.bin" "$root_dir_data/boot/initrd.bin"
cat >"$root_dir_data/boot/miniloader.conf" <<EOF
timeout=1
default=lvm-smoke

[lvm-smoke]
type=linux
fs_uuid=$fs_uuid
kernel=/boot/TEST-CHILD.EFI
initrd=/boot/initrd.bin
cmdline=smoke=1
EOF

truncate -s 64M "$lv_image"
mke2fs -q -F -t ext4 -U "$fs_uuid" -d "$root_dir_data" "$lv_image"
python3 "$root_dir/tests/make_lvm_image.py" "$disk_image" "$lv_image"
cp "$vars_template" "$vars_file"

set +e
timeout 10s qemu-system-x86_64 \
    -machine q35,accel=tcg -m 512 \
    -drive if=pflash,format=raw,unit=0,readonly=on,file="$code_file" \
    -drive if=pflash,format=raw,unit=1,file="$vars_file" \
    -drive format=raw,file="fat:rw:$esp_dir" \
    -drive format=raw,file="$disk_image" \
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
    echo "OVMF LVM linear LV boot passed (QEMU exit status: $qemu_status)"
else
    echo "OVMF LVM boot failed; captured QEMU output is in $log_file" >&2
    exit 1
fi
