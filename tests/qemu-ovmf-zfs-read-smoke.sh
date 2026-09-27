#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
set -euo pipefail

root_dir="$(cd "$(dirname "$0")/.." && pwd)"
build_dir="$root_dir/build/zfs"
if [[ "$#" -ge 1 ]]; then build_dir="$1"; fi
code_file=/usr/share/edk2/OvmfX64/OVMF_CODE.fd
vars_template=/usr/share/edk2/OvmfX64/OVMF_VARS.fd
if [[ -n "$(printenv OVMF_CODE 2>/dev/null || true)" ]]; then
    code_file="$(printenv OVMF_CODE)"
fi
if [[ -n "$(printenv OVMF_VARS 2>/dev/null || true)" ]]; then
    vars_template="$(printenv OVMF_VARS)"
fi
vars_file="$build_dir/OVMF_VARS.zfs-read-test.fd"
esp_dir="$build_dir/ovmf-zfs-read-esp"
vdev_dir="$build_dir/ovmf-zfs-vdevs"
log_file="$build_dir/qemu-ovmf-zfs-read.log"
archive="$root_dir/tests/fixtures/zol-0.6.2.tar.bz2"

for program in qemu-system-x86_64 timeout tar; do
    command -v "$program" >/dev/null || {
        echo "$program is required for the OVMF ZFS read smoke test" >&2
        exit 2
    }
done
test -f "$code_file" || { echo "OVMF code image not found: $code_file" >&2; exit 2; }
test -f "$vars_template" || { echo "OVMF vars image not found: $vars_template" >&2; exit 2; }
test -f "$build_dir/ZFS-PROBE.EFI" || {
    echo "run make qemu-ovmf-zfs-read-smoke first" >&2
    exit 2
}

rm -rf "$esp_dir" "$vdev_dir"
mkdir -p "$esp_dir/EFI/BOOT" "$vdev_dir"
cp "$build_dir/ZFS-PROBE.EFI" "$esp_dir/EFI/BOOT/BOOTX64.EFI"
tar -xjf "$archive" -C "$vdev_dir" --strip-components=1
cp "$vars_template" "$vars_file"

set +e
timeout 30s qemu-system-x86_64 \
    -machine q35,accel=tcg -m 768 \
    -drive if=pflash,format=raw,unit=0,readonly=on,file="$code_file" \
    -drive if=pflash,format=raw,unit=1,file="$vars_file" \
    -drive format=raw,file="fat:rw:$esp_dir" \
    -drive format=raw,file="$vdev_dir/vdev0" \
    -drive format=raw,file="$vdev_dir/vdev1" \
    -drive format=raw,file="$vdev_dir/vdev2" \
    -drive format=raw,file="$vdev_dir/vdev3" \
    -nographic -serial stdio -monitor none -no-reboot >"$log_file" 2>&1
qemu_status=$?
set -e

if python3 - "$log_file" <<'PY'
from pathlib import Path
import sys

log = Path(sys.argv[1]).read_bytes().replace(b"\x1b", b"")
if b"MINILOADER_ZFS_BLOCK_IO_READ_OK" not in log:
    print(log.decode("utf-8", errors="replace"))
    raise SystemExit(1)
PY
then
    echo "OVMF UEFI Block I/O ZFS RAID-Z file read passed (QEMU exit status: $qemu_status)"
else
    echo "OVMF UEFI Block I/O ZFS RAID-Z file read failed (QEMU exit status: $qemu_status); captured output is in $log_file" >&2
    exit 1
fi
