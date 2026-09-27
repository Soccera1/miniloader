#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
set -euo pipefail

root_dir="$(cd "$(dirname "$0")/.." && pwd)"
build_dir="${MINILOADER_BUILD_DIR:-$root_dir/build/luks2}"
esp_dir="$build_dir/ovmf-luks2-esp"
filesystem_root="$build_dir/ovmf-luks2-root"
filesystem_image="$build_dir/ovmf-luks2-ext4.img"
luks_image="$build_dir/ovmf-luks2.img"
lvm_disk="$build_dir/ovmf-luks2-lvm.img"
pv_image="$build_dir/ovmf-luks2-pv.img"
luks_lvm_image="$build_dir/ovmf-luks2-luks-lvm.img"
lvm_luks_image="$build_dir/ovmf-luks2-lvm-luks.img"
serpent_image="$build_dir/ovmf-luks2-serpent.img"
twofish_image="$build_dir/ovmf-luks2-twofish.img"
key_file="$build_dir/ovmf-luks2.key"
volume_key_file="$build_dir/ovmf-luks2-volume-key"
code_file="${OVMF_CODE:-/usr/share/edk2/OvmfX64/OVMF_CODE.fd}"
vars_template="${OVMF_VARS:-/usr/share/edk2/OvmfX64/OVMF_VARS.fd}"
vars_file="$build_dir/OVMF_VARS.luks2-test.fd"
fs_uuid="12345678-1234-1234-1234-123456789abc"

for command in qemu-system-x86_64 cryptsetup mke2fs sgdisk python3 dd cc; do
    command -v "$command" >/dev/null || { echo "$command is required for LUKS2 OVMF smoke" >&2; exit 2; }
done
test -f "$code_file" || { echo "OVMF code image not found: $code_file" >&2; exit 2; }
test -f "$vars_template" || { echo "OVMF vars image not found: $vars_template" >&2; exit 2; }
test -f "$build_dir/BOOTX64.EFI" || { echo "run the LUKS2 feature build first" >&2; exit 2; }
test -f "$build_dir/TEST-CHILD.EFI" || { echo "run make efi-smoke first" >&2; exit 2; }

rm -rf "$esp_dir" "$filesystem_root"
mkdir -p "$esp_dir/EFI/BOOT" "$filesystem_root/boot"
cp "$build_dir/BOOTX64.EFI" "$esp_dir/EFI/BOOT/BOOTX64.EFI"
cp "$build_dir/TEST-CHILD.EFI" "$filesystem_root/boot/TEST-CHILD.EFI"
cp "$root_dir/tests/fixtures/initrd.bin" "$filesystem_root/boot/initrd.bin"
cat >"$filesystem_root/boot/miniloader.conf" <<EOF
timeout=1
default=luks2-smoke

[luks2-smoke]
type=linux
fs_uuid=$fs_uuid
kernel=/boot/TEST-CHILD.EFI
initrd=/boot/initrd.bin
cmdline=smoke=1
EOF

truncate -s 48M "$filesystem_image"
mke2fs -q -F -t ext4 -U "$fs_uuid" -d "$filesystem_root" "$filesystem_image"

cc -std=c11 -O2 -Wall -Wextra -Werror \
    -DML_ENABLE_CIPHER_SERPENT_XTS=1 -DML_ENABLE_CIPHER_TWOFISH_XTS=1 \
    -I"$root_dir/src/nettle" -I"$root_dir/include" \
    "$root_dir/src/crypto.c" "$root_dir/src/nettle/serpent-set-key.c" \
    "$root_dir/src/nettle/serpent-encrypt.c" "$root_dir/src/nettle/serpent-decrypt.c" \
    "$root_dir/src/nettle/twofish.c" "$root_dir/tests/make_xts_payload.c" \
    -o "$build_dir/make_xts_payload"

create_luks2_image() {
    local plaintext_image="$1"
    local destination="$2"
    local image_size="$3"
    local pbkdf="${4:-pbkdf2}"
    local xts_cipher="${5:-aes}"
    local cipher_profile="${6:-xts}"
    local cipher_name="aes-xts-plain64"
    local key_bits=512
    local key_bytes=64
    local -a pbkdf_options=(--pbkdf pbkdf2 --pbkdf-force-iterations 1000)
    if [[ "$xts_cipher" != "aes" ]]; then
        cipher_name="$xts_cipher-xts-plain64"
    fi
    if [[ "$cipher_profile" == "cbc-essiv" ]]; then
        cipher_name="aes-cbc-essiv:sha256"
        key_bits=256
        key_bytes=32
    fi
    if [[ "$pbkdf" == "argon2id" ]]; then
        pbkdf_options=(--pbkdf argon2id --pbkdf-memory 32 --pbkdf-force-iterations 4)
    fi
    truncate -s "$image_size" "$destination"
    printf 'luks2pass' >"$key_file"
    python3 - "$volume_key_file" "$key_bytes" <<'PY'
from pathlib import Path
import sys
Path(sys.argv[1]).write_bytes(bytes(range(int(sys.argv[2]))))
PY
    cryptsetup luksFormat --type luks2 --batch-mode \
        --cipher "$cipher_name" --key-size "$key_bits" --hash sha256 \
        "${pbkdf_options[@]}" --sector-size 4096 \
        --volume-key-file "$volume_key_file" --key-file "$key_file" "$destination"
    "$build_dir/make_xts_payload" "$plaintext_image" "$destination" "$volume_key_file"
    rm -f "$key_file" "$volume_key_file"
}

run_qemu_case() {
    local disk_image="$1"
    local case_name="$2"
    local log_file="$build_dir/qemu-ovmf-luks2-$case_name.log"
    local qmp_socket="$build_dir/qemu-ovmf-luks2-$case_name.qmp"
    cp "$vars_template" "$vars_file"
    MINILOADER_LUKS_VERSION=2 MINILOADER_TEST_PASSPHRASE=luks2pass \
    python3 "$root_dir/tests/qemu_ovmf_qmp.py" "$log_file" "$qmp_socket" -- \
        qemu-system-x86_64 \
        -machine q35,accel=tcg -m 512 \
        -drive if=pflash,format=raw,unit=0,readonly=on,file="$code_file" \
        -drive if=pflash,format=raw,unit=1,file="$vars_file" \
        -drive format=raw,file="fat:rw:$esp_dir" \
        -drive format=raw,file="$disk_image" \
        -nographic -serial stdio -monitor none -no-reboot \
        -qmp "unix:$qmp_socket,server=on,wait=off"
    echo "OVMF LUKS2 $case_name unlock and initrd handoff passed"
}

create_luks2_image "$filesystem_image" "$luks_image" 64M
run_qemu_case "$luks_image" direct

create_luks2_image "$filesystem_image" "$luks_image" 64M argon2id
run_qemu_case "$luks_image" argon2id

create_luks2_image "$filesystem_image" "$serpent_image" 64M pbkdf2 serpent
run_qemu_case "$serpent_image" serpent-xts

create_luks2_image "$filesystem_image" "$twofish_image" 64M pbkdf2 twofish
run_qemu_case "$twofish_image" twofish-xts

create_luks2_image "$filesystem_image" "$luks_image" 64M pbkdf2 aes cbc-essiv
run_qemu_case "$luks_image" aes-cbc-essiv

python3 "$root_dir/tests/make_lvm_image.py" "$lvm_disk" "$filesystem_image"
dd if="$lvm_disk" of="$pv_image" bs=512 skip=2048 count=262144 status=none
create_luks2_image "$pv_image" "$luks_lvm_image" 160M
run_qemu_case "$luks_lvm_image" luks-lvm

create_luks2_image "$filesystem_image" "$luks_image" 64M
python3 "$root_dir/tests/make_lvm_image.py" "$lvm_luks_image" "$luks_image"
run_qemu_case "$lvm_luks_image" lvm-luks
