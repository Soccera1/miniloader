#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
set -euo pipefail

root_dir="$(cd "$(dirname "$0")/.." && pwd)"
build_dir="${MINILOADER_BUILD_DIR:-$root_dir/build/luks1}"
esp_dir="$build_dir/ovmf-luks1-esp"
filesystem_root="$build_dir/ovmf-luks1-root"
filesystem_image="$build_dir/ovmf-luks1-ext4.img"
luks_image="$build_dir/ovmf-luks1.img"
lvm_plain_disk="$build_dir/ovmf-luks1-lvm-plain.img"
pv_plain_image="$build_dir/ovmf-luks1-pv.img"
luks_lvm_image="$build_dir/ovmf-luks1-luks-lvm.img"
lvm_luks_image="$build_dir/ovmf-luks1-lvm-luks.img"
cipher_cbc_image="$build_dir/ovmf-luks1-cbc.img"
key_file="$build_dir/ovmf-luks1.key"
volume_key_file="$build_dir/ovmf-luks1-volume-key"
cbc_volume_key_file="$build_dir/ovmf-luks1-cbc-volume-key"
serpent_image="$build_dir/ovmf-luks1-serpent.img"
twofish_image="$build_dir/ovmf-luks1-twofish.img"
code_file="${OVMF_CODE:-/usr/share/edk2/OvmfX64/OVMF_CODE.fd}"
vars_template="${OVMF_VARS:-/usr/share/edk2/OvmfX64/OVMF_VARS.fd}"
vars_file="$build_dir/OVMF_VARS.luks1-test.fd"
log_file="$build_dir/qemu-ovmf-luks1.log"
qmp_socket="$build_dir/qemu-ovmf-luks1.qmp"

for command in qemu-system-x86_64 cryptsetup mke2fs sgdisk cc python3 dd; do
    command -v "$command" >/dev/null || { echo "$command is required for LUKS1 OVMF smoke" >&2; exit 2; }
done
python3 -c 'import cryptography' >/dev/null 2>&1 || {
    echo "Python cryptography is required for the CBC-ESSIV OVMF fixture" >&2
    exit 2
}
test -f "$code_file" || { echo "OVMF code image not found: $code_file" >&2; exit 2; }
test -f "$vars_template" || { echo "OVMF vars image not found: $vars_template" >&2; exit 2; }
test -f "$build_dir/BOOTX64.EFI" || { echo "run the LUKS1 feature build first" >&2; exit 2; }
test -f "$build_dir/TEST-CHILD.EFI" || { echo "run make efi-smoke first" >&2; exit 2; }

rm -rf "$esp_dir"
rm -rf "$filesystem_root"
mkdir -p "$esp_dir/EFI/BOOT" "$filesystem_root/boot"
cp "$build_dir/BOOTX64.EFI" "$esp_dir/EFI/BOOT/BOOTX64.EFI"
cp "$build_dir/TEST-CHILD.EFI" "$filesystem_root/boot/TEST-CHILD.EFI"
cp "$root_dir/tests/fixtures/initrd.bin" "$filesystem_root/boot/initrd.bin"
filesystem_uuid="12345678-1234-1234-1234-123456789abc"
cat >"$filesystem_root/boot/miniloader.conf" <<EOF
timeout=1
default=luks1-smoke

[luks1-smoke]
type=linux
fs_uuid=$filesystem_uuid
kernel=/boot/TEST-CHILD.EFI
initrd=/boot/initrd.bin
cmdline=smoke=1
EOF

truncate -s 48M "$filesystem_image"
mke2fs -q -F -t ext4 -U "$filesystem_uuid" -d "$filesystem_root" "$filesystem_image"
cc -std=c11 -O2 -Wall -Wextra -Werror \
    -DML_ENABLE_CIPHER_SERPENT_XTS=1 -DML_ENABLE_CIPHER_TWOFISH_XTS=1 \
    -I"$root_dir/src/nettle" -I"$root_dir/include" \
    "$root_dir/src/crypto.c" "$root_dir/src/nettle/serpent-set-key.c" \
    "$root_dir/src/nettle/serpent-encrypt.c" "$root_dir/src/nettle/serpent-decrypt.c" \
    "$root_dir/src/nettle/twofish.c" "$root_dir/tests/make_xts_payload.c" \
    -o "$build_dir/make_xts_payload"

create_luks_image() {
    local plaintext_image="$1"
    local destination="$2"
    local image_size="$3"
    local hash_name="${4:-sha512}"
    local xts_cipher="${5:-aes}"
    local cipher_name="aes-xts-plain64"
    if [[ "$xts_cipher" != "aes" ]]; then
        cipher_name="$xts_cipher-xts-plain64"
    fi
    truncate -s "$image_size" "$destination"
    printf 'luks1pass' >"$key_file"
    python3 - "$volume_key_file" <<'PY'
from pathlib import Path
import sys
Path(sys.argv[1]).write_bytes(bytes(range(64)))
PY
    cryptsetup luksFormat --type luks1 --batch-mode \
        --cipher "$cipher_name" --key-size 512 --hash "$hash_name" \
        --pbkdf pbkdf2 --iter-time 10 --volume-key-file "$volume_key_file" \
        --key-file "$key_file" "$destination"
    "$build_dir/make_xts_payload" "$plaintext_image" "$destination" "$volume_key_file"
    rm -f "$key_file" "$volume_key_file"
}

create_cbc_essiv_image() {
    truncate -s 64M "$cipher_cbc_image"
    printf 'luks1pass' >"$key_file"
    python3 - "$cbc_volume_key_file" <<'PY'
from pathlib import Path
import sys
Path(sys.argv[1]).write_bytes(bytes(range(32)))
PY
    cryptsetup luksFormat --type luks1 --batch-mode \
        --cipher aes-cbc-essiv:sha256 --key-size 256 --hash sha512 \
        --pbkdf pbkdf2 --iter-time 10 --volume-key-file "$cbc_volume_key_file" \
        --key-file "$key_file" "$cipher_cbc_image"
    python3 - "$filesystem_image" "$cipher_cbc_image" "$cbc_volume_key_file" <<'PY'
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from pathlib import Path
import hashlib
import struct
import sys

plain = Path(sys.argv[1]).read_bytes()
destination = Path(sys.argv[2])
key = Path(sys.argv[3]).read_bytes()
assert len(plain) % 512 == 0 and len(key) in (16, 24, 32)
essiv_key = hashlib.sha256(key).digest()[:len(key)]
with destination.open("r+b") as image:
    image.seek(104)
    payload_sector = int.from_bytes(image.read(4), "big")
    image.seek(payload_sector * 512)
    for sector in range(len(plain) // 512):
        iv_input = struct.pack("<Q", sector) + bytes(8)
        iv = Cipher(algorithms.AES(essiv_key), modes.ECB()).encryptor().update(iv_input)
        encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
        start = sector * 512
        image.write(encryptor.update(plain[start:start + 512]))
PY
    rm -f "$key_file" "$cbc_volume_key_file"
}

run_qemu_case() {
    local disk_image="$1"
    local case_name="$2"
    local log_file="$build_dir/qemu-ovmf-luks1-$case_name.log"
    local qmp_socket="$build_dir/qemu-ovmf-luks1-$case_name.qmp"
    cp "$vars_template" "$vars_file"
    python3 "$root_dir/tests/qemu_ovmf_qmp.py" "$log_file" "$qmp_socket" -- \
        qemu-system-x86_64 \
        -machine q35,accel=tcg -m 512 \
        -drive if=pflash,format=raw,unit=0,readonly=on,file="$code_file" \
        -drive if=pflash,format=raw,unit=1,file="$vars_file" \
        -drive format=raw,file="fat:rw:$esp_dir" \
        -drive format=raw,file="$disk_image" \
        -nographic -serial stdio -monitor none -no-reboot \
        -qmp "unix:$qmp_socket,server=on,wait=off"
    echo "OVMF $case_name unlock and initrd handoff passed"
}

create_luks_image "$filesystem_image" "$luks_image" 64M whirlpool
run_qemu_case "$luks_image" direct

create_luks_image "$filesystem_image" "$serpent_image" 64M sha256 serpent
run_qemu_case "$serpent_image" serpent-xts

create_luks_image "$filesystem_image" "$twofish_image" 64M sha256 twofish
run_qemu_case "$twofish_image" twofish-xts

create_cbc_essiv_image
run_qemu_case "$cipher_cbc_image" aes-cbc-essiv

python3 "$root_dir/tests/make_lvm_image.py" "$lvm_plain_disk" "$filesystem_image"
dd if="$lvm_plain_disk" of="$pv_plain_image" bs=512 skip=2048 count=262144 status=none
create_luks_image "$pv_plain_image" "$luks_lvm_image" 140M
run_qemu_case "$luks_lvm_image" luks-lvm

create_luks_image "$filesystem_image" "$luks_image" 64M
python3 "$root_dir/tests/make_lvm_image.py" "$lvm_luks_image" "$luks_image"
run_qemu_case "$lvm_luks_image" lvm-luks
