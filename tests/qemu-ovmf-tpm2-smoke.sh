#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
set -euo pipefail

root_dir="$(cd "$(dirname "$0")/.." && pwd)"
build_dir="${1:-$root_dir/build}"
code_file="${OVMF_CODE:-/usr/share/edk2/OvmfX64/OVMF_CODE.fd}"
vars_template="${OVMF_VARS:-/usr/share/edk2/OvmfX64/OVMF_VARS.fd}"
vars_file="$build_dir/OVMF_VARS.tpm2-test.fd"
esp_dir="$build_dir/ovmf-tpm2-esp"
state_dir="$(mktemp -d "${TMPDIR:-/tmp}/miniloader-ovmf-tpm2.XXXXXX")"
tpm_socket="$state_dir/swtpm-sock"
log_file="$build_dir/qemu-ovmf-tpm2.log"

for program in qemu-system-x86_64 swtpm timeout; do
    command -v "$program" >/dev/null || {
        echo "$program is required for the OVMF TPM2 smoke test" >&2
        exit 2
    }
done
test -f "$code_file" || { echo "OVMF code image not found: $code_file" >&2; exit 2; }
test -f "$vars_template" || { echo "OVMF vars image not found: $vars_template" >&2; exit 2; }
test -f "$build_dir/TPM2-PROBE.EFI" || { echo "run make qemu-ovmf-tpm2-smoke first" >&2; exit 2; }

cleanup() {
    if [[ -n "${swtpm_pid:-}" ]]; then
        kill "$swtpm_pid" >/dev/null 2>&1 || true
        wait "$swtpm_pid" >/dev/null 2>&1 || true
    fi
    rm -rf "$state_dir"
}
trap cleanup EXIT INT TERM

mkdir -p "$esp_dir/EFI/BOOT"
cp "$build_dir/TPM2-PROBE.EFI" "$esp_dir/EFI/BOOT/BOOTX64.EFI"
cp "$vars_template" "$vars_file"
swtpm socket --tpm2 --tpmstate "dir=$state_dir" \
    --ctrl "type=unixio,path=$tpm_socket" --flags not-need-init \
    >"$state_dir/swtpm.log" 2>&1 &
swtpm_pid=$!
for attempt in $(seq 1 50); do
    [[ -S "$tpm_socket" ]] && break
    sleep 0.1
done
[[ -S "$tpm_socket" ]] || {
    cat "$state_dir/swtpm.log" >&2
    echo "swtpm did not create its command socket" >&2
    exit 1
}

set +e
timeout 8s qemu-system-x86_64 \
    -machine q35,accel=tcg -m 512 \
    -drive if=pflash,format=raw,unit=0,readonly=on,file="$code_file" \
    -drive if=pflash,format=raw,unit=1,file="$vars_file" \
    -drive format=raw,file="fat:rw:$esp_dir" \
    -chardev socket,id=chrtpm,path="$tpm_socket" \
    -tpmdev emulator,id=tpm0,chardev=chrtpm -device tpm-tis,tpmdev=tpm0 \
    -nographic -serial stdio -monitor none -no-reboot >"$log_file" 2>&1
qemu_status=$?
set -e
if python3 - "$log_file" <<'PY'
from pathlib import Path
import sys
log = Path(sys.argv[1]).read_bytes().replace(b"\x1b", b"")
if b"MINILOADER_TCG2_SUBMIT_OK" not in log:
    print(log.decode("utf-8", errors="replace"))
    raise SystemExit(1)
PY
then
    echo "OVMF TCG2 SubmitCommand with swtpm passed (QEMU exit status: $qemu_status)"
else
    echo "OVMF TCG2 SubmitCommand failed (QEMU exit status: $qemu_status); captured output is in $log_file" >&2
    cat "$state_dir/swtpm.log" >&2
    exit 1
fi
