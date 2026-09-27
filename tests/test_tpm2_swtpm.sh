#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
set -euo pipefail

test_program="$1"
state_dir="$(mktemp -d "${TMPDIR:-/tmp}/miniloader-swtpm.XXXXXX")"
port="$((23000 + ($$ % 20000)))"
control_port="$((port + 1))"
log_file="$state_dir/swtpm.log"
swtpm socket --tpm2 --tpmstate "dir=$state_dir" \
    --server "type=tcp,port=$port" --ctrl "type=tcp,port=$control_port" \
    --flags not-need-init >"$log_file" 2>&1 &
swtpm_pid=$!
cleanup() {
    kill "$swtpm_pid" >/dev/null 2>&1 || true
    wait "$swtpm_pid" >/dev/null 2>&1 || true
    rm -rf "$state_dir"
}
trap cleanup EXIT INT TERM

ready=0
for attempt in $(seq 1 50); do
    if (echo >"/dev/tcp/127.0.0.1/$port") >/dev/null 2>&1; then
        ready=1
        break
    fi
    sleep 0.1
done
if [[ "$ready" != 1 ]]; then
    cat "$log_file" >&2
    echo "swtpm did not start on port $port" >&2
    exit 1
fi
"$test_program" "host=127.0.0.1,port=$port"
"$test_program" "host=127.0.0.1,port=$port" rsa
"$test_program" "host=127.0.0.1,port=$port" sha1
