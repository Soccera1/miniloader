#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Run QEMU with QMP and type one test passphrase when the EFI prompt appears."""

import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path


def receive_line(connection, timeout=5):
    connection.settimeout(timeout)
    data = bytearray()
    while not data.endswith(b"\r\n"):
        chunk = connection.recv(1)
        if not chunk:
            raise RuntimeError("QEMU closed the QMP connection")
        data.extend(chunk)
    return json.loads(data)


def qmp_command(connection, command_id, command, arguments=None):
    request = {"execute": command, "id": command_id}
    if arguments is not None:
        request["arguments"] = arguments
    connection.sendall(json.dumps(request).encode() + b"\r\n")
    while True:
        response = receive_line(connection)
        if response.get("id") == command_id:
            if "error" in response:
                raise RuntimeError(f"QMP {command} failed: {response['error']}")
            return response


def main():
    if len(sys.argv) < 5 or sys.argv[3] != "--":
        raise SystemExit(
            "usage: qemu_ovmf_qmp.py LOG QMP_SOCKET -- QEMU [ARG ...]"
        )
    log_path = Path(sys.argv[1])
    socket_path = Path(sys.argv[2])
    qemu = sys.argv[4:]
    luks_version = os.environ.get("MINILOADER_LUKS_VERSION", "1")
    passphrase = os.environ.get("MINILOADER_TEST_PASSPHRASE", "luks1pass")
    prompt_marker = f"Unlock LUKS{luks_version} volume".encode()
    unlocked_marker = f"LUKS{luks_version} volume unlocked.".encode()
    log_path.parent.mkdir(parents=True, exist_ok=True)
    socket_path.unlink(missing_ok=True)

    with log_path.open("wb") as log:
        process = subprocess.Popen(
            qemu,
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
        )
        connection = None
        try:
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    raise RuntimeError("QEMU exited before opening its QMP socket")
                try:
                    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    connection.connect(str(socket_path))
                    break
                except (FileNotFoundError, ConnectionRefusedError):
                    if connection is not None:
                        connection.close()
                    connection = None
                    time.sleep(0.1)
            if connection is None:
                raise RuntimeError("QEMU did not open its QMP socket")
            receive_line(connection)
            qmp_command(connection, 1, "qmp_capabilities")

            prompt_deadline = time.monotonic() + 25
            while time.monotonic() < prompt_deadline:
                log.flush()
                output = log_path.read_bytes().replace(b"\r", b"")
                if prompt_marker in output:
                    break
                if process.poll() is not None:
                    raise RuntimeError(f"QEMU exited before the LUKS{luks_version} prompt")
                time.sleep(0.1)
            else:
                raise RuntimeError(f"UEFI LUKS{luks_version} prompt did not appear")

            # All lower-case keys keep this deterministic across keyboard layouts.
            for command_id, character in enumerate(passphrase, start=2):
                qmp_command(connection, command_id, "send-key", {
                    "keys": [{"type": "qcode", "data": character}],
                    "hold-time": 120,
                })
            qmp_command(connection, len(passphrase) + 2, "send-key", {
                "keys": [{"type": "qcode", "data": "ret"}],
                "hold-time": 120,
            })

            boot_deadline = time.monotonic() + 30
            while time.monotonic() < boot_deadline:
                log.flush()
                output = log_path.read_bytes().replace(b"\r", b"")
                if (unlocked_marker in output and
                        b"MINILOADER_LINUX_CHILD_OK" in output):
                    return 0
                if process.poll() is not None:
                    raise RuntimeError("QEMU exited before the EFI child marker")
                time.sleep(0.1)
            raise RuntimeError("EFI child did not report the Linux initrd handoff")
        except Exception as error:
            log.flush()
            captured = log_path.read_bytes().decode("utf-8", errors="replace")
            print(captured, file=sys.stderr)
            print(f"OVMF QMP smoke failed: {error}", file=sys.stderr)
            return 1
        finally:
            if connection is not None:
                connection.close()
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            socket_path.unlink(missing_ok=True)


if __name__ == "__main__":
    raise SystemExit(main())
