# SPDX-License-Identifier: GPL-3.0-or-later
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
import hashlib
import struct

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError:
    Cipher = algorithms = modes = None


def run(*args):
    try:
        subprocess.run(args, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError as error:
        sys.stderr.buffer.write(error.stdout or b"")
        sys.stderr.buffer.write(error.stderr or b"")
        raise


def write_cbc_essiv_payload(plaintext, image, volume_key):
    padded = plaintext + bytes((-len(plaintext)) % 512)
    with image.open("r+b") as output:
        output.seek(104)
        payload_sector = int.from_bytes(output.read(4), "big")
        output.seek(payload_sector * 512)
        essiv_key = hashlib.sha256(volume_key).digest()[:len(volume_key)]
        for sector, offset in enumerate(range(0, len(padded), 512)):
            iv_plain = struct.pack("<Q", sector) + bytes(8)
            iv = Cipher(algorithms.AES(essiv_key), modes.ECB()).encryptor().update(iv_plain)
            encryptor = Cipher(algorithms.AES(volume_key), modes.CBC(iv)).encryptor()
            output.write(encryptor.update(padded[offset:offset + 512]))


def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: test_luks1.py LUKS1_TEST XTS_PAYLOAD_WRITER")
    cryptsetup = shutil.which("cryptsetup")
    if not cryptsetup:
        print("LUKS1 image tests skipped (cryptsetup is unavailable)")
        return
    executable = sys.argv[1]
    payload_writer = sys.argv[2]
    passphrase = b"miniloader-test-passphrase\n"
    with tempfile.TemporaryDirectory(prefix="miniloader-luks1-") as temporary:
        root = Path(temporary)
        keyfile = root / "passphrase"
        volume_keyfile = root / "volume-key"
        plainfile = root / "payload.bin"
        keyfile.write_bytes(passphrase)
        volume_key = bytes(range(64))
        volume_keyfile.write_bytes(volume_key)
        plaintext = bytes((index * 31 + 7) & 0xff for index in range(4096))
        plainfile.write_bytes(plaintext)
        for hash_name in ("sha1", "sha256", "sha512", "ripemd160", "whirlpool"):
            image = root / f"luks1-{hash_name}.img"
            with image.open("wb") as output:
                output.truncate(64 * 1024 * 1024)
            run(
                cryptsetup, "luksFormat", "--type", "luks1", "--batch-mode",
                "--cipher", "aes-xts-plain64", "--key-size", "512",
                "--hash", hash_name, "--pbkdf", "pbkdf2", "--iter-time", "10",
                "--volume-key-file", str(volume_keyfile),
                "--key-file", str(keyfile), str(image),
            )
            run(payload_writer, str(plainfile), str(image), str(volume_keyfile))
            run(executable, str(image), passphrase.decode(), "success", str(plainfile))
            wrong = subprocess.run(
                [executable, str(image), "incorrect-passphrase", "wrong"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            if wrong.returncode:
                sys.stderr.buffer.write(wrong.stdout)
                sys.stderr.buffer.write(wrong.stderr)
                raise SystemExit("LUKS1 wrong-passphrase case failed")
        for cipher in ("serpent", "twofish"):
            image = root / f"luks1-{cipher}.img"
            with image.open("wb") as output:
                output.truncate(64 * 1024 * 1024)
            run(
                cryptsetup, "luksFormat", "--type", "luks1", "--batch-mode",
                "--cipher", f"{cipher}-xts-plain64", "--key-size", "512",
                "--hash", "sha256", "--pbkdf", "pbkdf2", "--iter-time", "10",
                "--volume-key-file", str(volume_keyfile),
                "--key-file", str(keyfile), str(image),
            )
            run(payload_writer, str(plainfile), str(image), str(volume_keyfile))
            run(executable, str(image), passphrase.decode(), "success", str(plainfile))
            wrong = subprocess.run(
                [executable, str(image), "incorrect-passphrase", "wrong"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            if wrong.returncode:
                sys.stderr.buffer.write(wrong.stdout)
                sys.stderr.buffer.write(wrong.stderr)
                raise SystemExit(f"LUKS1 {cipher} wrong-passphrase case failed")
        cbc_image = root / "luks1-aes-cbc-essiv.img"
        with cbc_image.open("wb") as output:
            output.truncate(64 * 1024 * 1024)
        cbc_volume_key = bytes(range(32))
        volume_keyfile.write_bytes(cbc_volume_key)
        run(
            cryptsetup, "luksFormat", "--type", "luks1", "--batch-mode",
            "--cipher", "aes-cbc-essiv:sha256", "--key-size", "256",
            "--hash", "sha256", "--pbkdf", "pbkdf2", "--iter-time", "10",
            "--volume-key-file", str(volume_keyfile),
            "--key-file", str(keyfile), str(cbc_image),
        )
        if Cipher is not None:
            write_cbc_essiv_payload(plaintext, cbc_image, cbc_volume_key)
            run(executable, str(cbc_image), passphrase.decode(), "success",
                str(plainfile))
        else:
            run(executable, str(cbc_image), passphrase.decode(), "success")
            print("CBC-ESSIV payload image check skipped (cryptography is unavailable)")
        wrong = subprocess.run(
            [executable, str(cbc_image), "incorrect-passphrase", "wrong"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        if wrong.returncode:
            sys.stderr.buffer.write(wrong.stdout)
            sys.stderr.buffer.write(wrong.stderr)
            raise SystemExit("LUKS1 CBC-ESSIV wrong-passphrase case failed")
    print("cryptsetup-generated LUKS1 PBKDF2 hashes and AES/Serpent/Twofish XTS plus AES-CBC-ESSIV tests passed")


if __name__ == "__main__":
    main()
