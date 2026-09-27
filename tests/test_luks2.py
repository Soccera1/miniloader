# SPDX-License-Identifier: GPL-3.0-or-later
import hashlib
import base64
import json
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

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


def write_xts_payload(image, volume_key, plaintext):
    if Cipher is None:
        return False
    with image.open("r+b") as output:
        output.seek(4096)
        raw = output.read(4096)
        json_end = raw.index(b"\0")
        import json
        metadata = json.loads(raw[:json_end])
        segment = metadata["segments"]["0"]
        output.seek(int(segment["offset"]))
        tweak = struct.pack("<Q", int(segment["iv_tweak"])) + bytes(8)
        encryptor = Cipher(algorithms.AES(volume_key), modes.XTS(tweak)).encryptor()
        output.write(encryptor.update(plaintext) + encryptor.finalize())
    return True


def update_header_checksum(image):
    with image.open("r+b") as output:
        header = bytearray(output.read(16384))
        header[448:480] = bytes(32)
        digest = hashlib.sha256(header).digest()
        output.seek(448)
        output.write(digest)


def add_systemd_tpm2_token(source, destination):
    destination.write_bytes(source.read_bytes())
    with destination.open("r+b") as output:
        header = bytearray(output.read(16384))
        area = header[4096:]
        json_end = area.index(b"\0")
        metadata = json.loads(area[:json_end])
        slot = next(iter(metadata["keyslots"]))
        metadata.setdefault("tokens", {})["0"] = {
            "type": "systemd-tpm2",
            "keyslots": [slot],
            "tpm2-blob": base64.b64encode(b"\x00\x01\xaa").decode("ascii"),
            "tpm2-pcrs": [7, 11],
            "tpm2-pcr-bank": "sha256",
            "tpm2-primary-alg": "ecc",
            "tpm2-policy-hash": bytes(range(32)).hex(),
        }
        encoded = json.dumps(metadata, separators=(",", ":")).encode("ascii")
        if len(encoded) >= len(area):
            raise SystemExit("TPM2 token does not fit in LUKS2 metadata area")
        header[4096:] = encoded + bytes(len(area) - len(encoded))
        header[448:480] = bytes(32)
        header[448:480] = hashlib.sha256(header).digest()
        output.seek(0)
        output.write(header)


def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: test_luks2.py LUKS2_TEST XTS_PAYLOAD_WRITER")
    cryptsetup = shutil.which("cryptsetup")
    if not cryptsetup:
        print("LUKS2 image tests skipped (cryptsetup is unavailable)")
        return
    executable = sys.argv[1]
    payload_writer = sys.argv[2]
    passphrase = "miniloader-test-passphrase"
    volume_key = bytes(range(64))
    plaintext = bytes((index * 31 + 7) & 0xff for index in range(4096))
    with tempfile.TemporaryDirectory(prefix="miniloader-luks2-") as temporary:
        root = Path(temporary)
        keyfile = root / "passphrase"
        volume_keyfile = root / "volume-key"
        payload = root / "payload.bin"
        keyfile.write_bytes(passphrase.encode())
        volume_keyfile.write_bytes(volume_key)
        payload.write_bytes(plaintext)
        image = root / "luks2.img"
        with image.open("wb") as output:
            output.truncate(64 * 1024 * 1024)
        run(
            cryptsetup, "luksFormat", "--type", "luks2", "--batch-mode",
            "--cipher", "aes-xts-plain64", "--key-size", "512",
            "--hash", "sha256", "--pbkdf", "pbkdf2",
            "--pbkdf-force-iterations", "1000",
            "--volume-key-file", str(volume_keyfile),
            "--key-file", str(keyfile), str(image),
        )
        token_image = root / "luks2-tpm2-token.img"
        add_systemd_tpm2_token(image, token_image)
        run(executable, str(token_image), "token")
        payload_available = write_xts_payload(image, volume_key, plaintext)
        if payload_available:
            run(executable, str(image), passphrase, "success", str(payload))
        else:
            run(executable, str(image), passphrase, "success")
            print("LUKS2 payload read skipped (Python cryptography is unavailable)")
        run(executable, str(image), "incorrect-passphrase", "wrong")

        corrupted = root / "corrupt.img"
        corrupted.write_bytes(image.read_bytes())
        with corrupted.open("r+b") as output:
            output.seek(5000)
            byte = output.read(1)
            output.seek(5000)
            output.write(bytes([byte[0] ^ 1]))
        run(executable, str(corrupted), passphrase, "bad")

        unsupported = root / "unsupported.img"
        unsupported.write_bytes(image.read_bytes())
        with unsupported.open("r+b") as output:
            output.seek(4096)
            metadata = output.read(12288)
            target = b'"encryption":"aes-xts-plain64"'
            matches = [i for i in range(len(metadata))
                       if metadata.startswith(target, i)]
            if len(matches) < 2:
                raise SystemExit("could not locate LUKS2 cipher fields")
            segment_cipher = matches[1] + len(b'"encryption":"')
            metadata = bytearray(metadata)
            metadata[segment_cipher:segment_cipher + len(b"aes-xts-plain64")] = b"aes-cbc-plain64"
            output.seek(4096)
            output.write(metadata)
        update_header_checksum(unsupported)
        run(executable, str(unsupported), passphrase, "unsupported")

        argon_image = root / "luks2-argon2id.img"
        argon_passphrase = "miniloader-argon2-passphrase"
        keyfile.write_bytes(argon_passphrase.encode())
        with argon_image.open("wb") as output:
            output.truncate(64 * 1024 * 1024)
        run(
            cryptsetup, "luksFormat", "--type", "luks2", "--batch-mode",
            "--cipher", "aes-xts-plain64", "--key-size", "512",
            "--hash", "sha256", "--pbkdf", "argon2id",
            "--pbkdf-memory", "32", "--pbkdf-force-iterations", "4",
            "--volume-key-file", str(volume_keyfile),
            "--key-file", str(keyfile), str(argon_image),
        )
        if write_xts_payload(argon_image, volume_key, plaintext):
            run(executable, str(argon_image), argon_passphrase, "success", str(payload))
        else:
            run(executable, str(argon_image), argon_passphrase, "success")
        run(executable, str(argon_image), "incorrect-passphrase", "wrong")

        excessive_memory = root / "luks2-argon2-excessive.img"
        excessive_memory.write_bytes(argon_image.read_bytes())
        with excessive_memory.open("r+b") as output:
            output.seek(4096)
            metadata_area = output.read(12288)
            json_end = metadata_area.index(b"\0")
            metadata = metadata_area[:json_end]
            target = b'"memory":32'
            if target not in metadata:
                raise SystemExit("could not locate Argon2id memory cost")
            metadata = metadata.replace(target, b'"memory":1048577', 1)
            metadata += bytes(12288 - len(metadata))
            output.seek(4096)
            output.write(metadata)
        update_header_checksum(excessive_memory)
        run(executable, str(excessive_memory), argon_passphrase, "unsupported")
        keyfile.write_bytes(passphrase.encode())
        for cipher in ("serpent", "twofish"):
            alt_image = root / f"luks2-{cipher}.img"
            with alt_image.open("wb") as output:
                output.truncate(64 * 1024 * 1024)
            run(
                cryptsetup, "luksFormat", "--type", "luks2", "--batch-mode",
                "--cipher", f"{cipher}-xts-plain64", "--key-size", "512",
                "--hash", "sha256", "--pbkdf", "pbkdf2",
                "--pbkdf-force-iterations", "1000",
                "--volume-key-file", str(volume_keyfile),
                "--key-file", str(keyfile), str(alt_image),
            )
            run(payload_writer, str(payload), str(alt_image), str(volume_keyfile))
            run(executable, str(alt_image), passphrase, "success", str(payload))
            run(executable, str(alt_image), "incorrect-passphrase", "wrong")

        cbc_image = root / "luks2-aes-cbc-essiv.img"
        cbc_key = bytes(range(32))
        volume_keyfile.write_bytes(cbc_key)
        with cbc_image.open("wb") as output:
            output.truncate(64 * 1024 * 1024)
        run(
            cryptsetup, "luksFormat", "--type", "luks2", "--batch-mode",
            "--cipher", "aes-cbc-essiv:sha256", "--key-size", "256",
            "--hash", "sha256", "--pbkdf", "pbkdf2",
            "--pbkdf-force-iterations", "1000", "--sector-size", "4096",
            "--volume-key-file", str(volume_keyfile), "--key-file", str(keyfile),
            str(cbc_image),
        )
        run(payload_writer, str(payload), str(cbc_image), str(volume_keyfile))
        run(executable, str(cbc_image), passphrase, "success", str(payload))
        run(executable, str(cbc_image), "incorrect-passphrase", "wrong")
    print("cryptsetup-generated LUKS2 PBKDF2/Argon2id unlock, payload, wrong-passphrase, resource-cap, checksum, AES-CBC-ESSIV, AES/Serpent/Twofish XTS, and unsupported-cipher tests passed")


if __name__ == "__main__":
    main()
