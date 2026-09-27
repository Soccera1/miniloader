# SPDX-License-Identifier: GPL-3.0-or-later
import importlib.machinery
import importlib.util
import base64
import json
import os
import pathlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "tools" / "miniloader-enroll"
LOADER = importlib.machinery.SourceFileLoader("miniloader_enroll", str(SCRIPT))
SPEC = importlib.util.spec_from_loader(LOADER.name, LOADER)
enroll = importlib.util.module_from_spec(SPEC)
LOADER.exec_module(enroll)


class PcrListTests(unittest.TestCase):
    def test_preserves_valid_list(self):
        self.assertEqual(enroll.normalize_pcrs("7,0,2"), "7+0+2")
        self.assertEqual(enroll.normalize_pcrs("7+0+2"), "7+0+2")

    def test_rejects_out_of_range_duplicate_and_empty_items(self):
        for value in ("24", "7,7", "7,", "-1", "sha256:7"):
            with self.subTest(value=value), self.assertRaises(enroll.EnrollError):
                enroll.normalize_pcrs(value)


class SystemdCommandTests(unittest.TestCase):
    def parse(self, *argv):
        return enroll.make_parser().parse_args(argv)

    @patch.object(enroll.shutil, "which", return_value="/usr/bin/systemd-cryptenroll")
    @patch.object(enroll, "luks_version", return_value=2)
    def test_add_uses_systemd_plus_delimited_pcrs(self, _luks, _which):
        args = self.parse("add", "--device", "/dev/test", "--tpm", "2", "--pcrs", "0,2,7")
        self.assertEqual(
            enroll.command_for(args),
            ["/usr/bin/systemd-cryptenroll", "--tpm2-device=auto", "--tpm2-pcrs=0+2+7", "/dev/test"],
        )

    @patch.object(enroll, "luks_version", return_value=1)
    def test_tpm2_rejects_luks1(self, _luks):
        args = self.parse("add", "--device", "/dev/test", "--tpm", "2", "--pcrs", "7")
        with self.assertRaisesRegex(enroll.EnrollError, "LUKS2"):
            enroll.command_for(args)

    @patch.object(enroll.shutil, "which", return_value="/usr/bin/systemd-cryptenroll")
    @patch.object(enroll, "luks_version", return_value=2)
    def test_remove_wipes_tpm2_tokens(self, _luks, _which):
        args = self.parse("remove", "--device", "/dev/test", "--tpm", "2")
        self.assertEqual(
            enroll.command_for(args),
            ["/usr/bin/systemd-cryptenroll", "--wipe-slot=tpm2", "/dev/test"],
        )


class Tpm12SidecarTests(unittest.TestCase):
    def parse(self, *argv):
        return enroll.make_parser().parse_args(argv)

    @patch.object(enroll, "luks_version", return_value=1)
    @patch.object(enroll, "luks_uuid",
                  return_value="00112233-4455-6677-8899-aabbccddeeff")
    @patch.object(enroll.shutil, "which", return_value="/usr/bin/tpm_sealdata")
    @patch.object(enroll.getpass, "getpass", return_value="fixture passphrase")
    @patch.object(enroll.subprocess, "run")
    def test_add_writes_uuid_linked_pcr_sidecar(self, run, _password, _which,
                                                _uuid, _version):
        with tempfile.TemporaryDirectory(prefix="miniloader-enroll-test-") as directory:
            args = self.parse("add", "--device", "/dev/test", "--tpm", "1.2",
                              "--pcrs", "0,2,7", "--metadata-dir", directory)

            def seal(command, check):
                self.assertTrue(check)
                self.assertEqual(command[:2], ["/usr/bin/tpm_sealdata", "--well-known"])
                self.assertIn("--infile", command)
                self.assertIn(("--pcr", "0"), list(zip(command, command[1:])))
                self.assertIn(("--pcr", "2"), list(zip(command, command[1:])))
                self.assertIn(("--pcr", "7"), list(zip(command, command[1:])))
                input_path = Path(command[command.index("--infile") + 1])
                output_path = Path(command[command.index("--outfile") + 1])
                self.assertEqual(input_path.read_bytes(), b"fixture passphrase")
                self.assertEqual(os.stat(input_path).st_mode & 0o777, 0o600)
                output_path.write_bytes(b"sealed-tpm12-test-blob")

            run.side_effect = seal
            enroll.add_tpm12(args)
            sidecar = Path(directory) / "00112233-4455-6677-8899-aabbccddeeff.json"
            document = json.loads(sidecar.read_text(encoding="ascii"))
            self.assertEqual(document["format"], "miniloader-tpm12-v1")
            self.assertEqual(document["luks_uuid"], "00112233-4455-6677-8899-aabbccddeeff")
            self.assertEqual(document["pcrs"], [0, 2, 7])
            self.assertEqual(base64.b64decode(document["sealed_blob"]),
                             b"sealed-tpm12-test-blob")
            self.assertEqual(os.stat(sidecar).st_mode & 0o777, 0o600)
            run.assert_called_once()

    @patch.object(enroll, "luks_version", return_value=1)
    @patch.object(enroll, "luks_uuid",
                  return_value="00112233-4455-6677-8899-aabbccddeeff")
    def test_remove_deletes_only_matching_uuid_sidecar(self, _uuid, _version):
        with tempfile.TemporaryDirectory(prefix="miniloader-enroll-test-") as directory:
            sidecar = Path(directory) / "00112233-4455-6677-8899-aabbccddeeff.json"
            sidecar.write_text("{}", encoding="ascii")
            other = Path(directory) / "ffffffff-ffff-ffff-ffff-ffffffffffff.json"
            other.write_text("{}", encoding="ascii")
            args = self.parse("remove", "--device", "/dev/test", "--tpm", "1.2",
                              "--metadata-dir", directory)
            enroll.remove_tpm12(args)
            self.assertFalse(sidecar.exists())
            self.assertTrue(other.exists())


if __name__ == "__main__":
    unittest.main()
