"""Check that TPM handles are released when an operation fails."""

from __future__ import annotations

import hashlib
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from typing import Any, cast
from unittest.mock import Mock

from tpm2_pytss import ESAPI, ESYS_TR, TPM2B_PRIVATE, TPM2B_PUBLIC

from src.tpm import TPMKeys


class HandleCleanupTest(unittest.TestCase):
    def setUp(self):
        self.keys = TPMKeys()
        self.esys = Mock()

    def test_parent_is_flushed_on_error(self):
        self.esys.create_primary.return_value = (123,)
        with (
            self.assertRaisesRegex(RuntimeError, "failed"),
            cast(Any, self.keys)._TPMKeys__parent(
                cast(ESAPI, self.esys), bytes(20), bytes(32)
            ),
        ):
            raise RuntimeError("failed")
        self.esys.flush_context.assert_called_once_with(123)

    def test_child_is_flushed_on_error(self):
        self.esys.load.return_value = 456
        with (
            self.assertRaisesRegex(RuntimeError, "failed"),
            cast(Any, self.keys)._TPMKeys__child(
                cast(ESAPI, self.esys),
                cast(ESYS_TR, 123),
                cast(TPM2B_PRIVATE, Mock()),
                cast(TPM2B_PUBLIC, Mock()),
            ),
        ):
            raise RuntimeError("failed")
        self.esys.flush_context.assert_called_once_with(456)


@unittest.skipUnless(shutil.which("swtpm"), "swtpm is unavailable")
class TPMAlgorithmTest(unittest.TestCase):
    def test_keys_sign_with_correct_algorithm_and_rp_binding(self):
        with tempfile.TemporaryDirectory() as directory:
            socket = str(Path(directory) / "tpm.sock")
            process = subprocess.Popen(
                [
                    "swtpm",
                    "socket",
                    "--tpm2",
                    "--tpmstate",
                    f"dir={directory}",
                    "--server",
                    f"type=unixio,path={socket}",
                    "--ctrl",
                    f"type=unixio,path={socket}.ctrl",
                    "--flags",
                    "not-need-init,startup-clear",
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            try:
                for _ in range(50):
                    if Path(socket).exists() and Path(f"{socket}.ctrl").exists():
                        break
                    time.sleep(0.05)
                else:
                    self.fail("swtpm did not start")
                keys = TPMKeys(f"swtpm:path={socket}")
                rp_hash = hashlib.sha256(b"example.com").digest()
                with self.assertRaises(ValueError):
                    keys.create(rp_hash, -8)
                for algorithm in (-7, -257):
                    with self.subTest(algorithm=algorithm):
                        credential_id, public_key = keys.create(rp_hash, algorithm)
                        self.assertEqual(public_key[3], algorithm)
                        message = b"authenticator data and client data hash"
                        public_key.verify(
                            message,
                            keys.sign(
                                credential_id, rp_hash, hashlib.sha256(message).digest()
                            ),
                        )
                        self.assertTrue(keys.matches(credential_id, rp_hash))
                        self.assertFalse(keys.matches(credential_id, bytes(32)))
            finally:
                process.terminate()
                process.wait(timeout=5)


if __name__ == "__main__":
    unittest.main()
