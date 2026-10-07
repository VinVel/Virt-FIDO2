"""Check that TPM handles are released when an operation fails."""

from __future__ import annotations

import unittest
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


if __name__ == "__main__":
    unittest.main()
