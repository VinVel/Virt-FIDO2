"""Checks for the generated user-service unit."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.config import ACTION_ID, SERVICE_NAME, data_dir, install_user_unit


class UserUnitTest(unittest.TestCase):
    def test_unit_requires_absolute_command(self):
        with self.assertRaises(ValueError):
            install_user_unit("virt-fido2")

    def test_renamed_identifiers_and_data_directory(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.dict(os.environ, {"XDG_DATA_HOME": directory}),
        ):
            self.assertEqual(data_dir(), Path(directory) / "virt-fido2")
        self.assertEqual(SERVICE_NAME, "virt-fido2.service")
        self.assertEqual(ACTION_ID, "io.github.virt-fido2.authenticate")

    def test_uevent_socket_is_available(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.dict(os.environ, {"XDG_CONFIG_HOME": directory}),
        ):
            path = install_user_unit("/usr/bin/virt-fido2")
            unit = path.read_text()
        self.assertEqual(path.name, SERVICE_NAME)
        self.assertIn("ExecStart=/usr/bin/virt-fido2 run", unit)
        self.assertNotIn("WorkingDirectory=", unit)
        self.assertNotIn("-m main", unit)
        self.assertIn("RestrictAddressFamilies=AF_UNIX AF_NETLINK", unit)
        self.assertNotIn("PrivateNetwork=", unit)
        self.assertNotIn("ConditionPathExists=/dev/uhid", unit)


if __name__ == "__main__":
    unittest.main()
