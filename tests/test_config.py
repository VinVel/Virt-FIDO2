"""Checks for the generated user-service unit."""

from __future__ import annotations

import os
import tempfile
import unittest
from unittest.mock import patch

from src.config import install_user_unit


class UserUnitTest(unittest.TestCase):
    def test_uevent_socket_is_available(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.dict(os.environ, {"XDG_CONFIG_HOME": directory}),
        ):
            unit = install_user_unit("/usr/bin/python3").read_text()
        self.assertIn("RestrictAddressFamilies=AF_UNIX AF_NETLINK", unit)
        self.assertNotIn("PrivateNetwork=", unit)
        self.assertNotIn("ConditionPathExists=/dev/uhid", unit)


if __name__ == "__main__":
    unittest.main()
