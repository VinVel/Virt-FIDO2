"""Exercise CLI service setup without changing the live user manager."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import main


class MainTest(unittest.TestCase):
    def test_install_user_is_not_a_cli_command(self):
        with (
            patch.object(sys, "argv", ["virt-fido2", "install-user"]),
            patch("main.install_user_unit") as install,
            self.assertRaises(SystemExit) as error,
        ):
            main.main()
        self.assertEqual(error.exception.code, 2)
        install.assert_not_called()

    def test_system_file_commands_do_not_manage_user_service(self):
        for operation, helper in (
            ("install", "install_system_files"),
            ("uninstall", "uninstall_system_files"),
        ):
            with self.subTest(operation=operation):
                with (
                    patch.object(sys, "argv", ["virt-fido2", operation]),
                    patch(f"main.{helper}") as system_files,
                    patch("main.manage_user_unit") as service,
                ):
                    main.main()
                system_files.assert_called_once_with()
                service.assert_not_called()

    def test_enable_uses_invoked_installed_command_without_path_lookup(self):
        with tempfile.TemporaryDirectory() as directory:
            command = Path(directory) / "virt-fido2"
            command.touch()
            with (
                patch.object(sys, "argv", [str(command), "enable"]),
                patch("main.shutil.which", return_value=None),
                patch("main.install_user_unit") as install,
                patch("main.manage_user_unit") as manage,
            ):
                main.main()
        install.assert_called_once_with(str(command))
        manage.assert_called_once_with("enable")

    def test_enable_installs_unit_for_installed_command(self):
        with (
            patch.object(sys, "argv", ["main.py", "enable"]),
            patch("main.shutil.which", return_value="/opt/bin/virt-fido2"),
            patch(
                "main.install_user_unit", return_value=Path("/tmp/virt-fido2.service")
            ) as install,
            patch("main.manage_user_unit") as manage,
        ):
            main.main()
        install.assert_called_once_with("/opt/bin/virt-fido2")
        manage.assert_called_once_with("enable")


if __name__ == "__main__":
    unittest.main()
