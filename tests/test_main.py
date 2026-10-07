"""Exercise Typer commands without changing the live user manager."""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

import main


class MainTest(unittest.TestCase):
    def setUp(self) -> None:
        self.runner = CliRunner()

    def test_help_lists_commands_but_not_install_user(self):
        result = self.runner.invoke(main.app, ["--help"])
        self.assertEqual(result.exit_code, 0)
        for command in (
            "install",
            "uninstall",
            "enable",
            "disable",
            "start",
            "stop",
            "restart",
            "run",
        ):
            self.assertIn(command, result.output)
        self.assertNotIn("install-user", result.output)
        self.assertEqual(self.runner.invoke(main.app, ["install-user"]).exit_code, 2)

    def test_system_file_commands_do_not_manage_user_service(self):
        for operation, helper in (
            ("install", "install_system_files"),
            ("uninstall", "uninstall_system_files"),
        ):
            with self.subTest(operation=operation):
                with (
                    patch(f"main.{helper}") as system_files,
                    patch("main.manage_user_unit") as service,
                ):
                    result = self.runner.invoke(main.app, [operation])
                self.assertEqual(result.exit_code, 0)
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
                result = self.runner.invoke(main.app, ["enable"])
        self.assertEqual(result.exit_code, 0)
        install.assert_called_once_with(str(command))
        manage.assert_called_once_with("enable")

    def test_enable_uses_path_for_module_invocation(self):
        with (
            patch.object(sys, "argv", ["main.py", "enable"]),
            patch("main.shutil.which", return_value="/opt/bin/virt-fido2"),
            patch("main.install_user_unit") as install,
            patch("main.manage_user_unit") as manage,
        ):
            result = self.runner.invoke(main.app, ["enable"])
        self.assertEqual(result.exit_code, 0)
        install.assert_called_once_with("/opt/bin/virt-fido2")
        manage.assert_called_once_with("enable")

    def test_enable_reports_missing_installed_command(self):
        with (
            patch.object(sys, "argv", ["main.py", "enable"]),
            patch("main.shutil.which", return_value=None),
            patch("main.install_user_unit") as install,
        ):
            result = self.runner.invoke(main.app, ["enable"])
        self.assertEqual(result.exit_code, 2)
        self.assertIn("Install the virt-fido2 command", result.output)
        install.assert_not_called()

    def test_service_lifecycle_commands(self):
        for operation in ("disable", "start", "stop", "restart"):
            with self.subTest(operation=operation):
                with patch("main.manage_user_unit") as manage:
                    result = self.runner.invoke(main.app, [operation])
                self.assertEqual(result.exit_code, 0)
                manage.assert_called_once_with(operation)

    def test_run_requires_tpm_access(self):
        with (
            patch.dict(os.environ, {"TPM2TOOLS_TCTI": ""}),
            patch("main.os.access", return_value=False),
            patch("main.FidoTransport") as transport,
        ):
            result = self.runner.invoke(main.app, ["run"])
        self.assertEqual(result.exit_code, 2)
        self.assertIn("/dev/tpmrm0 is unavailable", result.output)
        transport.assert_not_called()


if __name__ == "__main__":
    unittest.main()
