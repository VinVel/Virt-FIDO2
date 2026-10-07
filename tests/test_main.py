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
from src.storage import Credential, CredentialStore


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
            "list",
            "delete",
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

    def test_list_and_revoke_by_displayed_prefix(self):
        with tempfile.TemporaryDirectory() as directory:
            store = CredentialStore(Path(directory))
            credential_id = b"VFD1" + bytes(range(64))
            store.save(
                Credential(credential_id, "example.com", b"alice", "alice", "Alice")
            )
            with patch("main.CredentialStore", return_value=store):
                listing = self.runner.invoke(main.app, ["list"])
                self.assertEqual(listing.exit_code, 0)
                self.assertIn("example.com", listing.output)
                self.assertIn("Alice", listing.output)
                prefix = main._credential_text(credential_id)[:16]
                self.assertIn(prefix, listing.output)
                revoked = self.runner.invoke(main.app, ["delete", prefix])
                self.assertEqual(revoked.exit_code, 0)
                self.assertIn("revoked locally", revoked.output)
                self.assertEqual(store.all(), [])
                self.assertTrue(store.is_revoked(credential_id))
                self.assertTrue(store.revocations_path.exists())

    def test_revoke_requires_unambiguous_id(self):
        with tempfile.TemporaryDirectory() as directory:
            store = CredentialStore(Path(directory))
            first = b"VFD1" + bytes(40)
            second = first + b"different"
            store.save(Credential(first, "example.com", b"a", "a", "A"))
            store.save(Credential(second, "example.com", b"b", "b", "B"))
            with patch("main.CredentialStore", return_value=store):
                result = self.runner.invoke(
                    main.app, ["delete", main._credential_text(first)[:16]]
                )
            self.assertEqual(result.exit_code, 2)
            self.assertIn("ambiguous", result.output)
            self.assertFalse(store.revocations_path.exists())

    def test_revoke_unlisted_full_id(self):
        with tempfile.TemporaryDirectory() as directory:
            store = CredentialStore(Path(directory))
            credential_id = b"VFD1" + bytes(range(64))
            with patch("main.CredentialStore", return_value=store):
                result = self.runner.invoke(
                    main.app, ["delete", main._credential_text(credential_id)]
                )
            self.assertEqual(result.exit_code, 0)
            self.assertTrue(store.is_revoked(credential_id))
            self.assertEqual(store.all(), [])

    def test_delete_requires_credential_id(self):
        result = self.runner.invoke(main.app, ["delete"])
        self.assertEqual(result.exit_code, 2)
        self.assertIn("Missing argument", result.output)
        self.assertEqual(self.runner.invoke(main.app, ["-d", "some-id"]).exit_code, 2)


if __name__ == "__main__":
    unittest.main()
