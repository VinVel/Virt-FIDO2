# Check privileged command construction without invoking sudo.

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src import system_files


class SystemFilesTest(unittest.TestCase):
    def test_install_uses_bundled_files_and_explains_sudo_first(self):
        events: list[str] = []

        def fake_run(command: list[str], *, check: bool) -> None:
            self.assertTrue(check)
            self.assertEqual(command[0], "sudo")
            events.append("command")

        def fake_print(message: str, *, flush: bool) -> None:
            self.assertTrue(flush)
            self.assertIn("sudo", message)
            events.append("explanation")

        with (
            patch("src.system_files.subprocess.run", side_effect=fake_run) as run,
            patch("builtins.print", side_effect=fake_print),
        ):
            system_files.install_system_files()
        self.assertEqual(events[0], "explanation")
        calls = [call.args[0] for call in run.call_args_list]
        self.assertEqual(
            [call[1] for call in calls], ["install", "install", "udevadm", "udevadm"]
        )
        self.assertEqual(Path(calls[0][3]).read_text().count("<action id="), 1)
        self.assertIn('KERNEL=="tpmrm0"', Path(calls[1][3]).read_text())

    def test_uninstall_refuses_to_remove_modified_files(self):
        with tempfile.TemporaryDirectory() as directory:
            policy = Path(directory) / system_files.POLICY_NAME
            policy.write_text("modified")
            with (
                patch.object(system_files, "POLICY_TARGET", policy),
                patch.object(system_files, "RULE_TARGET", Path(directory) / "missing"),
                patch("src.system_files.subprocess.run") as run,
                self.assertRaisesRegex(RuntimeError, "modified system file"),
            ):
                system_files.uninstall_system_files()
            run.assert_not_called()

    def test_uninstall_removes_only_matching_files(self):
        with tempfile.TemporaryDirectory() as directory:
            assets = system_files.files("src.assets")
            policy = Path(directory) / system_files.POLICY_NAME
            rule = Path(directory) / system_files.RULE_NAME
            policy.write_bytes(assets.joinpath(system_files.POLICY_NAME).read_bytes())
            rule.write_bytes(assets.joinpath(system_files.RULE_NAME).read_bytes())
            with (
                patch.object(system_files, "POLICY_TARGET", policy),
                patch.object(system_files, "RULE_TARGET", rule),
                patch("src.system_files.subprocess.run") as run,
                patch("builtins.print"),
            ):
                system_files.uninstall_system_files()
            calls = [call.args[0] for call in run.call_args_list]
            self.assertEqual(calls[0], ["sudo", "rm", "-f", "--", str(policy)])
            self.assertEqual(calls[1], ["sudo", "rm", "-f", "--", str(rule)])
            self.assertEqual([call[1] for call in calls[2:]], ["udevadm", "udevadm"])

    def test_uninstall_does_not_request_sudo_when_already_absent(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.object(system_files, "POLICY_TARGET", Path(directory) / "policy"),
            patch.object(system_files, "RULE_TARGET", Path(directory) / "rule"),
            patch("src.system_files.subprocess.run") as run,
            patch("builtins.print"),
        ):
            system_files.uninstall_system_files()
        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
