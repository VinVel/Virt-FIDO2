# Install the bundled Polkit policy and udev rule into system directories.

from __future__ import annotations

import subprocess
from contextlib import ExitStack
from importlib.resources import as_file, files
from pathlib import Path

POLICY_NAME = "io.github.virt-fido2.policy"
RULE_NAME = "60-virt-fido2.rules"
POLICY_TARGET = Path("/usr/share/polkit-1/actions") / POLICY_NAME
RULE_TARGET = Path("/etc/udev/rules.d") / RULE_NAME


def _sudo(*command: str) -> None:
    subprocess.run(["sudo", *command], check=True)


def _reload_udev() -> None:
    _sudo("udevadm", "control", "--reload-rules")
    _sudo("udevadm", "trigger", "--subsystem-match=misc", "--subsystem-match=tpmrm")


def install_system_files() -> None:
    print(
        "Installing Virt-FIDO2's Polkit policy and udev rule into system "
        "directories, then reloading device permissions. sudo is required "
        "because those directories and udev are managed by root.",
        flush=True,
    )
    assets = files("src.assets")
    with ExitStack() as stack:
        policy = stack.enter_context(as_file(assets.joinpath(POLICY_NAME)))
        rule = stack.enter_context(as_file(assets.joinpath(RULE_NAME)))
        _sudo("install", "-Dm644", str(policy), str(POLICY_TARGET))
        _sudo("install", "-Dm644", str(rule), str(RULE_TARGET))
    _reload_udev()


def uninstall_system_files() -> None:
    assets = files("src.assets")
    targets = ((POLICY_NAME, POLICY_TARGET), (RULE_NAME, RULE_TARGET))
    existing = [(name, target) for name, target in targets if target.exists()]
    for name, target in existing:
        if target.read_bytes() != assets.joinpath(name).read_bytes():
            raise RuntimeError(f"Refusing to remove modified system file: {target}")
    if not existing:
        print("Virt-FIDO2 system files are already absent.")
        return
    print(
        "Removing Virt-FIDO2's Polkit policy and udev rule, then reloading "
        "device permissions. sudo is required because those files and udev "
        "are managed by root. The user service is not changed.",
        flush=True,
    )
    for _, target in existing:
        _sudo("rm", "-f", "--", str(target))
    _reload_udev()
