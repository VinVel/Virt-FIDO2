from __future__ import annotations

import os
from pathlib import Path

ACTION_ID = "io.github.virt-fido2.authenticate"
SERVICE_NAME = "virt-fido2.service"
APP_NAME = "virt-fido2"


def data_dir() -> Path:
    base = os.environ.get("XDG_DATA_HOME")
    return (
        Path(base)
        if base and Path(base).is_absolute()
        else Path.home() / ".local/share"
    ) / APP_NAME


def user_unit_path() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME")
    config = (
        Path(base) if base and Path(base).is_absolute() else Path.home() / ".config"
    )
    return config / "systemd/user" / SERVICE_NAME


def install_user_unit(command: str) -> Path:
    if not Path(command).is_absolute():
        raise ValueError("service command must be an absolute path")
    path = user_unit_path()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    unit = (
        "[Unit]\n"
        "Description=Virt-FIDO2 TPM-backed authenticator\n"
        "ConditionPathExists=/dev/tpmrm0\n"
        "\n"
        "[Service]\n"
        "Type=simple\n"
        f"ExecStart={command} run\n"
        "Restart=on-failure\n"
        "RestartSec=2\n"
        "NoNewPrivileges=true\n"
        "PrivateUsers=false\n"
        "PrivatePIDs=false\n"
        "RestrictAddressFamilies=AF_UNIX AF_NETLINK\n"
        "\n"
        "[Install]\n"
        "WantedBy=default.target\n"
    )
    path.write_text(unit)
    path.chmod(0o600)
    return path


def manage_user_unit(operation: str) -> None:
    # Use systemd's user manager through pystemd for lifecycle operations.
    from pystemd.dbuslib import DBus
    from pystemd.systemd1 import Manager

    if operation not in {"enable", "disable", "start", "stop", "restart"}:
        raise ValueError(operation)
    with DBus(user_mode=True) as bus:
        manager = Manager(bus=bus)
        manager.load()
        manager.Manager.Reload()
        name = SERVICE_NAME.encode()
        if operation == "enable":
            manager.Manager.EnableUnitFiles([name], False, True)
            manager.Manager.StartUnit(name, b"replace")
        elif operation == "disable":
            manager.Manager.StopUnit(name, b"replace")
            manager.Manager.DisableUnitFiles([name], False)
        else:
            getattr(manager.Manager, operation.capitalize() + "Unit")(name, b"replace")
