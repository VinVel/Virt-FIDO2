"""Virt-FIDO2 command-line entry point."""

from __future__ import annotations

import argparse
import logging
import os
import shutil
import sys
from pathlib import Path

from src.config import APP_NAME, install_user_unit, manage_user_unit
from src.fidoauth import Authenticator
from src.polkit import authorize
from src.storage import CredentialStore
from src.system_files import install_system_files, uninstall_system_files
from src.tpm import TPMKeys
from src.transport import FidoTransport


def main() -> None:
    parser = argparse.ArgumentParser(
        description="TPM-backed virtual FIDO2 authenticator"
    )
    parser.add_argument(
        "operation",
        choices=[
            "run",
            "install",
            "uninstall",
            "enable",
            "disable",
            "start",
            "stop",
            "restart",
        ],
    )
    args = parser.parse_args()
    if args.operation == "install":
        install_system_files()
        return
    if args.operation == "uninstall":
        uninstall_system_files()
        return
    if args.operation == "enable":
        invoked = Path(sys.argv[0])
        command = (
            str(invoked.absolute())
            if invoked.name == APP_NAME and invoked.is_file()
            else shutil.which(APP_NAME)
        )
        if command is None:
            parser.error(f"Install the {APP_NAME} command before enabling the service")
        install_user_unit(str(Path(command).absolute()))
    if args.operation != "run":
        manage_user_unit(args.operation)
        return
    logging.basicConfig(level=logging.INFO)
    if not os.environ.get("TPM2TOOLS_TCTI") and not os.access(
        "/dev/tpmrm0", os.R_OK | os.W_OK
    ):
        parser.error(
            "/dev/tpmrm0 is unavailable; install device rules and start a local user session"
        )
    authenticator = Authenticator(TPMKeys(), CredentialStore(), authorize)
    FidoTransport(authenticator).run()


if __name__ == "__main__":
    main()
