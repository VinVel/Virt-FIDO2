"""Passkey TPM Linux command-line entry point."""

from __future__ import annotations

import argparse
import logging
import os
import sys

from src.config import install_user_unit, manage_user_unit
from src.fidoauth import Authenticator
from src.polkit import authorize
from src.storage import CredentialStore
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
            "install-user",
            "enable",
            "disable",
            "start",
            "stop",
            "restart",
        ],
    )
    args = parser.parse_args()
    if args.operation == "install-user":
        print(install_user_unit(sys.executable))
        return
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
