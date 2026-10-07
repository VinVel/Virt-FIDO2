"""Virt-FIDO2 command-line entry point."""

from __future__ import annotations

import logging
import os
import shutil
import sys
from pathlib import Path

import typer

from src.config import APP_NAME, install_user_unit, manage_user_unit
from src.fidoauth import Authenticator
from src.polkit import authorize
from src.storage import CredentialStore
from src.system_files import install_system_files, uninstall_system_files
from src.tpm import TPMKeys
from src.transport import FidoTransport

app = typer.Typer(
    help="TPM-backed virtual FIDO2 authenticator",
    no_args_is_help=True,
    add_completion=False,
    context_settings={
        # Enable both -h and --help via context_settings
        "help_option_names": ["-h", "--help"]
    },
)


@app.command()
def install() -> None:
    """Install the system Polkit policy and udev rule."""
    install_system_files()


@app.command()
def uninstall() -> None:
    """Remove the system Polkit policy and udev rule."""
    uninstall_system_files()


@app.command()
def enable() -> None:
    """Create, enable, and start the user service."""
    invoked = Path(sys.argv[0])
    command = (
        str(invoked.absolute())
        if invoked.name == APP_NAME and invoked.is_file()
        else shutil.which(APP_NAME)
    )
    if command is None:
        typer.echo(
            f"Install the {APP_NAME} command before enabling the service", err=True
        )
        raise typer.Exit(code=2)
    install_user_unit(str(Path(command).absolute()))
    manage_user_unit("enable")


@app.command()
def disable() -> None:
    """Stop and disable the user service."""
    manage_user_unit("disable")


@app.command()
def start() -> None:
    """Start the user service."""
    manage_user_unit("start")


@app.command()
def stop() -> None:
    """Stop the user service."""
    manage_user_unit("stop")


@app.command()
def restart() -> None:
    """Restart the user service."""
    manage_user_unit("restart")


@app.command()
def run() -> None:
    """Run the virtual authenticator (normally started by systemd)."""
    logging.basicConfig(level=logging.INFO)
    if not os.environ.get("TPM2TOOLS_TCTI") and not os.access(
        "/dev/tpmrm0", os.R_OK | os.W_OK
    ):
        typer.echo(
            "/dev/tpmrm0 is unavailable; install device rules and start a local user session",
            err=True,
        )
        raise typer.Exit(code=2)
    authenticator = Authenticator(TPMKeys(), CredentialStore(), authorize)
    FidoTransport(authenticator).run()


def main() -> None:
    app()


if __name__ == "__main__":
    main()
