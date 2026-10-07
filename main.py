"""Virt-FIDO2 command-line entry point."""

from __future__ import annotations

import base64
import binascii
import hashlib
import logging
import os
import shutil
import sys
from pathlib import Path
from typing import Annotated

import typer
from rich.box import ROUNDED
from rich.console import Console
from rich.table import Table

from src.config import APP_NAME, install_user_unit, manage_user_unit
from src.fidoauth import Authenticator
from src.polkit import authorize
from src.storage import CredentialStore
from src.system_files import install_system_files, uninstall_system_files
from src.tpm import MAGIC, MAX_ID, TPMKeys
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


def _credential_text(credential_id: bytes) -> str:
    return base64.urlsafe_b64encode(credential_id).decode("ascii")


def _resolve_credential_id(store: CredentialStore, identifier: str) -> bytes:
    matches = (
        [
            item
            for item in store.all()
            if _credential_text(item.credential_id).startswith(identifier)
        ]
        if len(identifier) >= 12
        else []
    )
    if len(matches) > 1:
        raise ValueError("credential ID prefix is ambiguous")
    if matches:
        return matches[0].credential_id
    try:
        credential_id = base64.b64decode(identifier, altchars=b"-_", validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("provide a full credential ID or a listed prefix") from exc
    if (
        _credential_text(credential_id) != identifier
        or not credential_id.startswith(MAGIC)
        or not 28 <= len(credential_id) <= MAX_ID
    ):
        raise ValueError("provide a full credential ID or a listed prefix")
    return credential_id


@app.command()
def delete(
    identifier: Annotated[
        str, typer.Argument(help="Full credential ID or unambiguous listed prefix")
    ],
) -> None:
    """Revoke a credential locally and remove it from the index."""
    store = CredentialStore()
    try:
        credential_id = _resolve_credential_id(store, identifier)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    created = store.revoke(credential_id)
    if created:
        typer.echo("Credential revoked locally and removed from the index, if present.")
    else:
        typer.echo("Credential was already revoked.")


@app.command("list")
def list_credentials() -> None:
    """Show credentials in the local index (not all non-discoverable keys)."""
    table = Table(
        title="Virt-FIDO2 credentials", box=ROUNDED, pad_edge=False, expand=True
    )
    for heading in ("Credential ID", "RP ID", "User ID", "User name", "Display name"):
        table.add_column(
            header=heading, style=f"#{hashlib.sha256(heading.encode()).hexdigest()[:6]}"
        )
    for item in CredentialStore().all():
        encoded = _credential_text(item.credential_id)
        shortened = encoded if len(encoded) <= 27 else f"{encoded[:24]}"
        table.add_row(
            shortened,
            item.rp_id,
            _credential_text(item.user_id),
            item.user_name,
            item.display_name,
        )
    Console().print(table)


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
