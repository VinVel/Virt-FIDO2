# Virt-FIDO2

A small, per-user FIDO2 authenticator for Linux. It appears to browsers and local
applications as a virtual USB security key. Your desktop's Polkit agent verifies
each real registration or login, and the TPM creates and signs with the passkey key.
Browsers may also make silent `up=false` credential checks; those can use the
TPM without a prompt and do not claim user presence or verification.

This is an early implementation. It supports ES256 CTAP2 passkeys, including
discoverable credentials. It does not implement CTAP1/U2F or optional CTAP
extensions. Its virtual USB transport is presented as a roaming security key, 
so sites that insist on a platform-only authenticator may not offer it.

The authenticator identifies its model with AAGUID
`7849e707-af46-4b9c-a766-68f5938cd846` and appears locally as
`Virt-FIDO2`. Websites can display that name only if their AAGUID metadata
recognizes it; the USB name itself is not sent to websites.

# Installation

```bash
uv tool install virt-fido2
virt-fido2 install
virt-fido2 enable
```

`virt-fido2 install` copies the bundled Polkit policy and udev rule into
system directories and reloads udev. 

`virt-fido2 enable` copies the bundled systemD service into the $HOME/.config/systemd/user
and runs the equivalent to `systemctl --user enable --now virt-fido2.service" (just in python)

Run `virt-fido2 --help` for the other commands.

# Development

## Requirements
- [`uv`](https://docs.astral.sh/uv/)
- tpm2-tss
- systemd

The user service needs read/write access to the TPM resource manager and
virtual HID device. The bundled udev rule grants it to the active local user,
without `tss` group membership.

The credential index is stored at
`$XDG_DATA_HOME/virt-fido2/credentials.json`, or
`~/.local/share/virt-fido2/credentials.json` by default. The index
contains RP and user metadata plus opaque TPM-wrapped credential IDs. The
private signing key remains protected by the TPM. Back up this file if you
want discoverable credentials to remain findable after restoring your home
directory. The TPM-bound credentials cannot be transferred to another TPM.

Polkit gates operations performed by this service; it is not part of the TPM
key's authorization policy. A process that obtains both a credential ID and
direct access to the same TPM could bypass this service's prompt. The TPM
still prevents export of the private signing key. Protect your user session
and credential index accordingly.

## Commands

```bash
uv run -m unittest discover -s tests -v
uv run ty check
uv run ruff check
```
# License


```
    Virt-FIDO2, a TPM-backed virtual FIDO2 passkey authenticator for Linux
    Copyright (C) 2026 VinVel


    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program. If not, see <https://www.gnu.org/licenses/>.
```
