# Passkey-tpm-linux

A small, per-user FIDO2 authenticator for Linux. It appears to browsers and local
applications as a virtual USB security key. Your desktop's Polkit agent verifies
each real registration or login, and the TPM creates and signs with the passkey key.
Browsers may also make silent `up=false` credential checks; those can use the
TPM without a prompt and do not claim user presence or verification.

This is an early implementation. It supports ES256 CTAP2 passkeys, including
discoverable credentials. It does not implement CTAP1/U2F or optional CTAP
extensions. Its virtual USB transport is presented as a roaming security key, 
so sites that insist on a platform-only authenticator may not offer it.

# Development

## Requirements
- [`uv`](https://docs.astral.sh/uv/)
- tpm2-tss
- systemd

The user service needs read/write access to the TPM resource manager and
virtual HID device. The included udev rules grant it to the active local user,
without `tss` group membership:

```sh
sudo install -Dm644 install/polkit/io.github.passkey-tpm-linux.policy \
  /usr/share/polkit-1/actions/io.github.passkey-tpm-linux.policy
sudo install -Dm644 install/udev/60-passkey-tpm-linux.rules \
  /etc/udev/rules.d/60-passkey-tpm-linux.rules
sudo udevadm control --reload-rules
sudo udevadm trigger --subsystem-match=misc --subsystem-match=tpmrm
```

Clone the repo, install Python dependencies and then the user service:

```sh
uv sync
uv run main.py install-user
uv run main.py enable
```

The generated user unit points at this checkout and its Python interpreter;
keep both paths in place. `uv run main.py stop`, `start`, `restart`, and
`disable` manage the service. Inspect logs with
`journalctl --user -u passkey-tpm-linux.service -f`.

The credential index is stored at
`$XDG_DATA_HOME/passkey-tpm-linux/credentials.json`, or
`~/.local/share/passkey-tpm-linux/credentials.json` by default. The index
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

```sh
uv run -m unittest discover -s tests -v
uv run ty check
uv run ruff check
```
# License


```
    Passkey-tpm-linux, a TPM-backed virtual FIDO2 passkey authenticator for Linux
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