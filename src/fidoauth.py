from __future__ import annotations

import hashlib
import os
import time
from collections.abc import Callable, Mapping
from typing import Protocol, cast

from cryptography.hazmat.primitives.asymmetric import ec, rsa
from fido2 import cbor
from fido2.cose import ES256, RS256, CoseKey
from fido2.ctap import CtapError
from fido2.ctap2 import Ctap2
from fido2.webauthn import AttestedCredentialData, AuthenticatorData

from src.config import AUTHENTICATOR_AAGUID
from src.outliers import should_store_discoverable
from src.polkit import AuthorizationDenied
from src.storage import Credential, CredentialStore
from src.tpm import InvalidCredential

ERR = CtapError.ERR
FLAG = AuthenticatorData.FLAG


class KeyBackend(Protocol):
    def create(self, rp_hash: bytes, algorithm: int, /) -> tuple[bytes, CoseKey]: ...
    def matches(self, credential_id: bytes, rp_hash: bytes, /) -> bool: ...
    def sign(self, credential_id: bytes, rp_hash: bytes, digest: bytes, /) -> bytes: ...


class ProtocolError(Exception):
    def __init__(self, status: int):
        self.status = int(status)
        # CTAP status codes are one-byte values; 02x prints two hex digits
        # (for example, 0x27 is CTAP2_ERR_OPERATION_DENIED).
        super().__init__(f"CTAP status 0x{self.status:02x}")


class _Helpers:
    @staticmethod
    def require(value: object, kind: type, status=ERR.INVALID_CBOR):
        if not isinstance(value, kind):
            raise ProtocolError(status)
        return value

    @staticmethod
    def required(mapping: Mapping, key: object, kind: type):
        try:
            value = mapping[key]
        except KeyError as exc:
            raise ProtocolError(ERR.MISSING_PARAMETER) from exc
        return _Helpers.require(value, kind)


class Authenticator:
    def __init__(
        self, keys: KeyBackend, store: CredentialStore, verify_user: Callable[[], None]
    ):
        self.keys = keys
        self.store = store
        self.verify_user = verify_user
        self._next: list[tuple[Credential, bytes, bytes, bool, bool]] = []
        self._next_until = 0.0
        self._next_channel: int | None = None

    def handle(self, request: bytes, channel: int | None = None) -> bytes:
        # Return a CTAP2 status byte followed by a CBOR response, if any.
        if not request:
            return bytes([ERR.INVALID_LENGTH])
        command, payload = request[0], request[1:]
        try:
            return b"\0" + cbor.encode(self.__dispatch(command, payload, channel))
        except ProtocolError as exc:
            return bytes([exc.status])
        except (
            AuthorizationDenied,
            TimeoutError,
            InvalidCredential,
            OSError,
            ValueError,
        ):
            return bytes([ERR.OPERATION_DENIED])

    def __dispatch(self, command: int, payload: bytes, channel: int | None) -> dict:
        if command == Ctap2.CMD.GET_INFO:
            return self.__info()
        if command == Ctap2.CMD.GET_NEXT_ASSERTION:
            return self.__next_assertion(channel)

        # Any other command ends a pending getNextAssertion sequence.
        self._next.clear()
        self._next_channel = None
        if command not in (Ctap2.CMD.MAKE_CREDENTIAL, Ctap2.CMD.GET_ASSERTION):
            raise ProtocolError(ERR.INVALID_COMMAND)
        try:
            params = cbor.decode(payload)
        except Exception as exc:
            raise ProtocolError(ERR.INVALID_CBOR) from exc
        params = cast(dict, _Helpers.require(params, dict))
        if command == Ctap2.CMD.MAKE_CREDENTIAL:
            return self.__make(params)
        return self.__assert(params, channel)

    def __verify(self) -> None:
        try:
            self.verify_user()
        except (AuthorizationDenied, TimeoutError):
            # Bare raise re-raises the caught denial or timeout unchanged.
            raise
        except Exception as exc:
            raise AuthorizationDenied(str(exc)) from exc

    @staticmethod
    def __info() -> dict:
        # Numeric keys are CTAP2 authenticatorGetInfo response fields.
        return {
            1: ["FIDO_2_0"],  # Supported protocol versions.
            3: AUTHENTICATOR_AAGUID,  # Stable Virt-FIDO2 model identifier.
            4: {  # Supported authenticator options.
                "rk": True,  # Discoverable (resident) credentials.
                "up": True,  # User presence on interactive operations.
                "uv": True,  # User verification via Polkit.
                "plat": False,  # Roaming device, not a platform authenticator.
            },
            5: 1200,  # Maximum CTAP message size in bytes.
            6: [2],  # Advertised PIN/UV protocol version.
            9: ["usb"],  # Transport presented to clients.
            10: [{"type": "public-key", "alg": algorithm} for algorithm in (-7, -257)],
        }

    def __make(self, request: Mapping) -> dict:
        client_hash = _Helpers.required(request, 1, bytes)
        rp = _Helpers.required(request, 2, dict)
        user = _Helpers.required(request, 3, dict)
        algorithms = _Helpers.required(request, 4, list)
        rp_id = _Helpers.required(rp, "id", str)
        user_id = _Helpers.required(user, "id", bytes)
        if len(client_hash) != 32 or not rp_id or not user_id:
            raise ProtocolError(ERR.INVALID_PARAMETER)
        # CODEX: Use an iterative approach instead of a declarative approach
        algorithm = next(
            (
                p["alg"]
                for p in algorithms
                if isinstance(p, dict)
                and p.get("type") == "public-key"
                and p.get("alg") in (-7, -257)
            ),
            None,
        )
        if algorithm is None:
            raise ProtocolError(ERR.UNSUPPORTED_ALGORITHM)
        if request.get(6):
            raise ProtocolError(ERR.UNSUPPORTED_OPTION)
        options = _Helpers.require(request.get(7, {}), dict)
        rp_hash = hashlib.sha256(rp_id.encode()).digest()
        self.__verify()
        # FIDO 2.0 clients use a synthetic makeCredential to select a device.
        # It must not leave a real TPM credential behind.
        # Key 8 is pinUvAuthParam. An empty value is a client's probe for
        # authenticator selection, not permission to create a credential.
        if request.get(8) == b"":
            raise ProtocolError(ERR.PIN_AUTH_INVALID)
        # python-fido2 also probes selection with a .dummy RP/user pair.
        # Return a disposable attestation without creating a TPM key.
        if rp_id == ".dummy" and user.get("name") == "dummy":
            public = {
                -7: lambda: ec.generate_private_key(ec.SECP256R1()).public_key(),
                -257: lambda: rsa.generate_private_key(65537, 2048).public_key(),
            }[algorithm]()
            attested = AttestedCredentialData.create(
                AUTHENTICATOR_AAGUID,
                os.urandom(32),
                {-7: ES256, -257: RS256}[algorithm].from_cryptography_key(public),
            )
            auth_data = AuthenticatorData.create(
                rp_hash, FLAG.UP | FLAG.UV | FLAG.AT, 0, attested
            )
            return {1: "none", 2: bytes(auth_data), 3: {}}
        for descriptor in _Helpers.require(request.get(5, []), list):
            if (
                isinstance(descriptor, dict)
                and isinstance(descriptor.get("id"), bytes)
                and not self.store.is_revoked(descriptor["id"])
                and self.keys.matches(descriptor["id"], rp_hash)
            ):
                raise ProtocolError(ERR.CREDENTIAL_EXCLUDED)
        credential_id, cose_key = self.keys.create(rp_hash, algorithm)
        attested = AttestedCredentialData.create(
            AUTHENTICATOR_AAGUID, credential_id, cose_key
        )
        auth_data = AuthenticatorData.create(
            rp_hash, FLAG.UP | FLAG.UV | FLAG.AT, 0, attested
        )
        if should_store_discoverable(rp_id, options.get("rk", False) is True):
            self.store.save(
                Credential(
                    credential_id,
                    rp_id,
                    user_id,
                    user.get("name", ""),
                    user.get("displayName", ""),
                )
            )
        return {1: "none", 2: bytes(auth_data), 3: {}}

    def __assert(self, request: Mapping, channel: int | None) -> dict:
        rp_id = _Helpers.required(request, 1, str)
        client_hash = _Helpers.required(request, 2, bytes)
        if not rp_id or len(client_hash) != 32:
            raise ProtocolError(ERR.INVALID_PARAMETER)
        if request.get(4):
            raise ProtocolError(ERR.UNSUPPORTED_OPTION)
        options = _Helpers.require(request.get(5, {}), dict)
        rp_hash = hashlib.sha256(rp_id.encode()).digest()
        allow_list = request.get(3)
        candidates: list[Credential] = []
        if allow_list:
            for descriptor in _Helpers.require(allow_list, list):
                if isinstance(descriptor, dict) and isinstance(
                    descriptor.get("id"), bytes
                ):
                    cid = descriptor["id"]
                    if not self.store.is_revoked(cid):
                        candidates.append(Credential(cid, rp_id, b"", "", ""))
        else:
            candidates = self.store.for_rp(rp_id)
        if not candidates:
            raise ProtocolError(ERR.NO_CREDENTIALS)
        want_up = options.get("up", True) is not False
        want_uv = options.get("uv", False) is True
        verified = False
        if want_up or want_uv:
            self.__verify()
            verified = True
        # Normal requests authenticate before any TPM operation. A silent
        # up=false preflight intentionally has no prompt and must not claim UV.
        candidates = [
            c for c in candidates if self.keys.matches(c.credential_id, rp_hash)
        ]
        if not candidates:
            raise ProtocolError(ERR.NO_CREDENTIALS)
        self._next = [
            (c, rp_hash, client_hash, verified, want_up) for c in candidates[1:]
        ]
        self._next_channel = channel
        self._next_until = time.monotonic() + 30
        result = self.__assertion(
            candidates[0], rp_hash, client_hash, verified, want_up
        )
        if len(candidates) > 1:
            result[5] = len(candidates)
        return result

    def __next_assertion(self, channel: int | None) -> dict:
        if channel != self._next_channel:
            raise ProtocolError(ERR.NOT_ALLOWED)
        if not self._next or time.monotonic() > self._next_until:
            self._next.clear()
            self._next_channel = None
            raise ProtocolError(ERR.NOT_ALLOWED)
        credential, rp_hash, client_hash, verified, want_up = self._next.pop(0)
        return self.__assertion(credential, rp_hash, client_hash, verified, want_up)

    def __assertion(
        self,
        credential: Credential,
        rp_hash: bytes,
        client_hash: bytes,
        verified: bool,
        want_up: bool,
    ) -> dict:
        if self.store.is_revoked(credential.credential_id):
            raise ProtocolError(ERR.NO_CREDENTIALS)
        flags = FLAG(0)
        if want_up and verified:
            flags |= FLAG.UP
        if verified:
            flags |= FLAG.UV
        auth_data = AuthenticatorData.create(rp_hash, flags, 0)
        digest = hashlib.sha256(bytes(auth_data) + client_hash).digest()
        signature = self.keys.sign(credential.credential_id, rp_hash, digest)
        result = {
            1: {"type": "public-key", "id": credential.credential_id},
            2: bytes(auth_data),
            3: signature,
        }
        if credential.user_id:
            result[4] = {
                "id": credential.user_id,
                "name": credential.user_name,
                "displayName": credential.display_name,
            }
        return result
