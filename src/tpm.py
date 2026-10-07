from __future__ import annotations

import hashlib
import os
import struct
from collections.abc import Iterator
from contextlib import contextmanager
from typing import cast

from tpm2_pytss import (
    ESAPI,
    ESYS_TR,
    TPM2_ALG,
    TPM2B_ECC_PARAMETER,
    TPM2B_PRIVATE,
    TPM2B_PUBLIC,
    TPMA_OBJECT,
    TPMT_SIG_SCHEME,
)

# Versioned prefix lets us reject credential IDs from other formats.
MAGIC = b"PTL1"
# Bound the size of the self-contained TPM key blobs accepted as a credential ID.
MAX_ID = 1024


class InvalidCredential(Exception):
    pass


def _parts(credential_id: bytes) -> tuple[bytes, TPM2B_PRIVATE, TPM2B_PUBLIC]:
    if (
        len(credential_id) < 28
        or len(credential_id) > MAX_ID
        or credential_id[:4] != MAGIC
    ):
        raise InvalidCredential("invalid credential ID")
    seed = credential_id[4:24]
    private_size, public_size = struct.unpack_from(">HH", credential_id, 24)
    if 28 + private_size + public_size != len(credential_id):
        raise InvalidCredential("invalid credential ID length")
    try:
        private, used_private = TPM2B_PRIVATE.unmarshal(
            credential_id[28 : 28 + private_size]
        )
        public, used_public = TPM2B_PUBLIC.unmarshal(credential_id[28 + private_size :])
    except Exception as exc:
        raise InvalidCredential("invalid TPM key blob") from exc
    if used_private != private_size or used_public != public_size:
        raise InvalidCredential("trailing TPM key data")
    return seed, private, public


def _parent_template(seed: bytes, rp_hash: bytes) -> TPM2B_PUBLIC:
    template = TPM2B_PUBLIC.parse(
        "ecc256", objectAttributes=TPMA_OBJECT.DEFAULT_TPM2_TOOLS_CREATEPRIMARY_ATTRS
    )
    digest = hashlib.sha512(b"passkey-tpm-linux parent v1" + rp_hash + seed).digest()
    template.publicArea.unique.ecc.x = TPM2B_ECC_PARAMETER(buffer=digest[:32])
    template.publicArea.unique.ecc.y = TPM2B_ECC_PARAMETER(buffer=digest[32:])
    return template


def _child_template() -> TPM2B_PUBLIC:
    return TPM2B_PUBLIC.parse(
        "ecc256:ecdsa-sha256",
        objectAttributes=TPMA_OBJECT.DEFAULT_TPM2_TOOLS_CREATE_ATTRS
        & ~TPMA_OBJECT.DECRYPT,
    )


class TPMKeys:
    def __init__(self, tcti: str | None = None):
        self.tcti = tcti or os.environ.get("TPM2TOOLS_TCTI") or "device:/dev/tpmrm0"

    @contextmanager
    def __context(self):
        with ESAPI(self.tcti) as esys:
            yield esys

    @contextmanager
    def __parent(self, esys: ESAPI, seed: bytes, rp_hash: bytes) -> Iterator[ESYS_TR]:
        parent, *_ = esys.create_primary(
            None, _parent_template(seed, rp_hash), cast(ESYS_TR, ESYS_TR.OWNER)
        )
        try:
            yield parent
        finally:
            esys.flush_context(parent)

    @contextmanager
    def __child(
        self,
        esys: ESAPI,
        parent: ESYS_TR,
        private: TPM2B_PRIVATE,
        public: TPM2B_PUBLIC,
    ) -> Iterator[ESYS_TR]:
        child = esys.load(parent, private, public)
        try:
            yield child
        finally:
            esys.flush_context(child)

    def create(self, rp_hash: bytes) -> tuple[bytes, bytes, bytes]:
        # Return credential ID and 32-byte public X/Y coordinates.
        if len(rp_hash) != 32:
            raise ValueError("RP hash must be SHA-256")
        seed = os.urandom(20)
        with self.__context() as esys, self.__parent(esys, seed, rp_hash) as parent:
            private, public, *_ = esys.create(parent, None, _child_template())
            with self.__child(esys, parent, private, public) as child:
                actual, *_ = esys.read_public(child)
                point = actual.publicArea.unique.ecc
                x, y = bytes(point.x), bytes(point.y)
        private_bytes, public_bytes = private.marshal(), public.marshal()
        credential_id = (
            MAGIC
            + seed
            + struct.pack(">HH", len(private_bytes), len(public_bytes))
            + private_bytes
            + public_bytes
        )
        if len(credential_id) > MAX_ID:
            raise RuntimeError("TPM key blob exceeds credential ID size")
        return credential_id, x.rjust(32, b"\0"), y.rjust(32, b"\0")

    def sign(self, credential_id: bytes, rp_hash: bytes, digest: bytes) -> bytes:
        # Sign a SHA-256 digest; Load verifies the RP binding and this TPM.
        if len(rp_hash) != 32 or len(digest) != 32:
            raise ValueError("expected SHA-256 digests")
        seed, private, public = _parts(credential_id)
        try:
            with (
                self.__context() as esys,
                self.__parent(esys, seed, rp_hash) as parent,
                self.__child(esys, parent, private, public) as child,
            ):
                signature = esys.sign(
                    child, digest, TPMT_SIG_SCHEME(scheme=TPM2_ALG.NULL)
                )
                return bytes(signature)
        except InvalidCredential:
            raise
        except Exception as exc:
            raise InvalidCredential(
                "credential cannot be loaded or signed by this TPM for this RP"
            ) from exc

    def matches(self, credential_id: bytes, rp_hash: bytes) -> bool:
        # Check a key handle without creating an externally visible signature.
        try:
            self.sign(credential_id, rp_hash, b"\0" * 32)
            return True
        except (InvalidCredential, ValueError):
            return False
