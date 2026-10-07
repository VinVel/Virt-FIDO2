from __future__ import annotations

import base64
import hashlib
import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path

from src.config import data_dir


class _Helpers:
    @staticmethod
    def b64(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).decode("ascii")

    @staticmethod
    def unb64(data: str) -> bytes:
        return base64.urlsafe_b64decode(data.encode("ascii"))


@dataclass(frozen=True)
class Credential:
    credential_id: bytes
    rp_id: str
    user_id: bytes
    user_name: str
    display_name: str

    def to_json(self) -> dict:
        return {
            "credential_id": _Helpers.b64(self.credential_id),
            "rp_id": self.rp_id,
            "user_id": _Helpers.b64(self.user_id),
            "user_name": self.user_name,
            "display_name": self.display_name,
        }

    @classmethod
    def from_json(cls, value: dict) -> Credential:
        return cls(
            _Helpers.unb64(value["credential_id"]),
            value["rp_id"],
            _Helpers.unb64(value["user_id"]),
            value.get("user_name", ""),
            value.get("display_name", ""),
        )


class CredentialStore:
    def __init__(self, directory: Path | None = None):
        self.directory = directory or data_dir()
        self.path = self.directory / "credentials.json"
        self.revocations_path = self.directory / "revocations.json"

    def all(self) -> list[Credential]:
        try:
            data = self.path.read_text()
        except FileNotFoundError:
            return []
        value = json.loads(data)
        if value.get("version") != 1:
            raise ValueError("unsupported credential index version")
        return [Credential.from_json(item) for item in value["credentials"]]

    def for_rp(self, rp_id: str) -> list[Credential]:
        revocations = self.__revocations()
        return [
            item
            for item in self.all()
            if item.rp_id == rp_id
            and hashlib.sha256(item.credential_id).hexdigest() not in revocations
        ]

    def is_revoked(self, credential_id: bytes) -> bool:
        return hashlib.sha256(credential_id).hexdigest() in self.__revocations()

    def revoke(self, credential_id: bytes) -> bool:
        """Reject an ID from now on, then remove it from the local index."""
        fingerprint = hashlib.sha256(credential_id).hexdigest()
        revocations = self.__revocations()
        was_new = fingerprint not in revocations
        if was_new:
            revocations.add(fingerprint)
            self.__write(
                self.revocations_path,
                {"version": 1, "revocations": sorted(revocations)},
            )
        indexed = self.all()
        entries = [item for item in indexed if item.credential_id != credential_id]
        if len(entries) != len(indexed):
            self.__write(
                self.path,
                {"version": 1, "credentials": [e.to_json() for e in entries]},
            )
        return was_new

    def __revocations(self) -> set[str]:
        try:
            value = json.loads(self.revocations_path.read_text())
        except FileNotFoundError:
            return set()
        if (
            not isinstance(value, dict)
            or value.get("version") != 1
            or not isinstance(value.get("revocations"), list)
        ):
            raise ValueError("unsupported revocation index")
        records = value["revocations"]
        if any(
            not isinstance(item, str)
            or len(item) != 64
            or any(ch not in "0123456789abcdef" for ch in item)
            for item in records
        ):
            raise ValueError("invalid revocation fingerprint")
        return set(records)

    def save(self, credential: Credential) -> None:
        if self.is_revoked(credential.credential_id):
            raise ValueError("credential has been revoked")
        entries = []
        for item in self.all():
            if item.credential_id == credential.credential_id or (
                item.rp_id,
                item.user_id,
            ) == (credential.rp_id, credential.user_id):
                continue
            entries.append(item)
        entries.append(credential)
        self.__write(
            self.path,
            {"version": 1, "credentials": [e.to_json() for e in entries]},
        )

    def __write(self, path: Path, value: dict) -> None:
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.directory, 0o700)
        fd, tmp = tempfile.mkstemp(prefix=f".{path.stem}-", dir=self.directory)
        try:
            with os.fdopen(fd, "w") as stream:
                os.fchmod(stream.fileno(), 0o600)
                json.dump(value, stream)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(tmp, path)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
