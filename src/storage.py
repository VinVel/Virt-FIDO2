from __future__ import annotations

import base64
import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path

from src.config import data_dir


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii")


def _unb64(data: str) -> bytes:
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
            "credential_id": _b64(self.credential_id),
            "rp_id": self.rp_id,
            "user_id": _b64(self.user_id),
            "user_name": self.user_name,
            "display_name": self.display_name,
        }

    @classmethod
    def from_json(cls, value: dict) -> Credential:
        return cls(
            _unb64(value["credential_id"]),
            value["rp_id"],
            _unb64(value["user_id"]),
            value.get("user_name", ""),
            value.get("display_name", ""),
        )


class CredentialStore:
    def __init__(self, directory: Path | None = None):
        self.directory = directory or data_dir()
        self.path = self.directory / "credentials.json"

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
        return [item for item in self.all() if item.rp_id == rp_id]

    def save(self, credential: Credential) -> None:
        entries = []
        for item in self.all():
            if item.credential_id == credential.credential_id or (
                item.rp_id,
                item.user_id,
            ) == (credential.rp_id, credential.user_id):
                continue
            entries.append(item)
        entries.append(credential)
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.directory, 0o700)
        fd, tmp = tempfile.mkstemp(prefix=".credentials-", dir=self.directory)
        try:
            with os.fdopen(fd, "w") as stream:
                os.fchmod(stream.fileno(), 0o600)
                json.dump(
                    {"version": 1, "credentials": [e.to_json() for e in entries]},
                    stream,
                )
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(tmp, self.path)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
