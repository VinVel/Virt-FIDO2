"""Exercise the authenticator with the independent python-fido2 client and RP."""

from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from fido2 import cbor
from fido2.client import DefaultClientDataCollector, Fido2Client
from fido2.ctap import CtapDevice, CtapError
from fido2.ctap2 import Ctap2
from fido2.hid import CAPABILITY, CTAPHID
from fido2.server import Fido2Server
from fido2.webauthn import (
    AttestedCredentialData,
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from src.config import AUTHENTICATOR_AAGUID
from src.fidoauth import Authenticator
from src.polkit import AuthorizationDenied
from src.storage import CredentialStore


class FakeKeys:
    def __init__(self):
        self.keys = {}
        self.uses = 0

    def create(self, rp_hash):
        key = ec.generate_private_key(ec.SECP256R1())
        cid = hashlib.sha256(
            rp_hash + key.private_numbers().private_value.to_bytes(32)
        ).digest()
        self.keys[cid] = (rp_hash, key)
        public = key.public_key().public_numbers()
        return cid, public.x.to_bytes(32), public.y.to_bytes(32)

    def matches(self, cid, rp_hash):
        self.uses += 1
        return cid in self.keys and self.keys[cid][0] == rp_hash

    def sign(self, cid, rp_hash, digest):
        if not self.matches(cid, rp_hash):
            raise ValueError("wrong RP")
        return self.keys[cid][1].sign(digest, ec.ECDSA(Prehashed(hashes.SHA256())))


class Device(CtapDevice):
    def __init__(self, auth):
        self.auth = auth

    @property
    def capabilities(self):
        return CAPABILITY.CBOR | CAPABILITY.NMSG

    def call(self, cmd, data=b"", event=None, on_keepalive=None):
        assert cmd == CTAPHID.CBOR
        return self.auth.handle(data)

    @classmethod
    def list_devices(cls):
        return iter(())


class AuthenticatorTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.prompts = 0
        self.deny = False

        def verify():
            self.prompts += 1
            if self.deny:
                raise AuthorizationDenied("denied")

        self.keys = FakeKeys()
        self.auth = Authenticator(
            self.keys, CredentialStore(Path(self.temp.name)), verify
        )
        self.device = Device(self.auth)
        self.ctap = Ctap2(self.device)

    def test_model_aaguid_is_consistent_in_info_and_registration(self):
        self.assertEqual(bytes(self.ctap.get_info().aaguid), AUTHENTICATOR_AAGUID)
        self.assertEqual(len(AUTHENTICATOR_AAGUID), 16)
        for rp_id, user in (
            ("example.com", {"id": b"alice", "name": "alice"}),
            (".dummy", {"id": b"dummy", "name": "dummy"}),
        ):
            with self.subTest(rp_id=rp_id):
                result = self.ctap.make_credential(
                    bytes(32),
                    {"id": rp_id},
                    user,
                    [{"type": "public-key", "alg": -7}],
                )
                credential = result.auth_data.credential_data
                assert credential is not None
                self.assertEqual(bytes(credential.aaguid), AUTHENTICATOR_AAGUID)

    def test_fido2_client_and_server_round_trip(self):
        client = Fido2Client(
            self.device, DefaultClientDataCollector("https://example.com")
        )
        server = Fido2Server(
            PublicKeyCredentialRpEntity(id="example.com", name="Example")
        )
        options, state = server.register_begin(
            PublicKeyCredentialUserEntity(
                id=b"alice", name="alice", display_name="Alice"
            ),
            resident_key_requirement=ResidentKeyRequirement.REQUIRED,
            user_verification=UserVerificationRequirement.REQUIRED,
        )
        registration = client.make_credential(options["publicKey"])
        credential = server.register_complete(state, registration).credential_data
        assert isinstance(credential, AttestedCredentialData)
        options, state = server.authenticate_begin(
            [credential], user_verification=UserVerificationRequirement.REQUIRED
        )
        assertion = client.get_assertion(options["publicKey"]).get_response(0)
        server.authenticate_complete(state, [credential], assertion)
        self.assertEqual(self.prompts, 2)
        self.assertEqual(len(self.auth.store.for_rp("example.com")), 1)

    def test_denial_prevents_creation(self):
        self.deny = True
        with self.assertRaises(CtapError):
            self.ctap.make_credential(
                bytes(32),
                {"id": "example.com"},
                {"id": b"alice"},
                [{"type": "public-key", "alg": -7}],
            )
        self.assertEqual(self.keys.keys, {})

    def test_dispatch_reports_invalid_requests(self):
        self.assertEqual(self.auth.handle(b""), bytes([CtapError.ERR.INVALID_LENGTH]))
        self.assertEqual(
            self.auth.handle(b"\xff"), bytes([CtapError.ERR.INVALID_COMMAND])
        )
        self.assertEqual(
            self.auth.handle(bytes([Ctap2.CMD.MAKE_CREDENTIAL, 0xFF])),
            bytes([CtapError.ERR.INVALID_CBOR]),
        )

    def test_selection_does_not_create_credential(self):
        client = Fido2Client(
            self.device, DefaultClientDataCollector("https://example.com")
        )
        client.selection()
        self.assertEqual(self.prompts, 1)
        self.assertEqual(self.keys.keys, {})

    def test_denial_prevents_tpm_access_on_login(self):
        registration = self.ctap.make_credential(
            bytes(32),
            {"id": "example.com"},
            {"id": b"alice"},
            [{"type": "public-key", "alg": -7}],
            options={"rk": True},
        )
        assert registration.auth_data.credential_data is not None
        self.keys.uses = 0
        self.deny = True
        with self.assertRaises(CtapError):
            self.ctap.get_assertion(
                "example.com",
                bytes(32),
                [
                    {
                        "type": "public-key",
                        "id": registration.auth_data.credential_data.credential_id,
                    }
                ],
            )
        self.assertEqual(self.keys.uses, 0)

    def test_multiple_discoverable_accounts(self):
        for name in ("alice", "bob"):
            self.ctap.make_credential(
                bytes(32),
                {"id": "example.com"},
                {"id": name.encode(), "name": name},
                [{"type": "public-key", "alg": -7}],
                options={"rk": True},
            )
        assertions = self.ctap.get_assertions("example.com", bytes(32))
        self.assertEqual(len(assertions), 2)
        self.assertEqual(
            {a.user["id"] for a in assertions if a.user}, {b"alice", b"bob"}
        )

    def test_discord_rk_false_remains_discoverable(self):
        self.ctap.make_credential(
            bytes(32),
            {"id": "discord.com"},
            {"id": b"alice", "name": "alice"},
            [{"type": "public-key", "alg": -7}],
            options={"rk": False},
        )
        assertion = self.ctap.get_assertion(
            "discord.com", bytes(32), options={"uv": True}
        )
        assert assertion.user is not None
        self.assertEqual(assertion.user["id"], b"alice")

    def test_other_rp_rk_false_stays_non_discoverable(self):
        registration = self.ctap.make_credential(
            bytes(32),
            {"id": "example.com"},
            {"id": b"alice", "name": "alice"},
            [{"type": "public-key", "alg": -7}],
            options={"rk": False},
        )
        self.assertEqual(self.auth.store.for_rp("example.com"), [])
        with self.assertRaises(CtapError) as error:
            self.ctap.get_assertion("example.com", bytes(32), options={"uv": True})
        self.assertEqual(error.exception.code, CtapError.ERR.NO_CREDENTIALS)
        assert registration.auth_data.credential_data is not None
        assertion = self.ctap.get_assertion(
            "example.com",
            bytes(32),
            [
                {
                    "type": "public-key",
                    "id": registration.auth_data.credential_data.credential_id,
                }
            ],
        )
        self.assertIsNone(assertion.user)

    def test_revocation_rejects_site_supplied_non_discoverable_id(self):
        registration = self.ctap.make_credential(
            bytes(32),
            {"id": "example.com"},
            {"id": b"alice"},
            [{"type": "public-key", "alg": -7}],
            options={"rk": False},
        )
        assert registration.auth_data.credential_data is not None
        credential_id = registration.auth_data.credential_data.credential_id
        self.assertEqual(self.auth.store.all(), [])
        self.assertTrue(self.auth.store.revoke(credential_id))
        self.assertFalse(self.auth.store.revoke(credential_id))
        self.keys.uses = 0
        with self.assertRaises(CtapError) as error:
            self.ctap.get_assertion(
                "example.com",
                bytes(32),
                [{"type": "public-key", "id": credential_id}],
            )
        self.assertEqual(error.exception.code, CtapError.ERR.NO_CREDENTIALS)
        self.assertEqual(self.keys.uses, 0)
        fresh_store = CredentialStore(Path(self.temp.name))
        self.assertTrue(fresh_store.is_revoked(credential_id))

    def test_revocation_removes_discoverable_credential(self):
        registration = self.ctap.make_credential(
            bytes(32),
            {"id": "example.com"},
            {"id": b"alice"},
            [{"type": "public-key", "alg": -7}],
            options={"rk": True},
        )
        assert registration.auth_data.credential_data is not None
        credential_id = registration.auth_data.credential_data.credential_id
        self.assertEqual(len(self.auth.store.all()), 1)
        self.auth.store.revoke(credential_id)
        self.assertEqual(self.auth.store.all(), [])
        with self.assertRaises(CtapError) as error:
            self.ctap.get_assertion("example.com", bytes(32))
        self.assertEqual(error.exception.code, CtapError.ERR.NO_CREDENTIALS)
        replacement = self.ctap.make_credential(
            bytes(32),
            {"id": "example.com"},
            {"id": b"alice"},
            [{"type": "public-key", "alg": -7}],
            exclude_list=[{"type": "public-key", "id": credential_id}],
            options={"rk": True},
        )
        self.assertIsNotNone(replacement.auth_data.credential_data)

    def test_next_assertion_stays_on_original_channel(self):
        for name in ("alice", "bob"):
            self.ctap.make_credential(
                bytes(32),
                {"id": "example.com"},
                {"id": name.encode(), "name": name},
                [{"type": "public-key", "alg": -7}],
                options={"rk": True},
            )
        request = bytes([Ctap2.CMD.GET_ASSERTION]) + cbor.encode(
            {1: "example.com", 2: bytes(32)}
        )
        self.assertEqual(self.auth.handle(request, channel=1)[0], 0)
        next_request = bytes([Ctap2.CMD.GET_NEXT_ASSERTION])
        self.assertEqual(
            self.auth.handle(next_request, channel=2),
            bytes([CtapError.ERR.NOT_ALLOWED]),
        )
        self.assertEqual(self.auth.handle(next_request, channel=1)[0], 0)

    def test_silent_check_has_no_up_or_uv(self):
        result = self.ctap.make_credential(
            bytes(32),
            {"id": "example.com"},
            {"id": b"alice"},
            [{"type": "public-key", "alg": -7}],
            options={"rk": True},
        )
        assert result.auth_data.credential_data is not None
        self.prompts = 0
        assertion = self.ctap.get_assertion(
            "example.com",
            bytes(32),
            [
                {
                    "type": "public-key",
                    "id": result.auth_data.credential_data.credential_id,
                }
            ],
            options={"up": False},
        )
        self.assertEqual(self.prompts, 0)
        self.assertFalse(assertion.auth_data.is_user_present())
        self.assertFalse(assertion.auth_data.is_user_verified())

    def test_wrong_rp_has_no_credentials(self):
        result = self.ctap.make_credential(
            bytes(32),
            {"id": "example.com"},
            {"id": b"alice"},
            [{"type": "public-key", "alg": -7}],
        )
        assert result.auth_data.credential_data is not None
        cid = result.auth_data.credential_data.credential_id
        with self.assertRaises(CtapError) as context:
            self.ctap.get_assertion(
                "other.example", bytes(32), [{"type": "public-key", "id": cid}]
            )
        self.assertEqual(context.exception.code, CtapError.ERR.NO_CREDENTIALS)


if __name__ == "__main__":
    unittest.main()
