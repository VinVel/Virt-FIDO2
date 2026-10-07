"""CTAP HID framing without requiring /dev/uhid in the test process."""

import struct
import unittest
from typing import cast
from unittest.mock import patch

from fido2.hid import CTAPHID

from src.transport import BROADCAST, FidoDevice, FidoTransport


class Device:
    def __init__(self):
        self.reports = []

    def call_input_event(self, report):
        self.reports.append(bytes(report))


class Authenticator:
    def handle(self, request, channel=None):
        return b"\0" + request[1:]


def packet(channel, command, payload):
    return (
        struct.pack(">IBH", channel, command | 0x80, len(payload)) + payload[:57]
    ).ljust(64, b"\0")


class FramingTest(unittest.TestCase):
    def setUp(self):
        self.transport = FidoTransport(Authenticator())
        self.addCleanup(self.transport.executor.shutdown, wait=True)
        self.device = Device()
        self.transport.device = cast(FidoDevice, self.device)

    def test_init_and_multiframe_ping(self):
        nonce = b"12345678"
        self.transport._receive(packet(BROADCAST, CTAPHID.INIT, nonce))
        response = self.device.reports.pop()
        self.assertEqual(response[7:15], nonce)
        channel = struct.unpack_from(">I", response, 15)[0]
        self.assertIn(channel, self.transport.channels)
        payload = bytes(range(100))
        self.transport._receive(packet(channel, CTAPHID.PING, payload))
        self.transport._receive(
            (struct.pack(">IB", channel, 0) + payload[57:]).ljust(64, b"\0")
        )
        self.assertEqual(len(self.device.reports), 2)
        first, second = self.device.reports
        self.assertEqual(first[4], CTAPHID.PING | 0x80)
        self.assertEqual(struct.unpack_from(">H", first, 5)[0], len(payload))
        self.assertEqual(first[7:] + second[5 : 5 + 43], payload)

    def test_bad_sequence_is_rejected(self):
        channel = 17
        self.transport.channels.add(channel)
        self.transport._receive(packet(channel, CTAPHID.PING, bytes(100)))
        self.transport._receive(
            (struct.pack(">IB", channel, 1) + bytes(43)).ljust(64, b"\0")
        )
        response = self.device.reports.pop()
        self.assertEqual(response[4], CTAPHID.ERROR | 0x80)
        self.assertEqual(response[7], 0x04)

    def test_cbor_command_reaches_authenticator(self):
        channel = 17
        self.transport.channels.add(channel)
        self.transport._receive(packet(channel, CTAPHID.CBOR, b"\x04"))
        assert self.transport.active is not None
        self.transport.active[1].result(timeout=1)
        self.transport._poll_active()
        response = self.device.reports.pop()
        self.assertEqual(response[4], CTAPHID.CBOR | 0x80)
        self.assertEqual(response[7], 0)

    def test_executor_shutdown_when_device_creation_fails(self):
        with (
            patch("src.transport.FidoDevice", side_effect=RuntimeError("failed")),
            patch.object(self.transport.executor, "shutdown") as shutdown,
            self.assertRaisesRegex(RuntimeError, "failed"),
        ):
            self.transport.run()
        shutdown.assert_called_once_with(wait=False, cancel_futures=True)


if __name__ == "__main__":
    unittest.main()
