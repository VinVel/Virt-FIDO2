from __future__ import annotations

import logging
import os
import queue
import struct
import time
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Protocol, cast

from fido2.hid import CAPABILITY, CTAPHID
from hidtools.uhid import UHIDDevice


class CommandHandler(Protocol):
    def handle(self, request: bytes, channel: int | None = None) -> bytes: ...


LOG = logging.getLogger(__name__)
# HID report descriptor for a FIDO authenticator: 06 d0 f1 selects the
# FIDO Alliance usage page (0xF1D0), 09 01 selects the authenticator usage,
# and a1 01/c0 wrap the application collection. The 09 20/81 02 and
# 09 21/91 02 pairs declare input and output reports; 15 00, 26 ff 00,
# 75 08, and 95 40 define unsigned 8-bit fields, 64 bytes per report.
REPORT_DESCRIPTOR = bytes.fromhex(
    "06 d0 f1 09 01 a1 01 09 20 15 00 26 ff 00 75 08 95 40 81 02 "
    "09 21 15 00 26 ff 00 75 08 95 40 91 02 c0"
)
REPORT_SIZE = 64  # Bytes in each CTAP HID input/output report.
MAX_MESSAGE = 1200  # Largest assembled CTAP message we accept.
BROADCAST = 0xFFFFFFFF  # All-ones CTAP HID channel used for INIT.


@dataclass
class _Assembly:
    command: int
    size: int
    data: bytearray = field(default_factory=bytearray)
    sequence: int = 0
    started: float = field(default_factory=time.monotonic)


class FidoDevice(UHIDDevice):
    def __init__(self, incoming: queue.Queue[bytes]):
        super().__init__()
        self.name = "Passkey TPM Linux"
        self.phys = "passkey-tpm-linux"
        # UHID bus type 0x03 is USB; the remaining values identify this
        # virtual device to HID clients (vendor 0x1209, product 0xF1D0).
        self.info = (0x03, 0x1209, 0xF1D0)
        self.rdesc = REPORT_DESCRIPTOR
        self.incoming = incoming

    def output_report(self, data: list[int], size: int, rtype: int) -> None:
        if rtype == self.UHID_OUTPUT_REPORT:
            packet = bytes(data[:size])
            if len(packet) == 65 and packet[0] == 0:
                packet = packet[1:]
            if len(packet) == REPORT_SIZE:
                self.incoming.put(packet)


class FidoTransport:
    def __init__(self, authenticator: CommandHandler):
        self.authenticator = authenticator
        self.incoming: queue.Queue[bytes] = queue.Queue()
        self.assemblies: dict[int, _Assembly] = {}
        self.channels: set[int] = set()
        self.executor = ThreadPoolExecutor(max_workers=1)
        self.active: tuple[int, Future[bytes]] | None = None
        self.cancelled = False
        self.keepalive_at = 0.0
        self.device: FidoDevice | None = None

    def __send(self, channel: int, command: int, payload: bytes) -> None:
        assert self.device is not None
        header = struct.pack(">IBH", channel, command | 0x80, len(payload))
        self.device.call_input_event((header + payload[:57]).ljust(64, b"\0"))
        for sequence, offset in enumerate(range(57, len(payload), 59)):
            report = (
                struct.pack(">IB", channel, sequence) + payload[offset : offset + 59]
            )
            self.device.call_input_event(report.ljust(64, b"\0"))

    def __error(self, channel: int, code: int) -> None:
        self.__send(channel, CTAPHID.ERROR, bytes([code]))

    def __receive(self, packet: bytes) -> None:
        channel = struct.unpack_from(">I", packet)[0]
        marker = packet[4]
        if marker & 0x80:
            self.__start_message(channel, marker & 0x7F, packet)
            return

        self.__continue_message(channel, marker, packet)

    def __start_message(self, channel: int, command: int, packet: bytes) -> None:
        size = struct.unpack_from(">H", packet, 5)[0]
        if size > MAX_MESSAGE:
            self.__error(channel, 0x03)
            return
        assembly = _Assembly(command, size, bytearray(packet[7 : 7 + min(size, 57)]))
        if len(assembly.data) == size:
            self.__handle(channel, command, bytes(assembly.data))
            return
        self.assemblies[channel] = assembly

    def __continue_message(self, channel: int, marker: int, packet: bytes) -> None:
        assembly = self.assemblies.get(channel)
        if assembly is None or marker != assembly.sequence:
            self.assemblies.pop(channel, None)
            self.__error(channel, 0x04)
            return
        assembly.sequence += 1
        assembly.data.extend(
            packet[5 : 5 + min(59, assembly.size - len(assembly.data))]
        )
        if len(assembly.data) == assembly.size:
            self.assemblies.pop(channel)
            self.__handle(channel, assembly.command, bytes(assembly.data))

    def __handle(self, channel: int, command: int, payload: bytes) -> None:
        if command == CTAPHID.INIT:
            self.__init_channel(channel, payload)
            return
        if channel not in self.channels:
            self.__error(channel, 0x0B)
            return

        match command:
            case CTAPHID.CANCEL:
                if self.active and self.active[0] == channel:
                    self.cancelled = True
            case CTAPHID.PING:
                self.__send(channel, CTAPHID.PING, payload)
            case CTAPHID.CBOR:
                self.__start_command(channel, payload)
            case _:
                self.__error(channel, 0x01)

    def __init_channel(self, channel: int, payload: bytes) -> None:
        if len(payload) != 8:
            self.__error(channel, 0x03)
            return
        allocated = int.from_bytes(os.urandom(4), "big")
        while allocated in self.channels or allocated in (0, BROADCAST):
            allocated = int.from_bytes(os.urandom(4), "big")
        self.channels.add(allocated)
        reply = (
            payload
            + struct.pack(">I", allocated)
            + bytes([2, 1, 0, 0, int(CAPABILITY.CBOR | CAPABILITY.NMSG)])
        )
        self.__send(channel, CTAPHID.INIT, reply)

    def __start_command(self, channel: int, payload: bytes) -> None:
        if self.active is not None:
            self.__error(channel, 0x06)
            return
        self.cancelled = False
        self.active = (
            channel,
            self.executor.submit(self.authenticator.handle, payload, channel),
        )
        self.keepalive_at = time.monotonic() + 0.1

    def run(self) -> None:
        try:
            with FidoDevice(self.incoming) as raw_device:
                device = cast(FidoDevice, raw_device)
                self.device = device
                device.create_kernel_device()
                LOG.info("Virtual FIDO2 device created")
                while True:
                    self.__poll_once()
        finally:
            # Also runs when dispatch or device creation raises, or on Ctrl-C.
            self.executor.shutdown(wait=False, cancel_futures=True)

    def __poll_once(self) -> None:
        UHIDDevice.dispatch(50)
        while not self.incoming.empty():
            self.__receive(self.incoming.get_nowait())
        self.__poll_active()
        self.__expire_assemblies()

    def __poll_active(self) -> None:
        if self.active is None:
            return
        channel, future = self.active
        if not future.done():
            if time.monotonic() >= self.keepalive_at:
                self.__send(channel, CTAPHID.KEEPALIVE, b"\x02")
                self.keepalive_at = time.monotonic() + 0.1
            return
        self.active = None
        try:
            result = future.result()
        except Exception:
            LOG.exception("Authenticator operation failed")
            result = bytes([0x27])
        if not self.cancelled:
            self.__send(channel, CTAPHID.CBOR, result)

    def __expire_assemblies(self) -> None:
        for channel, assembly in list(self.assemblies.items()):
            if time.monotonic() - assembly.started > 3:
                self.assemblies.pop(channel)
                self.__error(channel, 0x05)
