#!/usr/bin/env python3
"""Examples calling every UDS service of godocan over CAN (ISO-TP).

Start the server with the default configuration, then run this script:

    make run                       # or: go run ./cmd/server
    python examples/client.py      # every section
    python examples/client.py security memory   # only some sections
    python examples/client.py --list

The examples match the values of ./config.yaml (addresses, DIDs, DTCs,
routines, security levels...). Each section enters the session and security
level it needs, so sections can run on their own. Services implemented by
udsoncan are called through its client; the others (0x24, 0x2A, 0x84, 0x86)
are sent as raw bytes. The tester uses the Linux kernel ISO-TP stack.

Requirements: pip install -r tests/e2e/requirements.txt
"""

import argparse
import hashlib
import hmac
import socket
import struct
import sys
import time

import isotp
import udsoncan
from udsoncan import (
    Baudrate,
    CommunicationType,
    DataFormatIdentifier,
    DynamicDidDefinition,
    Filesize,
    MemoryLocation,
)
from udsoncan.client import Client
from udsoncan.connections import IsoTPSocketConnection
from udsoncan.exceptions import NegativeResponseException

# --- values from config.yaml -------------------------------------------------

LEVEL_EXTENDED = 0x01  # fixed seed, key = seed XOR AA BB CC DD
LEVEL_PROGRAMMING = 0x11  # random seed, key = seed + 0x12345678
AUTH_SECRET = bytes.fromhex("0011223344556677")  # authentication (ACR)
SDT_SECRET = bytes.fromhex("C0FFEE")  # secured_data_transmission


def security_algo(level, seed, params=None):
    """Key algorithms configured in config.yaml."""
    if level == LEVEL_EXTENDED:
        return bytes(s ^ m for s, m in zip(seed, bytes.fromhex("AABBCCDD")))
    if level == LEVEL_PROGRAMMING:
        value = (int.from_bytes(seed, "big") + 0x12345678) % (1 << (8 * len(seed)))
        return value.to_bytes(len(seed), "big")
    raise ValueError(f"unknown security level 0x{level:02X}")


def mem(addr, size):
    return MemoryLocation(addr, size, address_format=32, memorysize_format=32)


# --- output helpers ------------------------------------------------------------

def hexs(data):
    return " ".join(f"{b:02X}" for b in data) if data else "-"


class Examples:
    def __init__(self, conn, client, args):
        self.conn = conn
        self.client = client
        self.args = args
        self.failures = 0

    def step(self, title, fn):
        """Runs one example and prints its outcome without stopping on errors."""
        try:
            result = fn()
            print(f"  ✓ {title}" + (f": {result}" if result not in (None, "") else ""))
        except NegativeResponseException as e:
            self.failures += 1
            print(f"  ✗ {title}: NRC 0x{e.response.code:02X} ({e.response.code_name})")
        except Exception as e:  # noqa: BLE001 - examples report every failure
            self.failures += 1
            print(f"  ✗ {title}: {type(e).__name__}: {e}")

    # raw UDS for services udsoncan does not implement
    def raw(self, request, timeout=2.0):
        self.conn.send(bytes(request))
        return self.receive(timeout)

    def receive(self, timeout=2.0):
        """Receives the next UDS message, skipping response pending (0x78)."""
        while True:
            data = self.conn.wait_frame(timeout=timeout, exception=True)
            if len(data) == 3 and data[0] == 0x7F and data[2] == 0x78:
                continue
            return data

    def send_frame(self, can_id, data):
        """Sends one raw CAN frame (padded to 8 bytes with 0xCC)."""
        with socket.socket(socket.AF_CAN, socket.SOCK_RAW, socket.CAN_RAW) as s:
            s.bind((self.args.interface,))
            s.send(struct.pack("=IB3x8s", can_id, 8, bytes(data).ljust(8, b"\xCC")))

    def check_raw(self, request, expect_sid):
        resp = self.raw(request)
        if resp[0] != expect_sid:
            raise RuntimeError(f"unexpected response {hexs(resp)}")
        return hexs(resp)

    # session helpers
    def extended(self, unlock=False):
        self.client.change_session(0x03)
        if unlock:
            self.client.unlock_security_access(LEVEL_EXTENDED)

    def programming(self):
        self.client.change_session(0x03)  # programming is only reachable from extended
        self.client.change_session(0x02)
        self.client.unlock_security_access(LEVEL_PROGRAMMING)

    def default(self):
        self.client.change_session(0x01)

    # --- sections ----------------------------------------------------------

    def isotp_layer(self):
        """ISO-TP: single frame, segmented request and response, functional request."""
        self.step("single frame: TesterPresent", lambda: hexs(self.raw([0x3E, 0x00])))
        self.step("segmented response: VIN (first + consecutive frames)",
                  lambda: self.raw([0x22, 0xF1, 0x90])[3:].decode())
        self.step("segmented request and response: 3 DIDs in one request",
                  lambda: f"{len(self.raw([0x22, 0xF1, 0x90, 0xF1, 0x8C, 0xF1, 0x89]))} bytes")
        self.step(f"functional request on 0x{self.args.functional:X}", self._functional_tester_present)

    def session(self):
        """0x10 DiagnosticSessionControl, 0x3E TesterPresent, functional addressing."""
        c = self.client
        self.step("0x10 extended session", lambda: hexs(c.change_session(0x03).data))
        self.step("0x10 programming session (from extended)", lambda: hexs(c.change_session(0x02).data))
        self.step("0x10 default session", lambda: hexs(c.change_session(0x01).data))
        self.step("0x3E TesterPresent", lambda: hexs(c.tester_present().original_payload))
        self.step("0x3E TesterPresent, suppressed response", self._suppressed_tester_present)
        self.step("0x3E TesterPresent, functional request", self._functional_tester_present)

    def _suppressed_tester_present(self):
        with self.client.suppress_positive_response:
            self.client.tester_present()
        return "no response expected"

    def _functional_tester_present(self):
        self.send_frame(self.args.functional, [0x02, 0x3E, 0x00])  # single frame
        return hexs(self.receive())

    def reset(self):
        """0x11 ECUReset."""
        c = self.client
        self.step("0x11 hard reset", lambda: hexs(c.ecu_reset(0x01).data))
        self.step("0x11 soft reset", lambda: hexs(c.ecu_reset(0x03).data))
        self.step("0x11 enable rapid power shutdown",
                  lambda: f"power down time={c.ecu_reset(0x04).service_data.powerdown_time}s")

    def security(self):
        """0x27 SecurityAccess and 0x29 Authentication."""
        c = self.client
        self.step("0x10 extended session", lambda: self.extended())
        self.step("0x27 request seed level 0x01", lambda: hexs(c.request_seed(LEVEL_EXTENDED).service_data.seed))
        self.step("0x27 unlock level 0x01 (seed + key)", lambda: hexs(c.unlock_security_access(LEVEL_EXTENDED).data))
        self.step("0x22 read secret DID 0x0200 (needs level 0x01)", lambda: hexs(self.raw([0x22, 0x02, 0x00])))
        self.step("0x29 authentication configuration",
                  lambda: f"0x{c.authentication_configuration().service_data.return_value:02X} (0x04 = ACR)")
        self.step("0x29 ACR: request challenge + verify proof of ownership", self._acr)
        self.step("0x29 deAuthenticate", lambda: hexs(c.deauthenticate().data))
        self.step("0x10 default session", self.default)

    def _acr(self):
        algorithm = bytes(16)
        resp = self.client.request_challenge_for_authentication(communication_configuration=0, algorithm_indicator=algorithm)
        proof = hmac.new(AUTH_SECRET, resp.service_data.challenge_server, hashlib.sha256).digest()
        resp = self.client.authentication(0x06, algorithm_indicator=algorithm, proof_of_ownership_client=proof,
                                          challenge_client=b"", additional_parameter=b"")
        return f"return value 0x{resp.service_data.return_value:02X} (0x12 = ownership verified)"

    def data(self):
        """0x22, 0x2E, 0x24, 0x2C, 0x2A: data identifiers."""
        c = self.client
        self.step("0x22 read VIN, serial and software version", lambda: c.read_data_by_identifier(
            [0xF190, 0xF18C, 0xF189]).service_data.values)
        self.step("0x10 extended session + unlock level 0x01", lambda: self.extended(unlock=True))
        self.step("0x22 read calibration 0x0100 (extended only)",
                  lambda: c.read_data_by_identifier(0x0100).service_data.values)
        self.step("0x2E write calibration 0x0100", lambda: hexs(c.write_data_by_identifier(0x0100, 0x00C8).data))
        self.step("0x22 read it back", lambda: c.read_data_by_identifier(0x0100).service_data.values)
        self.step("0x2E write variable-length DID 0x0101", lambda: self.check_raw(
            [0x2E, 0x01, 0x01] + list(b"MY GARAGE"), 0x6E))
        self.step("0x22 read 0x0101", lambda: self.raw([0x22, 0x01, 0x01])[3:].decode())
        self.step("0x24 read scaling data of 0x0100 (raw)", lambda: self.check_raw([0x24, 0x01, 0x00], 0x64))
        self.step("0x2C define dynamic DID 0xF200 (VIN bytes 1-3 + memory 0x020008)", self._define_dynamic_did)
        self.step("0x22 read dynamic DID 0xF200", lambda: hexs(self.raw([0x22, 0xF2, 0x00])))
        self.step("0x2A periodic DID 0xF200 at fast rate (raw)", self._periodic)
        self.step("0x2C clear dynamic DID 0xF200", lambda: hexs(c.clear_dynamically_defined_did(0xF200).data))
        self.step("0x10 default session", self.default)

    def _define_dynamic_did(self):
        self.client.dynamically_define_did(0xF200, DynamicDidDefinition(source_did=0xF190, position=1, memorysize=3))
        self.client.dynamically_define_did(0xF200, DynamicDidDefinition(mem(0x020008, 4)))
        return "defined by identifier, then appended by memory address"

    def _periodic(self):
        self.check_raw([0x2A, 0x03, 0x00], 0x6A)
        received = [hexs(self.receive()) for _ in range(3)]
        self.check_raw([0x2A, 0x04, 0x00], 0x6A)
        time.sleep(0.2)
        return f"{len(received)} messages, e.g. {received[0]}"

    def io(self):
        """0x2F InputOutputControlByIdentifier."""
        c = self.client
        self.step("0x10 extended session + unlock level 0x01", lambda: self.extended(unlock=True))
        self.step("0x2F fan 0x0500 shortTermAdjustment = 80%",
                  lambda: c.io_control(0x0500, control_param=0x03, values=[80]).service_data.decoded_data)
        self.step("0x22 read 0x0500 while controlled", lambda: hexs(self.raw([0x22, 0x05, 0x00])))
        self.step("0x2F fan 0x0500 resetToDefault",
                  lambda: c.io_control(0x0500, control_param=0x01).service_data.decoded_data)
        self.step("0x2F fan 0x0500 returnControlToECU",
                  lambda: c.io_control(0x0500, control_param=0x00).service_data.decoded_data)
        self.step("0x2F outputs 0x0501 with enable mask (raw)",
                  lambda: self.check_raw([0x2F, 0x05, 0x01, 0x03, 0xFF, 0xFF, 0x00, 0x0F], 0x6F))
        self.step("0x10 default session (returns every control to the ECU)", self.default)

    def dtc(self):
        """0x19 ReadDTCInformation, 0x85 ControlDTCSetting, 0x14 ClearDiagnosticInformation."""
        c = self.client
        self.step("0x19/0x01 number of DTCs (confirmed)",
                  lambda: c.get_number_of_dtc_by_status_mask(0x08).service_data.dtc_count)
        self.step("0x19/0x02 DTCs by status mask", lambda: self._dtcs(c.get_dtc_by_status_mask(0xFF)))
        self.step("0x19/0x03 snapshot identification",
                  lambda: [f"{d.id:06X} record {s}"
                          for d in c.get_dtc_snapshot_identification().service_data.dtcs for s in d.snapshots])
        self.step("0x19/0x04 snapshot record of P0101", lambda: hexs(self.raw([0x19, 0x04, 0x01, 0x01, 0x00, 0xFF])))
        self.step("0x19/0x06 extended data of P0101", lambda: hexs(
            c.get_dtc_extended_data_by_dtc_number(0x010100, 0x01, data_size=1).service_data.dtcs[0].extended_data[0].raw_data))
        self.step("0x19/0x08 DTCs by severity", lambda: self._dtcs(c.get_dtc_by_status_severity_mask(0xFF, 0xFF)))
        self.step("0x19/0x0A supported DTCs", lambda: self._dtcs(c.get_supported_dtc()))
        self.step("0x19/0x0D most recent test failed DTC", lambda: self._dtcs(c.get_most_recent_test_failed_dtc()))
        self.step("0x19/0x14 fault detection counters",
                  lambda: {f"{d.id:06X}": d.fault_counter for d in c.get_dtc_fault_counter().service_data.dtcs})
        self.step("0x19/0x15 permanent DTCs", lambda: self._dtcs(c.get_dtc_with_permanent_status()))
        self.step("0x10 extended session", self.extended)
        self.step("0x85 DTC setting off", lambda: hexs(c.control_dtc_setting(0x02).data))
        self.step("0x85 DTC setting on", lambda: hexs(c.control_dtc_setting(0x01).data))
        self.step("0x14 clear group 0x000001 (powertrain)", lambda: hexs(c.clear_dtc(0x000001).original_payload))
        self.step("0x14 clear all DTCs", lambda: hexs(c.clear_dtc(0xFFFFFF).original_payload))
        self.step("0x19/0x0A after clearing", lambda: self._dtcs(c.get_supported_dtc()))
        self.step("0x10 default session", self.default)

    @staticmethod
    def _dtcs(resp):
        return {f"{d.id:06X}": f"0x{d.status.get_byte_as_int():02X}" for d in resp.service_data.dtcs}

    def routines(self):
        """0x31 RoutineControl (configured with a 0x78 response pending)."""
        c = self.client
        self.step("0x31 start 0x0203 check preconditions",
                  lambda: hexs(c.start_routine(0x0203).service_data.routine_status_record))
        self.step("0x31 results 0x0203", lambda: hexs(c.get_routine_result(0x0203).service_data.routine_status_record))
        self.step("0x10 extended session", self.extended)
        self.step("0x31 start 0x0300 actuator test (sets DID 0x0101 and DTC P0300)",
                  lambda: hexs(c.start_routine(0x0300).original_payload))
        self.step("0x31 results 0x0300 (running)", lambda: hexs(c.get_routine_result(0x0300).service_data.routine_status_record))
        self.step("0x31 stop 0x0300", lambda: hexs(c.stop_routine(0x0300).service_data.routine_status_record))
        self.step("0x10 programming session + unlock level 0x11", self.programming)
        self.step("0x31 start 0xFF01 check memory, CRC case DEADBEEF", lambda: hexs(
            c.start_routine(0xFF01, data=bytes.fromhex("DEADBEEF")).service_data.routine_status_record))
        self.step("0x31 start 0xFF00 erase memory 0x010000", lambda: hexs(c.start_routine(
            0xFF00, data=struct.pack(">II", 0x010000, 0x100)).service_data.routine_status_record))
        self.step("0x31 results 0xFF00 (in progress = 01)",
                  lambda: hexs(c.get_routine_result(0xFF00).service_data.routine_status_record))
        self.step("wait 2 s for the erase to finish", lambda: time.sleep(2))
        self.step("0x31 results 0xFF00 (finished = 00)",
                  lambda: hexs(c.get_routine_result(0xFF00).service_data.routine_status_record))
        self.step("0x10 default session", self.default)

    def memory(self):
        """0x23, 0x3D, 0x34/0x36/0x37 download, 0x35 upload."""
        c = self.client
        self.step("0x23 read calibration 0x020008", lambda: c.read_memory_by_address(
            mem(0x020008, 14)).service_data.memory_block)
        self.step("0x10 extended session + unlock level 0x01", lambda: self.extended(unlock=True))
        self.step("0x3D write calibration 0x020000", lambda: hexs(c.write_memory_by_address(
            mem(0x020000, 2), b"\x01\x2C").data))
        self.step("0x23 read it back", lambda: hexs(c.read_memory_by_address(mem(0x020000, 2)).service_data.memory_block))
        self.step("0x35 upload 32 bytes of code", self._upload)
        self.step("0x10 programming session + unlock level 0x11", self.programming)
        self.step("0x34/0x36/0x37 download 256 bytes to 0x010000", self._download)
        self.step("0x23 read downloaded code", lambda: hexs(c.read_memory_by_address(mem(0x010000, 8)).service_data.memory_block))
        self.step("0x10 default session", self.default)
        print("    (writes are persisted to firmware/engine_ecu.out.s19, the input file is untouched)")

    def _upload(self):
        c = self.client
        resp = c.request_upload(mem(0x010000, 32), dfi=DataFormatIdentifier(0, 0))
        data = c.transfer_data(1).service_data.parameter_records
        c.request_transfer_exit()
        return f"max block={resp.service_data.max_length}, data={hexs(data[:8])}..."

    def _download(self):
        c = self.client
        image = bytes(range(256))
        block = c.request_download(mem(0x010000, len(image)), dfi=DataFormatIdentifier(0, 0)).service_data.max_length - 2
        for counter, offset in enumerate(range(0, len(image), block), start=1):
            c.transfer_data(counter & 0xFF, image[offset:offset + block])
        c.request_transfer_exit()
        return f"{len(image)} bytes in blocks of {block}"

    def files(self):
        """0x38 RequestFileTransfer on firmware/files."""
        c = self.client
        content = b"Hello from examples/client.py\n"
        self.step("0x10 extended session", self.extended)
        self.step("0x38 add file hello.txt", lambda: self._add_file("hello.txt", content))
        self.step("0x38 read file hello.txt", lambda: self._read_transfer(
            c.read_file("hello.txt", dfi=DataFormatIdentifier(0, 0))).decode().strip())
        self.step("0x38 read directory /", lambda: self._read_transfer(c.read_dir("/")).decode().split())
        self.step("0x38 delete file hello.txt", lambda: hexs(c.delete_file("hello.txt").data))
        self.step("0x10 default session", self.default)

    def _add_file(self, path, content):
        c = self.client
        resp = c.add_file(path, dfi=DataFormatIdentifier(0, 0), filesize=Filesize(len(content), width=4))
        c.transfer_data(1, content[:resp.service_data.max_length - 2])
        c.request_transfer_exit()
        return f"{len(content)} bytes"

    def _read_transfer(self, resp):
        c = self.client
        size = (resp.service_data.filesize.uncompressed if resp.service_data.filesize
                else resp.service_data.dirinfo_length)
        data, counter = b"", 1
        while len(data) < size:
            data += c.transfer_data(counter).service_data.parameter_records
            counter += 1
        c.request_transfer_exit()
        return data

    def communication(self):
        """0x28 CommunicationControl, 0x87 LinkControl."""
        c = self.client
        self.step("0x10 extended session", self.extended)
        self.step("0x28 disable Rx and Tx (normal + NM messages)", lambda: hexs(c.communication_control(
            0x03, CommunicationType(subnet=0, normal_msg=True, network_management_msg=True)).data))
        self.step("0x28 enable Rx and Tx", lambda: hexs(c.communication_control(
            0x00, CommunicationType(subnet=0, normal_msg=True, network_management_msg=True)).data))
        self.step("0x87 verify fixed baudrate 500k", lambda: hexs(c.link_control(
            0x01, Baudrate(500000, baudtype=Baudrate.Type.Fixed)).data))
        self.step("0x87 transition mode", lambda: hexs(c.link_control(0x03).data))
        self.step("0x10 default session (link back to default)", self.default)

    def events(self):
        """0x86 ResponseOnEvent (raw)."""
        self.step("0x10 extended session", self.extended)
        self.step("0x86 on change of DID 0x0101, respond with 22 01 01",
                  lambda: self.check_raw([0x86, 0x03, 0x02, 0x01, 0x01, 0x22, 0x01, 0x01], 0xC6))
        self.step("0x86 on timer interrupt (slow), respond with 19 01 FF",
                  lambda: self.check_raw([0x86, 0x02, 0x02, 0x01, 0x19, 0x01, 0xFF], 0xC6))
        self.step("0x86 start response on event", lambda: self.check_raw([0x86, 0x05, 0x02], 0xC6))
        self.step("0x86 report activated events", lambda: self.check_raw([0x86, 0x04], 0xC6))
        self.step("trigger: write DID 0x0101, then wait for event responses", self._trigger_event)
        self.step("0x86 clear response on event", lambda: self.check_raw([0x86, 0x06, 0x02], 0xC6))
        self.step("0x10 default session", self.default)

    def _trigger_event(self):
        self.conn.send(bytes([0x2E, 0x01, 0x01]) + b"EVENT")
        messages = [self.receive() for _ in range(3)]  # write response + event responses
        return " | ".join(hexs(m) for m in messages)

    def secured(self):
        """0x84 SecuredDataTransmission (raw, HMAC-SHA256 signed)."""
        self.step("0x84 signed ReadDataByIdentifier 0xF190 with signed response", lambda: self._sdt(1, [0x22, 0xF1, 0x90]))
        self.step("0x84 unsigned TesterPresent", lambda: self._sdt(2, [0x3E, 0x00], sign=False))

    def _sdt(self, counter, internal, sign=True):
        apar = 0x0001 | (0x0030 if sign else 0)  # request (+ signed + response signature requested)
        body = struct.pack(">HBHH", apar, 0x00, 32 if sign else 0, counter) + bytes(internal)
        signature = hmac.new(SDT_SECRET, body, hashlib.sha256).digest() if sign else b""
        resp = self.raw(b"\x84" + body + signature)
        if resp[0] != 0xC4:
            raise RuntimeError(f"unexpected response {hexs(resp)}")
        sig_len = int.from_bytes(resp[4:6], "big")
        inner = resp[8:len(resp) - sig_len]
        if sig_len:
            expected = hmac.new(SDT_SECRET, resp[1:len(resp) - sig_len], hashlib.sha256).digest()
            assert resp[-sig_len:] == expected, "invalid response signature"
        return f"internal response {hexs(inner)}" + (" (signature verified)" if sig_len else "")


SECTIONS = ["isotp_layer", "session", "security", "data", "io", "dtc", "routines",
            "memory", "files", "communication", "events", "secured", "reset"]


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("sections", nargs="*", help="sections to run (default: all)")
    parser.add_argument("--list", action="store_true", help="list the sections")
    parser.add_argument("--interface", default="vcan0", help="SocketCAN interface")
    parser.add_argument("--request", type=lambda v: int(v, 0), default=0x7E0, help="physical request CAN ID")
    parser.add_argument("--response", type=lambda v: int(v, 0), default=0x7E8, help="response CAN ID")
    parser.add_argument("--functional", type=lambda v: int(v, 0), default=0x7DF, help="functional request CAN ID")
    args = parser.parse_args()

    if args.list:
        for name in SECTIONS:
            print(f"{name:14} {getattr(Examples, name).__doc__}")
        return 0
    unknown = set(args.sections) - set(SECTIONS)
    if unknown:
        parser.error(f"unknown sections: {', '.join(sorted(unknown))} (see --list)")

    tpsock = isotp.socket(timeout=0.1)
    tpsock.set_opts(txpad=0xCC)
    address = isotp.Address(isotp.AddressingMode.Normal_11bits, rxid=args.response, txid=args.request)
    conn = IsoTPSocketConnection(args.interface, address, tpsock=tpsock)
    config = dict(udsoncan.configs.default_client_config)
    config.update({
        "security_algo": security_algo,
        "request_timeout": 5,
        "data_identifiers": {
            0xF190: udsoncan.AsciiCodec(17),
            0xF18C: udsoncan.AsciiCodec(6),
            0xF189: "BBB",
            0x0100: ">H",
        },
        "input_output": {0x0500: "B"},
    })
    with Client(conn, config=config) as client:
        ex = Examples(conn, client, args)
        for name in args.sections or SECTIONS:
            print(f"\n== {name}: {getattr(Examples, name).__doc__}")
            getattr(ex, name)()

    print(f"\n{'All examples succeeded' if ex.failures == 0 else f'{ex.failures} example(s) failed'}")
    return 1 if ex.failures else 0


if __name__ == "__main__":
    sys.exit(main())
