"""End-to-end test fixtures: build the Go server, start a fresh instance per
test on the virtual CAN interface and talk to it through the Linux kernel
ISO-TP stack (can-isotp + udsoncan), an implementation independent from
the server's.

Requires a vcan interface (see README):
    sudo ip link add dev vcan0 type vcan && sudo ip link set up vcan0

Set GODOCAN_EXTERNAL=1 to test an already running server instead (state is
then shared between tests, so some tests may fail).
"""

import os
import shutil
import socket
import struct
import subprocess
import time
from pathlib import Path

import isotp
import pytest
import udsoncan
from udsoncan.client import Client
from udsoncan.connections import IsoTPSocketConnection

REPO_ROOT = Path(__file__).resolve().parents[2]
E2E_DIR = Path(__file__).resolve().parent
# Files copied to the per-test working directory of the server.
SERVER_FILES = ["config.yaml", "firmware.s19"]

INTERFACE = os.environ.get("GODOCAN_INTERFACE", "vcan0")
REQUEST_ID = 0x7E0
RESPONSE_ID = 0x7E8
FUNCTIONAL_ID = 0x7DF


def tester_address(rxid=RESPONSE_ID, txid=REQUEST_ID):
    return isotp.Address(isotp.AddressingMode.Normal_11bits, rxid=rxid, txid=txid)


def isotp_socket(timeout=0.1):
    """A kernel ISO-TP socket with the tester settings (frames padded with 0xCC)."""
    s = isotp.socket(timeout=timeout)
    s.set_opts(txpad=0xCC)
    return s


def _ecu_answers():
    """Reports whether an ECU already answers TesterPresent on the bus."""
    s = isotp_socket(timeout=0.3)
    s.bind(INTERFACE, address=tester_address())
    try:
        s.send(b"\x3E\x00")
        return s.recv() is not None
    except (TimeoutError, socket.timeout):
        return False
    finally:
        s.close()


@pytest.fixture(scope="session")
def server_binary(tmp_path_factory):
    binary = tmp_path_factory.mktemp("bin") / "godocan"
    subprocess.run(["go", "build", "-o", str(binary), "./cmd/server"], cwd=REPO_ROOT, check=True)
    return binary


class ServerProcess:
    """Runs the server binary in a working directory with a copy of the e2e
    configuration, optionally edited with text replacements."""

    def __init__(self, binary, workdir, replacements=None):
        for name in SERVER_FILES:
            shutil.copy(E2E_DIR / name, workdir / name)
        shutil.copytree(E2E_DIR / "files", workdir / "files")
        shutil.copytree(E2E_DIR / "pki", workdir / "pki")
        config = workdir / "config.yaml"
        text = config.read_text().replace("interface: vcan0", f"interface: {INTERFACE}")
        for old, new in (replacements or {}).items():
            assert old in text, f"{old!r} not found in config.yaml"
            text = text.replace(old, new)
        config.write_text(text)

        if _ecu_answers():
            raise RuntimeError(f"an ECU already answers on 0x{REQUEST_ID:03X} ({INTERFACE}): stop the running "
                               "server (or set GODOCAN_EXTERNAL=1 to test it)")
        self.logfile = workdir / "server.log"
        self.log = open(self.logfile, "w")
        self.proc = subprocess.Popen(
            [str(binary), "-config", str(config)],
            cwd=workdir, stdout=self.log, stderr=subprocess.STDOUT,
        )

    def wait_ready(self, timeout=10.0):
        """Waits for the start-up log line written once the CAN socket is open."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError(f"server exited with code {self.proc.returncode}:\n{self.logfile.read_text()}")
            if " on " in self.logfile.read_text():
                return
            time.sleep(0.02)
        raise TimeoutError("server did not start")

    def stop(self):
        self.proc.terminate()
        self.proc.wait(timeout=5)
        self.log.close()


@pytest.fixture
def start_server(server_binary, tmp_path):
    """Factory starting a server with a customized configuration."""
    started = []

    def start(replacements=None, wait=True):
        srv = ServerProcess(server_binary, tmp_path, replacements)
        started.append(srv)
        if wait:
            srv.wait_ready()
        return srv

    yield start
    for srv in started:
        srv.stop()


@pytest.fixture
def server(start_server):
    """A fresh server per test, so every test starts from the initial state."""
    if not os.environ.get("GODOCAN_EXTERNAL"):
        start_server()
    yield INTERFACE


@pytest.fixture
def workdir(server, tmp_path):
    """Directory holding the server configuration and memory files."""
    return tmp_path


@pytest.fixture
def conn(server):
    """The tester ISO-TP connection (kernel socket), shared by `uds` and `client`."""
    c = IsoTPSocketConnection(INTERFACE, tester_address(), tpsock=isotp_socket())
    c.open()
    yield c
    c.close()


CAN_EFF_FLAG = 0x80000000
CANFD_BRS = 0x01


class RawCAN:
    """A raw CAN socket (classic and FD frames) on the test interface."""

    def __init__(self, interface=INTERFACE):
        self.sock = socket.socket(socket.AF_CAN, socket.SOCK_RAW, socket.CAN_RAW)
        self.sock.setsockopt(socket.SOL_CAN_RAW, socket.CAN_RAW_FD_FRAMES, 1)
        self.sock.bind((interface,))

    def close(self):
        self.sock.close()

    def send(self, can_id, data, fd=False, extended=False, brs=False):
        data = bytes(data)
        if extended:
            can_id |= CAN_EFF_FLAG
        if fd:
            self.sock.send(struct.pack("=IBB2x64s", can_id, len(data), CANFD_BRS if brs else 0, data))
        else:
            self.sock.send(struct.pack("=IB3x8s", can_id, len(data), data))

    def recv(self, can_id=None, timeout=1.0):
        """Next frame (optionally with this identifier) as a dict, or None."""
        deadline = time.monotonic() + timeout
        while (remaining := deadline - time.monotonic()) > 0:
            self.sock.settimeout(remaining)
            try:
                raw = self.sock.recv(72)
            except socket.timeout:
                return None
            raw_id, length, flags = struct.unpack("=IBB", raw[:6])
            frame = {
                "id": raw_id & (0x1FFFFFFF if raw_id & CAN_EFF_FLAG else 0x7FF),
                "extended": bool(raw_id & CAN_EFF_FLAG),
                "fd": len(raw) == 72, "brs": len(raw) == 72 and bool(flags & CANFD_BRS),
                "data": raw[8:8 + length], "time": time.monotonic(),
            }
            if can_id is None or frame["id"] == can_id:
                return frame
        return None

    def frames(self, can_id, duration):
        """Every frame with this identifier received during `duration` seconds."""
        out, deadline = [], time.monotonic() + duration
        while (remaining := deadline - time.monotonic()) > 0:
            f = self.recv(can_id, remaining)
            if f:
                out.append(f)
        return out


@pytest.fixture
def raw_can(server):
    """A raw CAN socket on the test interface."""
    s = RawCAN()
    yield s
    s.close()


class RawUDS:
    """Sends raw UDS requests and returns raw responses (or None)."""

    def __init__(self, conn, raw_can):
        self.conn = conn
        self.raw_can = raw_can

    def __call__(self, request, timeout=1.0):
        self.conn.send(bytes(request))
        return self.receive(timeout)

    def receive(self, timeout=1.0):
        return self.conn.wait_frame(timeout=timeout)

    def functional(self, request, timeout=1.0):
        """Sends a single frame to the functional identifier."""
        data = bytes([len(request)]) + bytes(request)
        assert len(data) <= 8, "functional requests are single frames"
        self.raw_can.send(FUNCTIONAL_ID, data.ljust(8, b"\xCC"))
        return self.receive(timeout)


@pytest.fixture
def uds(conn, raw_can):
    return RawUDS(conn, raw_can)


def xor_key(level, seed, params=None):
    return bytes(s ^ m for s, m in zip(seed, bytes.fromhex("AABBCCDD")))


@pytest.fixture
def client(conn):
    """A udsoncan client, which strictly validates responses."""
    config = dict(udsoncan.configs.default_client_config)
    config["security_algo"] = xor_key
    config["data_identifiers"] = {
        0xF190: udsoncan.AsciiCodec(17),
        0xF189: "BBB",
        0x0100: ">H",
        0x0101: udsoncan.AsciiCodec(6),
    }
    config["input_output"] = {0x0500: "B"}
    config["request_timeout"] = 2
    with Client(conn, config=config) as c:
        yield c


def nrc(sid, code):
    return bytes([0x7F, sid, code])
