"""ISO 15765-2 (ISO-TP) and CAN behaviour, checked frame by frame on the bus."""

import isotp
import pytest

from conftest import INTERFACE, RawCAN, isotp_socket

REQ, RESP, FUNC = 0x7E0, 0x7E8, 0x7DF
VIN = b"WBA12345678901234"
PAD = b"\xCC"


def padded(*data):
    return bytes(data).ljust(8, PAD)


@pytest.fixture
def bus():
    """A raw CAN socket opened before the server, independent of it."""
    s = RawCAN()
    yield s
    s.close()


def expect_frame(bus, can_id, data, timeout=1.0):
    f = bus.recv(can_id, timeout)
    assert f is not None, f"no frame on 0x{can_id:X}, expected {bytes(data).hex()}"
    assert f["data"] == bytes(data), f"0x{can_id:X}: {f['data'].hex()}, expected {bytes(data).hex()}"
    return f


def read_vin_frames(bus):
    """Sends 22 F1 90 and returns the first frame of the 20-byte response."""
    bus.send(REQ, padded(0x03, 0x22, 0xF1, 0x90))
    return expect_frame(bus, RESP, bytes([0x10, 0x14, 0x62, 0xF1, 0x90]) + VIN[:3])


# --- single frames and padding -------------------------------------------------

def test_single_frame_padded(server, bus):
    bus.send(REQ, padded(0x02, 0x3E, 0x00))
    expect_frame(bus, RESP, padded(0x02, 0x7E, 0x00))


def test_unpadded_request_accepted(server, bus):
    bus.send(REQ, [0x02, 0x3E, 0x00])
    expect_frame(bus, RESP, padded(0x02, 0x7E, 0x00))


def test_invalid_single_frames_ignored(server, bus):
    bus.send(REQ, padded(0x00))  # SF_DL 0
    bus.send(REQ, [0x05, 0x3E, 0x00])  # SF_DL beyond the frame
    assert bus.recv(RESP, 0.3) is None


# --- segmented messages ----------------------------------------------------------

def test_segmented_request(server, bus):
    request = bytes([0x2E, 0x01, 0x01]) + b"WORKSHOP1"  # 12 bytes
    bus.send(REQ, bytes([0x10, 12]) + request[:6])
    expect_frame(bus, RESP, padded(0x30, 0x00, 0x00))  # flow control: no limits
    bus.send(REQ, padded(0x21, *request[6:]))
    expect_frame(bus, RESP, padded(0x03, 0x6E, 0x01, 0x01))


def test_segmented_response_with_tester_stmin(server, bus):
    read_vin_frames(bus)
    bus.send(REQ, padded(0x30, 0x00, 0x1E))  # BS 0, STmin 30 ms
    cf1 = expect_frame(bus, RESP, bytes([0x21]) + VIN[3:10])
    cf2 = expect_frame(bus, RESP, bytes([0x22]) + VIN[10:17])
    assert cf2["time"] - cf1["time"] >= 0.025, "STmin of 30 ms not respected"


def test_segmented_response_with_tester_block_size(server, bus):
    read_vin_frames(bus)
    bus.send(REQ, padded(0x30, 0x01, 0x00))  # one consecutive frame per flow control
    expect_frame(bus, RESP, bytes([0x21]) + VIN[3:10])
    assert bus.recv(RESP, 0.2) is None, "sent beyond the block size"
    bus.send(REQ, padded(0x30, 0x01, 0x00))
    expect_frame(bus, RESP, bytes([0x22]) + VIN[10:17])


def test_flow_control_wait_then_continue(server, bus):
    read_vin_frames(bus)
    for _ in range(3):
        bus.send(REQ, padded(0x31, 0x00, 0x00))  # WAIT
        assert bus.recv(RESP, 0.1) is None
    bus.send(REQ, padded(0x30, 0x00, 0x00))
    expect_frame(bus, RESP, bytes([0x21]) + VIN[3:10])
    expect_frame(bus, RESP, bytes([0x22]) + VIN[10:17])


def test_flow_control_overflow_aborts(server, bus):
    read_vin_frames(bus)
    bus.send(REQ, padded(0x32, 0x00, 0x00))  # OVERFLOW
    assert bus.recv(RESP, 0.3) is None, "consecutive frames after an overflow"
    bus.send(REQ, padded(0x02, 0x3E, 0x00))
    expect_frame(bus, RESP, padded(0x02, 0x7E, 0x00))


def test_missing_flow_control_times_out(start_server, bus):
    start_server({"padding: 0xCC\n": "padding: 0xCC\n  n_bs_ms: 200\n"})
    read_vin_frames(bus)
    assert bus.recv(RESP, 0.4) is None, "no consecutive frame without flow control"
    bus.send(REQ, padded(0x02, 0x3E, 0x00))
    expect_frame(bus, RESP, padded(0x02, 0x7E, 0x00), timeout=0.5)


def test_server_block_size_and_stmin(start_server, bus):
    start_server({"padding: 0xCC\n": "padding: 0xCC\n  block_size: 2\n  st_min: 0x14\n"})
    request = bytes([0x2E, 0x01, 0x01]) + b"A" * 24  # FF (6) + 3 CFs (7 + 7 + 7)
    bus.send(REQ, bytes([0x10, len(request)]) + request[:6])
    expect_frame(bus, RESP, padded(0x30, 0x02, 0x14))
    bus.send(REQ, bytes([0x21]) + request[6:13])
    bus.send(REQ, bytes([0x22]) + request[13:20])
    expect_frame(bus, RESP, padded(0x30, 0x02, 0x14), timeout=0.5)  # next block
    bus.send(REQ, padded(0x23, *request[20:]))
    expect_frame(bus, RESP, padded(0x03, 0x6E, 0x01, 0x01))


def test_request_too_large_overflow(start_server, bus):
    start_server({"padding: 0xCC\n": "padding: 0xCC\n  max_message_size: 32\n"})
    bus.send(REQ, bytes([0x10, 33, 0x2E, 0x01, 0x01, 0x41, 0x41, 0x41]))
    expect_frame(bus, RESP, padded(0x32, 0x00, 0x00))
    request = bytes([0x2E, 0x01, 0x01]) + b"B" * 29  # exactly 32 bytes
    s = isotp_socket(timeout=1)
    s.bind(INTERFACE, address=isotp.Address(isotp.AddressingMode.Normal_11bits, rxid=RESP, txid=REQ))
    s.send(request)
    assert s.recv() == bytes([0x6E, 0x01, 0x01])
    s.close()


def test_wrong_sequence_number_aborts(server, bus):
    request = bytes([0x2E, 0x01, 0x01]) + b"WORKSHOP1"
    bus.send(REQ, bytes([0x10, 12]) + request[:6])
    expect_frame(bus, RESP, padded(0x30, 0x00, 0x00))
    bus.send(REQ, padded(0x22, *request[6:]))  # SN 2 instead of 1
    assert bus.recv(RESP, 0.3) is None


def test_consecutive_frame_timeout(start_server, bus):
    start_server({"padding: 0xCC\n": "padding: 0xCC\n  n_cr_ms: 200\n"})
    request = bytes([0x2E, 0x01, 0x01]) + b"WORKSHOP1"
    bus.send(REQ, bytes([0x10, 12]) + request[:6])
    expect_frame(bus, RESP, padded(0x30, 0x00, 0x00))
    bus.recv(RESP, 0.3)  # let N_Cr expire
    bus.send(REQ, padded(0x21, *request[6:]))
    assert bus.recv(RESP, 0.3) is None, "late consecutive frame accepted"


def test_new_single_frame_interrupts_reception(server, bus):
    request = bytes([0x2E, 0x01, 0x01]) + b"WORKSHOP1"
    bus.send(REQ, bytes([0x10, 12]) + request[:6])
    expect_frame(bus, RESP, padded(0x30, 0x00, 0x00))
    bus.send(REQ, padded(0x02, 0x3E, 0x00))
    expect_frame(bus, RESP, padded(0x02, 0x7E, 0x00))


# --- functional addressing ---------------------------------------------------------

def test_functional_single_frame(server, bus):
    bus.send(FUNC, padded(0x02, 0x3E, 0x00))
    expect_frame(bus, RESP, padded(0x02, 0x7E, 0x00))


def test_functional_first_frame_ignored(server, bus):
    bus.send(FUNC, bytes([0x10, 12, 0x2E, 0x01, 0x01, 0x41, 0x41, 0x41]))
    assert bus.recv(RESP, 0.3) is None, "functional first frame answered"


def test_other_identifiers_ignored(server, bus):
    bus.send(0x7E1, padded(0x02, 0x3E, 0x00))
    bus.send(REQ, padded(0x02, 0x3E, 0x00), extended=True)  # same number, 29-bit
    assert bus.recv(RESP, 0.3) is None


# --- large messages ------------------------------------------------------------------

def test_4095_byte_messages(conn, uds):
    value = bytes(range(256)) * 15 + bytes(range(252))  # 4092 bytes: 4095 with SID + DID
    assert uds([0x2E, 0x01, 0x01] + list(value), timeout=3) == bytes([0x6E, 0x01, 0x01])
    assert uds([0x22, 0x01, 0x01], timeout=3) == bytes([0x62, 0x01, 0x01]) + value


# --- CAN FD, 29-bit identifiers, extended addressing, UUDT ---------------------------

def test_can_fd(start_server, bus):
    start_server({"padding: 0xCC\n": "padding: 0xCC\n  fd: true\n  bitrate_switch: true\n"})
    bus.send(REQ, padded(0x03, 0x22, 0xF1, 0x90), fd=True)
    f = bus.recv(RESP)
    assert f["fd"] and f["brs"], f
    # Escaped single frame: 00 + SF_DL, 22 bytes in a 24-byte FD frame.
    assert f["data"] == (bytes([0x00, 0x14, 0x62, 0xF1, 0x90]) + VIN).ljust(24, PAD), f["data"].hex()
    # A classic request is answered with FD frames too.
    bus.send(REQ, padded(0x02, 0x3E, 0x00))
    f = bus.recv(RESP)
    assert f["fd"] and f["data"] == padded(0x02, 0x7E, 0x00)


def test_can_fd_segmented_with_kernel_stack(start_server):
    start_server({"padding: 0xCC\n": "padding: 0xCC\n  fd: true\n"})
    s = isotp_socket(timeout=2)
    s.set_ll_opts(mtu=isotp.socket.LinkLayerProtocol.CAN_FD, tx_dl=64)
    s.bind(INTERFACE, address=isotp.Address(isotp.AddressingMode.Normal_11bits, rxid=RESP, txid=REQ))
    value = bytes(range(200))
    s.send(bytes([0x2E, 0x01, 0x01]) + value)
    assert s.recv() == bytes([0x6E, 0x01, 0x01])
    s.send(bytes([0x22, 0x01, 0x01]))
    assert s.recv() == bytes([0x62, 0x01, 0x01]) + value
    s.close()


def test_29bit_identifiers(start_server, bus):
    start_server({
        "request_id: 0x7E0": "request_id: 0x18DA10F1",
        "response_id: 0x7E8": "response_id: 0x18DAF110",
        "functional_id: 0x7DF": "functional_id: 0x18DB33F1\n  extended_ids: true",
    })
    s = isotp_socket(timeout=1)
    s.bind(INTERFACE, address=isotp.Address(isotp.AddressingMode.Normal_29bits, rxid=0x18DAF110, txid=0x18DA10F1))
    s.send(b"\x22\xF1\x90")
    assert s.recv() == b"\x62\xF1\x90" + VIN
    s.close()
    bus.frames(0x18DAF110, 0.1)  # discard the frames of the read above
    bus.send(0x18DB33F1, padded(0x02, 0x3E, 0x00), extended=True)
    f = expect_frame(bus, 0x18DAF110, padded(0x02, 0x7E, 0x00))
    assert f["extended"]


def test_extended_addressing(start_server, bus):
    start_server({
        "request_id: 0x7E0": "request_id: 0x600",
        "response_id: 0x7E8": "response_id: 0x601\n  addressing: extended\n  rx_address: 0x10\n  tx_address: 0xF1",
    })
    s = isotp_socket(timeout=1)
    s.bind(INTERFACE, address=isotp.Address(isotp.AddressingMode.Extended_11bits, rxid=0x601, txid=0x600,
                                            target_address=0x10, source_address=0xF1))
    s.send(b"\x22\xF1\x90")
    assert s.recv() == b"\x62\xF1\x90" + VIN
    s.close()
    bus.frames(0x601, 0.1)  # discard the frames of the read above
    bus.send(0x600, padded(0x11, 0x02, 0x3E, 0x00))  # another ECU's address
    assert bus.recv(0x601, 0.3) is None
    bus.send(0x600, padded(0x10, 0x02, 0x3E, 0x00))
    expect_frame(bus, 0x601, padded(0xF1, 0x02, 0x7E, 0x00))


def test_periodic_data_as_uudt(start_server, bus):
    start_server({"padding: 0xCC\n": "padding: 0xCC\n  periodic_response_id: 0x6E8\n"})
    s = isotp_socket(timeout=1)
    s.bind(INTERFACE, address=isotp.Address(isotp.AddressingMode.Normal_11bits, rxid=RESP, txid=REQ))
    s.send(bytes([0x2C, 0x01, 0xF2, 0x01, 0xF1, 0x90, 0x01, 0x03]))  # 0xF201 = VIN[0:3]
    assert s.recv() == bytes([0x6C, 0x01, 0xF2, 0x01])
    s.send(bytes([0x2A, 0x03, 0x01]))
    assert s.recv() == bytes([0x6A])
    frames = bus.frames(0x6E8, 0.3)
    assert len(frames) >= 3, f"{len(frames)} periodic frames in 0.3 s at 50 ms"
    assert all(f["data"] == padded(0x6A, 0x01, *b"WBA") for f in frames), frames[0]
    with pytest.raises(TimeoutError):
        s.recv()  # periodic data must not use ISO-TP
    s.close()
