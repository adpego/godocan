import pytest
from udsoncan import MemoryLocation
from udsoncan.exceptions import NegativeResponseException

from conftest import nrc

# Same content as firmware.s19.
CODE = bytes((i * 7 + 3) & 0xFF for i in range(256))
CALIBRATION = bytes.fromhex("006400C8012C0190") + b"CALIBRATION-V1" + bytes(2)


def parse_srec(path):
    """Minimal S-Record reader: returns {address: byte}."""
    mem = {}
    for line in path.read_text().split():
        if line[1] not in "123":
            continue
        raw = bytes.fromhex(line[2:])
        alen = {"1": 2, "2": 3, "3": 4}[line[1]]
        addr = int.from_bytes(raw[1:1 + alen], "big")
        for i, b in enumerate(raw[1 + alen:-1]):
            mem[addr + i] = b
    return mem


def test_read_udsoncan(client):
    resp = client.read_memory_by_address(MemoryLocation(0x010000, 16, address_format=32, memorysize_format=8))
    assert resp.service_data.memory_block == CODE[:16]


def test_read_raw(uds):
    # ALFID 0x13: 1-byte size, 3-byte address.
    assert uds([0x23, 0x13, 0x02, 0x00, 0x08, 0x0E]) == bytes([0x63]) + b"CALIBRATION-V1"


def test_read_fill_inside_region(uds):
    assert uds([0x23, 0x13, 0x02, 0x00, 0x16, 0x04]) == bytes([0x63, 0x00, 0x00, 0xFF, 0xFF])


def test_read_out_of_range(uds):
    assert uds([0x23, 0x13, 0x03, 0x00, 0x00, 0x01]) == nrc(0x23, 0x31)


def test_write_code_then_read_and_persist(uds, workdir):
    original = (workdir / "firmware.s19").read_text()
    assert uds([0x3D, 0x13, 0x01, 0x00, 0x00, 0x02, 0xDE, 0xAD]) == bytes([0x7D, 0x13, 0x01, 0x00, 0x00, 0x02])
    assert uds([0x23, 0x13, 0x01, 0x00, 0x00, 0x03]) == bytes([0x63, 0xDE, 0xAD, CODE[2]])

    assert (workdir / "firmware.s19").read_text() == original
    out = parse_srec(workdir / "firmware.out.s19")
    assert (out[0x010000], out[0x010001], out[0x010002]) == (0xDE, 0xAD, CODE[2])
    assert bytes(out[0x020000 + i] for i in range(8)) == CALIBRATION[:8]


def test_write_calibration_requires_security(client):
    loc = MemoryLocation(0x020000, 2, address_format=32, memorysize_format=8)
    with pytest.raises(NegativeResponseException) as e:
        client.write_memory_by_address(loc, b"\x01\x02")
    assert e.value.response.code == 0x31

    client.change_session(3)
    with pytest.raises(NegativeResponseException) as e:
        client.write_memory_by_address(loc, b"\x01\x02")
    assert e.value.response.code == 0x33

    client.unlock_security_access(1)
    client.write_memory_by_address(loc, b"\x01\x02")
    assert client.read_memory_by_address(loc).service_data.memory_block == b"\x01\x02"


def test_write_length_mismatch(uds):
    assert uds([0x3D, 0x13, 0x01, 0x00, 0x00, 0x02, 0xDE]) == nrc(0x3D, 0x13)
