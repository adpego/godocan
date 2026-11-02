import time

from udsoncan import DynamicDidDefinition

from conftest import nrc


def test_periodic_dynamic_did(client, uds):
    client.dynamically_define_did(0xF201, DynamicDidDefinition(source_did=0xF190, position=1, memorysize=3))
    assert uds([0x2A, 0x03, 0x01]) == bytes([0x6A])
    start = time.monotonic()
    received = [uds.receive() for _ in range(3)]
    assert received == [bytes([0x6A, 0x01]) + b"WBA"] * 3
    assert time.monotonic() - start < 1.0  # fast rate: 50 ms

    assert uds([0x2A, 0x04, 0x01]) == bytes([0x6A])
    time.sleep(0.1)
    while uds.receive(timeout=0.05) is not None:
        pass  # messages sent before the stop
    assert uds.receive(timeout=0.3) is None


def test_periodic_unknown_did(uds):
    assert uds([0x2A, 0x01, 0x55]) == nrc(0x2A, 0x31)
