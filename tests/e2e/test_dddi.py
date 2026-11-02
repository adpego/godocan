from udsoncan import DynamicDidDefinition, MemoryLocation

from conftest import nrc


def test_read_scaling_data_with_response_pending(uds):
    # Configured to answer NRC 0x78 twice before the final response.
    assert uds([0x24, 0xF1, 0x89]) == nrc(0x24, 0x78)
    assert uds.receive() == nrc(0x24, 0x78)
    assert uds.receive() == bytes([0x64, 0xF1, 0x89, 0x41, 0x02])
    assert uds([0x24, 0xF1, 0x90]) == nrc(0x24, 0x78)
    uds.receive()
    assert uds.receive() == nrc(0x24, 0x31)


def test_define_by_identifier(client, uds):
    d = DynamicDidDefinition(source_did=0xF190, position=1, memorysize=3)
    d.add(source_did=0xF189, position=2, memorysize=2)
    client.dynamically_define_did(0xF200, d)
    assert uds([0x22, 0xF2, 0x00]) == bytes([0x62, 0xF2, 0x00]) + b"WBA" + bytes([0x02, 0x03])


def test_define_by_memory_address(client, uds):
    d = DynamicDidDefinition(MemoryLocation(0x020008, 4, address_format=32, memorysize_format=8))
    client.dynamically_define_did(0xF201, d)
    assert uds([0x22, 0xF2, 0x01]) == bytes([0x62, 0xF2, 0x01]) + b"CALI"


def test_clear_dynamic_did(client, uds):
    client.dynamically_define_did(0xF200, DynamicDidDefinition(source_did=0xF190, position=1, memorysize=1))
    client.clear_dynamically_defined_did(0xF200)
    assert uds([0x22, 0xF2, 0x00]) == nrc(0x22, 0x31)
