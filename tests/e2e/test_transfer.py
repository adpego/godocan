from udsoncan import DataFormatIdentifier, MemoryLocation

from conftest import nrc
from test_memory import CODE, parse_srec


def loc(addr, size):
    return MemoryLocation(addr, size, address_format=32, memorysize_format=32)


def test_flash_download(client, workdir):
    image = bytes(range(0x40))
    resp = client.request_download(loc(0x010000, len(image)), dfi=DataFormatIdentifier(0, 0))
    block = resp.service_data.max_length - 2
    assert block == 32

    for counter, off in enumerate(range(0, len(image), block), start=1):
        client.transfer_data(counter & 0xFF, image[off:off + block])
    client.request_transfer_exit()

    read = client.read_memory_by_address(loc(0x010000, len(image)))
    assert read.service_data.memory_block == image
    out = parse_srec(workdir / "firmware.out.s19")
    assert bytes(out[0x010000 + i] for i in range(len(image))) == image


def test_upload(client):
    resp = client.request_upload(loc(0x010000, 40), dfi=DataFormatIdentifier(0, 0))
    block = resp.service_data.max_length - 2
    data = b""
    counter = 1
    while len(data) < 40:
        data += client.transfer_data(counter).service_data.parameter_records
        counter += 1
    client.request_transfer_exit()
    assert data == CODE[:40]
    assert block == 32


def test_transfer_without_request(uds):
    assert uds([0x36, 0x01, 0x00]) == nrc(0x36, 0x24)
    assert uds([0x37]) == nrc(0x37, 0x24)


def test_wrong_block_counter(uds):
    assert uds([0x34, 0x00, 0x44, 0, 1, 0, 0, 0, 0, 0, 4])[0] == 0x74
    assert uds([0x36, 0x02, 1, 2, 3, 4]) == nrc(0x36, 0x73)
