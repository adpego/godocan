import struct

from udsoncan import DataFormatIdentifier, Filesize

from conftest import nrc


def test_add_then_read_file(client, uds, workdir):
    content = b"uploaded by the tester " * 3
    resp = client.add_file("logs/new.txt", dfi=DataFormatIdentifier(0, 0), filesize=Filesize(len(content), width=4))
    block = resp.service_data.max_length - 2
    for counter, off in enumerate(range(0, len(content), block), start=1):
        client.transfer_data(counter, content[off:off + block])
    client.request_transfer_exit()
    assert (workdir / "files" / "logs" / "new.txt").read_bytes() == content

    resp = client.read_file("logs/new.txt", dfi=DataFormatIdentifier(0, 0))
    assert resp.service_data.filesize.uncompressed == len(content)
    data, counter = b"", 1
    while len(data) < len(content):
        data += client.transfer_data(counter).service_data.parameter_records
        counter += 1
    client.request_transfer_exit()
    assert data == content


def test_read_dir_and_delete(client, uds, workdir):
    path = b"/"
    resp = uds([0x38, 0x05] + list(struct.pack(">H", len(path))) + list(path))
    assert resp[:2] == bytes([0x78, 0x05])
    assert uds([0x36, 0x01]) == bytes([0x76, 0x01]) + b"readme.txt\n"
    assert uds([0x37]) == bytes([0x77])

    client.delete_file("readme.txt")
    assert not (workdir / "files" / "readme.txt").exists()


def test_cannot_escape_root(uds, workdir):
    path = b"../config.yaml"
    assert uds([0x38, 0x04] + list(struct.pack(">H", len(path))) + list(path) + [0x00]) == nrc(0x38, 0x31)
