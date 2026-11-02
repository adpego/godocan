import pytest
from udsoncan.exceptions import NegativeResponseException

from conftest import nrc


def test_read_vin(client):
    resp = client.read_data_by_identifier(0xF190)
    assert resp.service_data.values[0xF190] == "WBA12345678901234"


def test_read_multiple(client):
    resp = client.read_data_by_identifier([0xF190, 0xF189])
    assert resp.service_data.values[0xF189] == (1, 2, 3)


def test_read_unknown(uds):
    assert uds([0x22, 0x12, 0x34]) == nrc(0x22, 0x31)


def test_read_session_restricted(uds):
    assert uds([0x22, 0x01, 0x00]) == nrc(0x22, 0x31)
    uds([0x10, 0x03])
    assert uds([0x22, 0x01, 0x00]) == bytes([0x62, 0x01, 0x00, 0x00, 0x64])


def test_write_then_read(client):
    client.change_session(3)
    client.unlock_security_access(1)
    client.write_data_by_identifier(0x0100, 0x1234)
    assert client.read_data_by_identifier(0x0100).service_data.values[0x0100] == (0x1234,)


def test_write_requires_security(client):
    client.change_session(3)
    with pytest.raises(NegativeResponseException) as e:
        client.write_data_by_identifier(0x0100, 0x1234)
    assert e.value.response.code == 0x33


def test_write_not_writable(uds):
    assert uds([0x2E, 0xF1, 0x90] + list(b"X" * 17)) == nrc(0x2E, 0x31)


def test_write_wrong_length(client, uds):
    client.change_session(3)
    client.unlock_security_access(1)
    assert uds([0x2E, 0x01, 0x00, 0x01]) == nrc(0x2E, 0x13)


def test_write_variable_length(uds):
    assert uds([0x2E, 0x01, 0x01] + list(b"HELLO WORLD")) == bytes([0x6E, 0x01, 0x01])
    assert uds([0x22, 0x01, 0x01]) == bytes([0x62, 0x01, 0x01]) + b"HELLO WORLD"
