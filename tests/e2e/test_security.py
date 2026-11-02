import time

import pytest
from udsoncan.exceptions import NegativeResponseException

from conftest import nrc


def test_unlock_udsoncan(client, uds):
    client.change_session(3)
    client.unlock_security_access(1)
    # Unlocked: requesting the seed again returns zeros.
    assert uds([0x27, 0x01]) == bytes([0x67, 0x01, 0, 0, 0, 0])


def test_level_not_available_in_default_session(uds):
    assert uds([0x27, 0x01]) == nrc(0x27, 0x7E)


def test_invalid_key_and_lockout(uds):
    uds([0x10, 0x03])
    assert uds([0x27, 0x01]) == bytes([0x67, 0x01, 0x11, 0x22, 0x33, 0x44])
    assert uds([0x27, 0x02, 0, 0, 0, 0]) == nrc(0x27, 0x35)
    uds([0x27, 0x01])
    assert uds([0x27, 0x02, 0, 0, 0, 0]) == nrc(0x27, 0x36)
    assert uds([0x27, 0x01]) == nrc(0x27, 0x37)
    time.sleep(1.1)
    assert uds([0x27, 0x01])[0] == 0x67


def test_key_without_seed(uds):
    uds([0x10, 0x03])
    assert uds([0x27, 0x02, 0xBB, 0x99, 0xFF, 0x99]) == nrc(0x27, 0x24)


def test_session_change_relocks(client):
    client.change_session(3)
    client.unlock_security_access(1)
    client.change_session(3)
    with pytest.raises(NegativeResponseException) as e:
        client.write_data_by_identifier(0x0100, 0x1234)
    assert e.value.response.code == 0x33
