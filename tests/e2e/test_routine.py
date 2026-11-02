import time

import pytest
from udsoncan.exceptions import NegativeResponseException

from conftest import nrc


def test_erase_routine_udsoncan(client, uds):
    client.change_session(3)
    resp = client.start_routine(0xFF00)
    assert resp.service_data.routine_status_record == b"\x00"
    # In progress, then finished.
    assert client.get_routine_result(0xFF00).service_data.routine_status_record == b"\x01"
    time.sleep(1.1)
    assert client.get_routine_result(0xFF00).service_data.routine_status_record == b"\x00"
    # The erase effect is visible through ReadMemoryByAddress.
    assert uds([0x23, 0x13, 0x01, 0x00, 0x00, 0x04]) == bytes([0x63, 0xFF, 0xFF, 0xFF, 0xFF])


def test_routine_not_in_session(uds):
    assert uds([0x31, 0x01, 0xFF, 0x00]) == nrc(0x31, 0x31)


def test_results_before_start(client):
    client.change_session(3)
    with pytest.raises(NegativeResponseException) as e:
        client.get_routine_result(0xFF00)
    assert e.value.response.code == 0x24


def test_start_stop_with_did_effect(client, uds):
    client.start_routine(0x0300)
    assert uds([0x22, 0x01, 0x01]) == bytes([0x62, 0x01, 0x01]) + b"ACTIVE"
    assert uds([0x31, 0x01, 0x03, 0x00]) == nrc(0x31, 0x24)  # already running
    client.stop_routine(0x0300)
    assert uds([0x31, 0x02, 0x03, 0x00]) == nrc(0x31, 0x24)  # not running


def test_cases_by_option_record(uds):
    assert uds([0x31, 0x01, 0xFF, 0x01, 0x00, 0x00, 0x00, 0x00]) == bytes([0x71, 0x01, 0xFF, 0x01, 0x00])
    assert uds([0x31, 0x01, 0xFF, 0x01, 0xDE, 0xAD, 0xBE, 0xEF]) == bytes([0x71, 0x01, 0xFF, 0x01, 0x01])
    assert uds([0x31, 0x01, 0xFF, 0x01, 0x00]) == nrc(0x31, 0x13)


def test_unknown_routine(uds):
    assert uds([0x31, 0x01, 0x12, 0x34]) == nrc(0x31, 0x31)
