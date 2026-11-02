import time

from udsoncan.exceptions import NegativeResponseException

from conftest import nrc


def test_change_session_raw(uds):
    assert uds([0x10, 0x03]) == bytes([0x50, 0x03, 0x00, 0x19, 0x00, 0xC8])
    assert uds([0x10, 0x01]) == bytes([0x50, 0x01, 0x00, 0x32, 0x01, 0xF4])


def test_change_session_udsoncan(client):
    resp = client.change_session(3)
    assert resp.positive
    assert resp.service_data.session_param_records == bytes([0x00, 0x19, 0x00, 0xC8])


def test_unknown_session(uds):
    assert uds([0x10, 0x04]) == nrc(0x10, 0x12)


def test_transition_not_allowed(uds):
    assert uds([0x10, 0x02]) == nrc(0x10, 0x7E)
    assert uds([0x10, 0x03])[0] == 0x50
    assert uds([0x10, 0x02])[0] == 0x50


def test_suppress_positive_response(uds):
    assert uds([0x10, 0x83], timeout=0.3) is None
    # The session changed: programming is now reachable.
    resp = uds([0x10, 0x02])
    assert resp[0] == 0x50, resp.hex()


def test_s3_timeout(uds):
    assert uds([0x10, 0x03])[0] == 0x50
    time.sleep(4.5)
    # Back in default: programming is not reachable anymore.
    assert uds([0x10, 0x02]) == nrc(0x10, 0x7E)


def test_tester_present_keeps_session(client, uds):
    client.change_session(3)
    for _ in range(3):
        time.sleep(1.5)
        client.tester_present()
    assert uds([0x10, 0x02])[0] == 0x50


def test_functional_tester_present_suppressed(uds):
    assert uds.functional([0x3E, 0x80], timeout=0.3) is None
    assert uds.functional([0x3E, 0x00]) == bytes([0x7E, 0x00])


def test_unsupported_service(uds):
    assert uds([0xBA, 0x01]) == nrc(0xBA, 0x11)


def test_unsupported_service_functional_is_silent(uds):
    assert uds.functional([0xBA, 0x01], timeout=0.3) is None


def test_udsoncan_negative_response(client):
    try:
        client.change_session(4)
    except NegativeResponseException as e:
        assert e.response.code == 0x12
    else:
        raise AssertionError("expected a negative response")
