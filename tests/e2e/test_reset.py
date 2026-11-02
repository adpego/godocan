from conftest import nrc


def test_hard_reset_udsoncan(client):
    resp = client.ecu_reset(1)
    assert resp.positive


def test_reset_returns_to_default_session(uds):
    uds([0x10, 0x03])
    assert uds([0x11, 0x01]) == bytes([0x51, 0x01])
    assert uds([0x22, 0x01, 0x00]) == nrc(0x22, 0x31)  # extended-only DID


def test_reset_restores_volatile_did(uds):
    uds([0x2E, 0x01, 0x01] + list(b"CHANGED"))
    assert uds([0x11, 0x03]) == bytes([0x51, 0x03])
    assert uds([0x22, 0x01, 0x01]) == bytes([0x62, 0x01, 0x01]) + b"GODCAN"


def test_rapid_power_shutdown(client):
    resp = client.ecu_reset(4)
    assert resp.service_data.powerdown_time == 10


def test_unsupported_reset_type(uds):
    assert uds([0x11, 0x02]) == nrc(0x11, 0x12)
