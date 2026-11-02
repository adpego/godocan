from udsoncan import Dtc

from conftest import nrc


def codes(dtcs):
    return {d.id: d.status.get_byte_as_int() for d in dtcs}


def test_number_of_dtcs(client):
    resp = client.get_number_of_dtc_by_status_mask(0x08)
    assert resp.service_data.dtc_count == 2


def test_dtcs_by_status_mask(client):
    resp = client.get_dtc_by_status_mask(0x08)
    assert codes(resp.service_data.dtcs) == {0x010100: 0x09, 0xC10000: 0x08}


def test_supported_dtcs(client):
    resp = client.get_supported_dtc()
    assert codes(resp.service_data.dtcs) == {0x010100: 0x09, 0x030000: 0x04, 0xC10000: 0x08}


def test_snapshot(uds):
    resp = uds([0x19, 0x04, 0x01, 0x01, 0x00, 0x01])
    assert resp == bytes([0x59, 0x04, 0x01, 0x01, 0x00, 0x09, 0x01, 0x01, 0xF4, 0x0C, 0x0B, 0xB8])


def test_extended_data(client):
    resp = client.get_dtc_extended_data_by_dtc_number(0x010100, 0x01, data_size=1)
    assert resp.service_data.dtcs[0].extended_data[0].raw_data == b"\x05"


def test_permanent(client):
    resp = client.get_dtc_with_permanent_status()
    assert codes(resp.service_data.dtcs) == {0xC10000: 0x08}


def test_clear_all(client):
    client.clear_dtc(0xFFFFFF)
    assert client.get_number_of_dtc_by_status_mask(0x0F).service_data.dtc_count == 0


def test_clear_unknown_group(uds):
    assert uds([0x14, 0x12, 0x34, 0x56]) == nrc(0x14, 0x31)


def test_dtc_setting_blocks_routine_effect(client, uds):
    client.control_dtc_setting(2)  # off
    client.start_routine(0x0300)
    client.stop_routine(0x0300)
    assert uds([0x19, 0x02, 0x01]) == bytes([0x59, 0x02, 0xFF, 0x01, 0x01, 0x00, 0x09])
    client.control_dtc_setting(1)  # on
    client.start_routine(0x0300)
    resp = client.get_dtc_by_status_mask(0x01)
    assert 0x030000 in codes(resp.service_data.dtcs)


def test_dtc_by_severity(client):
    resp = client.get_dtc_by_status_severity_mask(status_mask=0xFF, severity_mask=0x80)
    assert [d.id for d in resp.service_data.dtcs] == [0x010100]
    assert resp.service_data.dtcs[0].severity.check_immediately
