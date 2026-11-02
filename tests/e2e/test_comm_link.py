from udsoncan import Baudrate, CommunicationType

from conftest import nrc


def test_communication_control(client):
    resp = client.communication_control(0x03, CommunicationType(subnet=0, normal_msg=True, network_management_msg=True))
    assert resp.service_data.control_type_echo == 0x03


def test_communication_control_invalid_type(uds):
    assert uds([0x28, 0x00, 0x00]) == nrc(0x28, 0x31)


def test_link_control_fixed(client, uds):
    assert uds([0x87, 0x03]) == nrc(0x87, 0x24)
    client.link_control(0x01, Baudrate(500000, baudtype=Baudrate.Type.Fixed))
    client.link_control(0x03)


def test_link_control_specific(client):
    client.link_control(0x02, Baudrate(500000, baudtype=Baudrate.Type.Specific))
    client.link_control(0x03)
