import hashlib
import hmac
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from udsoncan.exceptions import NegativeResponseException

from conftest import nrc

PKI = Path(__file__).with_name("pki")
SECRET = bytes.fromhex("0011223344556677")
ALGORITHM = bytes(16)


def der(name):
    return x509.load_pem_x509_certificate((PKI / name).read_bytes()).public_bytes(serialization.Encoding.DER)


def load_tester_key():
    return serialization.load_pem_private_key((PKI / "tester.key").read_bytes(), password=None)


def read_protected(uds):
    return uds([0x22, 0xF1, 0x8A])


def test_configuration(client):
    assert client.authentication_configuration().service_data.return_value == 0x02


def test_apce_unidirectional(client, uds):
    assert read_protected(uds) == nrc(0x22, 0x33)
    resp = client.authentication(0x01, communication_configuration=0, certificate_client=der("tester.pem"), challenge_client=b"")
    challenge = resp.service_data.challenge_server
    proof = load_tester_key().sign(challenge, ec.ECDSA(hashes.SHA256()))
    resp = client.authentication(0x03, proof_of_ownership_client=proof, ephemeral_public_key_client=b"")
    assert resp.service_data.return_value == 0x12
    assert read_protected(uds) == bytes([0x62, 0xF1, 0x8A]) + b"AUTH-ONLY"

    client.deauthenticate()
    assert read_protected(uds) == nrc(0x22, 0x33)


def test_apce_bidirectional(client):
    client_challenge = b"tester challenge"
    resp = client.authentication(0x02, communication_configuration=0, certificate_client=der("tester.pem"), challenge_client=client_challenge)
    sd = resp.service_data
    server_cert = x509.load_der_x509_certificate(sd.certificate_server)
    assert server_cert.subject.rfc4514_string() == "CN=godoip ECU"
    server_cert.public_key().verify(sd.proof_of_ownership_server, client_challenge, ec.ECDSA(hashes.SHA256()))

    proof = load_tester_key().sign(sd.challenge_server, ec.ECDSA(hashes.SHA256()))
    client.authentication(0x03, proof_of_ownership_client=proof, ephemeral_public_key_client=b"")


def test_apce_wrong_key(client):
    client.authentication(0x01, communication_configuration=0, certificate_client=der("tester.pem"), challenge_client=b"")
    other = ec.generate_private_key(ec.SECP256R1())
    with pytest.raises(NegativeResponseException) as e:
        client.authentication(0x03, proof_of_ownership_client=other.sign(b"x", ec.ECDSA(hashes.SHA256())), ephemeral_public_key_client=b"")
    assert e.value.response.code == 0x58


def test_untrusted_certificate(client):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "intruder")])
    import datetime
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=1)).sign(key, hashes.SHA256()))
    with pytest.raises(NegativeResponseException) as e:
        client.authentication(0x01, communication_configuration=0,
                              certificate_client=cert.public_bytes(serialization.Encoding.DER), challenge_client=b"")
    assert e.value.response.code == 0x52


def test_acr_bidirectional(client, uds):
    resp = client.request_challenge_for_authentication(communication_configuration=0, algorithm_indicator=ALGORITHM)
    challenge = resp.service_data.challenge_server
    client_challenge = b"abc"
    resp = client.authentication(0x07, algorithm_indicator=ALGORITHM,
                                 proof_of_ownership_client=hmac.new(SECRET, challenge, hashlib.sha256).digest(),
                                 challenge_client=client_challenge, additional_parameter=b"")
    assert resp.service_data.proof_of_ownership_server == hmac.new(SECRET, client_challenge, hashlib.sha256).digest()
    assert read_protected(uds)[0] == 0x62
