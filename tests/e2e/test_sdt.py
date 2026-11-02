import hashlib
import hmac
import struct

from conftest import nrc

SECRET = bytes.fromhex("C0FFEE")
REQUEST, SIGNED, RESPONSE_SIGNATURE = 0x0001, 0x0010, 0x0020


def secured(apar, counter, internal, sign=False):
    body = struct.pack(">HBHH", apar, 0, 32 if sign else 0, counter) + bytes(internal)
    sig = hmac.new(SECRET, body, hashlib.sha256).digest() if sign else b""
    return list(b"\x84" + body + sig)


def test_signed_read(uds):
    resp = uds(secured(REQUEST | SIGNED | RESPONSE_SIGNATURE, 1, [0x22, 0xF1, 0x90], sign=True))
    body, sig = resp[1:-32], resp[-32:]
    assert resp[0] == 0xC4
    assert sig == hmac.new(SECRET, body, hashlib.sha256).digest()
    assert body[7:] == bytes([0x62, 0xF1, 0x90]) + b"WBA12345678901234"


def test_bad_signature_and_replay(uds):
    req = secured(REQUEST | SIGNED, 1, [0x22, 0xF1, 0x90], sign=True)
    req[-1] ^= 0xFF
    assert uds(req) == nrc(0x84, 0x38)
    assert uds(secured(REQUEST, 2, [0x3E, 0x00]))[0] == 0xC4
    assert uds(secured(REQUEST, 2, [0x3E, 0x00])) == nrc(0x84, 0x38)
