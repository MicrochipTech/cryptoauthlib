import pytest
import datetime
import time
import base64

from cryptoauthlib import *
from cryptoauthlib.library import load_cryptoauthlib
from cryptoauthlib_mock import atcab_mock

__config = cfg_ateccx08a_kithid_default()

def pretty_print_hex(a, l=16, indent=''):
    """
    Format a list/bytes/bytearray object into a formatted ascii hex string
    """
    s = ''
    a = bytearray(a)
    for x in range(0, len(a), l):
        s += indent + ''.join(['%02X ' % y for y in a[x:x+l]]) + '\n'
    return s


def pubnums_to_bytes(pub_nums):
    return bytes(bytearray.fromhex('%064X%064X' % (pub_nums.x, pub_nums.y)))


@pytest.fixture
def test_jwt_init():
    """
    Run tests against the library mock
    """
    load_cryptoauthlib(atcab_mock())


@pytest.fixture
def test_jwt_init_live(test_init_with_device):
    """
    Use real hardware for these tests - otherwise skip
    """
    load_cryptoauthlib()

    if Status.ATCA_SUCCESS != atcab_init(__config):
        raise Exception('Unable to connect to a device')

    # Check device type
    info = bytearray(4)
    assert Status.ATCA_SUCCESS == atcab_info(info)
    dev_type = get_device_type_id(get_device_name(info))

    if dev_type != __config.devtype:
        __config.devtype = dev_type
        assert Status.ATCA_SUCCESS == atcab_release()
        time.sleep(1)
        assert Status.ATCA_SUCCESS == atcab_init(__config)


@pytest.mark.parametrize("slot, config", [
    pytest.param(0, None, id='Normal'),
    pytest.param(0, __config, id='Init/Reinit'),
])
def test_jwt_round_trip_ec_qa(test_jwt_init_live, slot, config):
    """
    Test JWT with an asymetric key (Elliptic Curve: SECP256r1)
    """
    # Load device public key
    public_key = bytearray(64)
    assert Status.ATCA_SUCCESS == atcab_get_pubkey(0, public_key)

    # Convert to the key to PEM format
    public_key_pem = bytearray.fromhex('3059301306072A8648CE3D020106082A8648CE3D03010703420004') + public_key
    public_key_pem = '-----BEGIN PUBLIC KEY-----\n' + base64.b64encode(public_key_pem).decode('ascii') + '\n-----END PUBLIC KEY-----'

    claims = {
        # The time that the token was issued at
        'iat': datetime.datetime.utcnow(),
        # The time the token expires.
        'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=60),
        # A Dummy/Test Audience to verify against
        'aud': 'test_audience'
    }

    token = PyJWT(slot, config)
    encoded = token.encode(claims, public_key_pem, algorithm='ES256')

    # If the audience does not match or the signature fails to verify the following will raise an exception
    decoded = token.decode(encoded, public_key_pem, audience=claims['aud'], algorithms=['ES256'])

    assert claims == decoded


@pytest.mark.parametrize("slot, config", [
    pytest.param(1, None, id='Normal'),
    pytest.param(1, __config, id='Init/Reinit'),
])
def test_jwt_round_trip_hmac_qa(test_jwt_init_live, slot, config):
    """
    Check JWT with a symmetric key (SHA256 based HMAC)
    """
    # Set write key
    write_key = bytearray([0x37, 0x80, 0xe6, 0x3d, 0x49, 0x68, 0xad, 0xe5,
                           0xd8, 0x22, 0xc0, 0x13, 0xfc, 0xc3, 0x23, 0x84,
                           0x5d, 0x1b, 0x56, 0x9f, 0xe7, 0x05, 0xb6, 0x00,
                           0x06, 0xfe, 0xec, 0x14, 0x5a, 0x0d, 0xb1, 0xe3])
    assert Status.ATCA_SUCCESS == atcab_write_zone(2, 4, 0, 0, write_key, 32);

    # Write HMAC key
    hmac_key = bytearray([0x73, 0x16, 0xe9, 0x64, 0x2b, 0x38, 0xfb, 0xad,
                          0x5d, 0xb7, 0x0a, 0x1b, 0x33, 0xf0, 0xdc, 0xb9,
                          0x4c, 0x35, 0x5e, 0x78, 0xd7, 0xf0, 0x00, 0xa9,
                          0xb3, 0x19, 0x41, 0xa0, 0x36, 0x0d, 0x09, 0x61])
    assert Status.ATCA_SUCCESS == atcab_write_enc(slot, 0, hmac_key, write_key, 4);

    claims = {
        # The time that the token was issued at
        'iat': datetime.datetime.utcnow(),
        # The time the token expires.
        'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=60),
        # A Dummy/Test Audience to verify against
        'aud': 'test_audience'
    }
    
    token = PyJWT(slot, config)
    encoded = token.encode(claims, b'', algorithm='HS256')

    # If the audience does not match or the signature fails to verify the following will raise an exception
    decoded = token.decode(encoded, bytes(hmac_key), audience=claims['aud'], algorithms=['HS256'])

    assert claims == decoded


