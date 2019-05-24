import datetime
import base64
import binascii
import pytest
import pytz

from datetime import datetime

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from ctypes import sizeof, create_string_buffer, memmove, addressof, c_uint8, POINTER
from cryptoauthlib import *
from cryptoauthlib.library import load_cryptoauthlib, get_size_by_name
from cryptoauthlib_mock import atcab_mock


ATCACERT_DEF_DEVICE_VECTOR = bytearray.fromhex(
    '00 00 00 00 02 00 00 0A 00 00 00 07 00 00 00 00'
    '00 00 00 00 00 01 00 00 00 04 00 00 00 04 00 4F'
    '01 00 02 00 00 00 00 01 00 00 40 00 02 00 00 00'
    '0A 00 00 00 48 00 CF 00 40 00 5F 01 4B 00 65 00'
    '0D 00 00 00 00 00 5D 00 04 00 0F 00 10 00 3F 01'
    '14 00 1E 01 14 00 00 00 00 00 00 00 00 00 00 00'
    '00 00 00 00 00 00 00 00 00')

ATCACERT_DEF_DEVICE_CONFIG = {
    'type': atcacert_cert_type_t.CERTTYPE_X509,
    'template_id': 2,
    'chain_id': 0,
    'private_key_slot': 0,
    'sn_source': atcacert_cert_sn_src_t.SNSRC_PUB_KEY_HASH,
    'cert_sn_dev_loc': {
        'zone': atcacert_device_zone_t.DEVZONE_NONE,
        'slot': 0,
        'is_genkey': 0,
        'offset': 0,
        'count': 0
    },
    'issue_date_format': atcacert_date_format_t.DATEFMT_RFC5280_UTC,
    'expire_date_format': atcacert_date_format_t.DATEFMT_RFC5280_GEN,
    'tbs_cert_loc': {'offset': 4, 'count': 335},
    'expire_years': 0,
    'public_key_dev_loc': {
        'zone': atcacert_device_zone_t.DEVZONE_DATA,
        'slot': 0,
        'is_genkey': 1,
        'offset': 0,
        'count': 64
    },
    'comp_cert_dev_loc': {
        'zone': atcacert_device_zone_t.DEVZONE_DATA,
        'slot': 10,
        'is_genkey': 0,
        'offset': 0,
        'count': 72
    },
    'std_cert_elements' : [
        {'offset': 207, 'count': 64},
        {'offset': 351, 'count': 75},
        {'offset': 101, 'count': 13},
        {'offset': 0, 'count': 0},
        {'offset': 93, 'count': 4},
        {'offset': 15, 'count': 16},
        {'offset': 319, 'count': 20},
        {'offset': 286, 'count': 20},
    ]
}

ATCACERT_DEF_DEVICE_TEMPLATE_VECTOR = bytearray([
    0x30, 0x82, 0x01, 0xa6, 0x30, 0x82, 0x01, 0x4b, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x10, 0x41,
    0xa6, 0x8b, 0xe4, 0x36, 0xdd, 0xc3, 0xd8, 0x39, 0xfa, 0xbd, 0xd7, 0x27, 0xd9, 0x74, 0xe7, 0x30,
    0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30, 0x34, 0x31, 0x14, 0x30,
    0x12, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x0b, 0x45, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x20,
    0x49, 0x6e, 0x63, 0x31, 0x1c, 0x30, 0x1a, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x13, 0x45, 0x78,
    0x61, 0x6d, 0x70, 0x6c, 0x65, 0x20, 0x53, 0x69, 0x67, 0x6e, 0x65, 0x72, 0x20, 0x46, 0x46, 0x46,
    0x46, 0x30, 0x20, 0x17, 0x0d, 0x31, 0x37, 0x30, 0x37, 0x31, 0x30, 0x32, 0x30, 0x30, 0x30, 0x30,
    0x30, 0x5a, 0x18, 0x0f, 0x33, 0x30, 0x30, 0x30, 0x31, 0x32, 0x33, 0x31, 0x32, 0x33, 0x35, 0x39,
    0x35, 0x39, 0x5a, 0x30, 0x2f, 0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x0b,
    0x45, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x20, 0x49, 0x6e, 0x63, 0x31, 0x17, 0x30, 0x15, 0x06,
    0x03, 0x55, 0x04, 0x03, 0x0c, 0x0e, 0x45, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x20, 0x44, 0x65,
    0x76, 0x69, 0x63, 0x65, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
    0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x96,
    0x27, 0xf1, 0x3e, 0x80, 0xac, 0xf9, 0xd4, 0x12, 0xce, 0x3b, 0x0d, 0x68, 0xf7, 0x4e, 0xb2, 0xc6,
    0x07, 0x35, 0x00, 0xb7, 0x78, 0x5b, 0xac, 0xe6, 0x50, 0x30, 0x54, 0x77, 0x7f, 0xc8, 0x62, 0x21,
    0xce, 0xf2, 0x5a, 0x9a, 0x9e, 0x86, 0x40, 0xc2, 0x29, 0xd6, 0x4a, 0x32, 0x1e, 0xb9, 0x4a, 0x1b,
    0x1c, 0x94, 0xf5, 0x39, 0x88, 0xae, 0xfe, 0x49, 0xcc, 0xfd, 0xbf, 0x8a, 0x0d, 0x34, 0xb8, 0xa3,
    0x42, 0x30, 0x40, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x2d, 0xda,
    0x6c, 0x36, 0xd5, 0xa5, 0x5a, 0xce, 0x97, 0x10, 0x3d, 0xbb, 0xaf, 0x9c, 0x66, 0x2a, 0xcd, 0x3e,
    0xe6, 0xcf, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0xc6,
    0x70, 0xe0, 0x5e, 0x8a, 0x45, 0x0d, 0xb8, 0x2c, 0x00, 0x2a, 0x40, 0x06, 0x39, 0x4c, 0x19, 0x58,
    0x04, 0x35, 0x76, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03,
    0x49, 0x00, 0x30, 0x46, 0x02, 0x21, 0x00, 0xe1, 0xfc, 0x00, 0x23, 0xc1, 0x3d, 0x01, 0x3f, 0x22,
    0x31, 0x0b, 0xf0, 0xb8, 0xf4, 0xf4, 0x22, 0xfc, 0x95, 0x96, 0x33, 0x9c, 0xb9, 0x62, 0xb1, 0xfc,
    0x8a, 0x2d, 0xa8, 0x5c, 0xee, 0x67, 0x72, 0x02, 0x21, 0x00, 0xa1, 0x0d, 0x47, 0xe4, 0xfd, 0x0d,
    0x15, 0xd8, 0xde, 0xa1, 0xb5, 0x96, 0x28, 0x4e, 0x7a, 0x0b, 0xbe, 0xcc, 0xec, 0xe8, 0x8e, 0xcc,
    0x7a, 0x31, 0xb3, 0x00, 0x8b, 0xc0, 0x2e, 0x4f, 0x99, 0xc5
])


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


def device_cert_sn(size, builder):
    """Cert serial number is the SHA256(Subject public key + Encoded dates)"""

    # Get the public key as X and Y integers concatenated
    pubkey = pubnums_to_bytes(builder._public_key.public_numbers())

    # Get the encoded dates
    expire_years = 0
    enc_dates = bytearray(b'\x00'*3)
    enc_dates[0] = (enc_dates[0] & 0x07) | ((((builder._not_valid_before.year - 2000) & 0x1F) << 3) & 0xFF)
    enc_dates[0] = (enc_dates[0] & 0xF8) | ((((builder._not_valid_before.month) & 0x0F) >> 1) & 0xFF)
    enc_dates[1] = (enc_dates[1] & 0x7F) | ((((builder._not_valid_before.month) & 0x0F) << 7) & 0xFF)
    enc_dates[1] = (enc_dates[1] & 0x83) | (((builder._not_valid_before.day & 0x1F) << 2) & 0xFF)
    enc_dates[1] = (enc_dates[1] & 0xFC) | (((builder._not_valid_before.hour & 0x1F) >> 3) & 0xFF)
    enc_dates[2] = (enc_dates[2] & 0x1F) | (((builder._not_valid_before.hour & 0x1F) << 5) & 0xFF)
    enc_dates[2] = (enc_dates[2] & 0xE0) | ((expire_years & 0x1F) & 0xFF)
    enc_dates = bytes(enc_dates)

    # SAH256 hash of the public key and encoded dates
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(pubkey)
    digest.update(enc_dates)
    raw_sn = bytearray(digest.finalize()[:size])
    raw_sn[0] = raw_sn[0] & 0x7F # Force MSB bit to 0 to ensure positive integer
    raw_sn[0] = raw_sn[0] | 0x40 # Force next bit to 1 to ensure the integer won't be trimmed in ASN.1 DER encoding

    try:
        return int.from_bytes(raw_sn, byteorder='big', signed=False)
    except AttributeError:
        return int(binascii.hexlify(raw_sn), 16)


def create_device_cert(cert_def):
    # Load device public key
    public_key = bytearray(64)
    assert Status.ATCA_SUCCESS == atcab_get_pubkey(cert_def.public_key_dev_loc.slot, public_key)

    # Convert to the key to PEM format
    public_key_pem = bytearray.fromhex('3059301306072A8648CE3D020106082A8648CE3D03010703420004') + public_key
    public_key_pem = '-----BEGIN PUBLIC KEY-----\n' + base64.b64encode(public_key_pem).decode('ascii') + '\n-----END PUBLIC KEY-----'

    # Convert the key into the cryptography format
    public_key = serialization.load_pem_public_key(public_key_pem.encode('ascii'), default_backend())

    # Create the private key
    signer_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    signer_public_key = signer_private_key.public_key()

    # Create the certificate builder
    builder = x509.CertificateBuilder()

    # Ordinarily we'd construct a signer cert first, but we'll skip that and just create the fields we need
    builder = builder.issuer_name(x509.Name([
        x509.NameAttribute(x509.oid.NameOID.ORGANIZATION_NAME, u'Example Inc'),
        x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, u'Example Signer FFFF')]))

    # Device cert must have minutes and seconds set to 0
    builder = builder.not_valid_before(datetime.now(tz=pytz.utc).replace(minute=0, second=0))

    # Should be year 9999, but this doesn't work on windows
    builder = builder.not_valid_after(datetime(3000, 12, 31, 23, 59, 59))

    builder = builder.subject_name(x509.Name([
        x509.NameAttribute(x509.oid.NameOID.ORGANIZATION_NAME, u'Example Inc'),
        x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, u'Example Device')]))

    builder = builder.public_key(public_key)

    # Device certificate is generated from certificate dates and public key
    builder = builder.serial_number(device_cert_sn(16, builder))

    # Subject Key ID is used as the thing name and MQTT client ID and is required for this demo
    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(public_key),
        critical=False)

    # Add the authority key id from the signer key
    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(signer_public_key),
        critical=False)

    # Sign certificate
    device_cert = builder.sign(private_key=signer_private_key, algorithm=hashes.SHA256(), backend=default_backend())

    # Get the certificate bytes
    device_cert_bytes = device_cert.public_bytes(encoding=serialization.Encoding.DER)

    # Convert the signer public key into the uncompressed numbers format
    signer_public_key_bytes = pubnums_to_bytes(signer_public_key.public_numbers())

    return device_cert_bytes, signer_public_key_bytes

@pytest.fixture
def test_atcacert_init():
    """
    Run tests against the library mock
    """
    load_cryptoauthlib(atcab_mock())


@pytest.fixture
def test_atcacert_init_lib(test_init_with_lib):
    """
    Run tests against a built library on the platform
    """
    load_cryptoauthlib()


@pytest.fixture
def test_atcacert_init_live(test_init_with_device):
    """
    Use real hardware for these tests - otherwise skip
    """
    load_cryptoauthlib()
    if Status.ATCA_SUCCESS != atcab_init(cfg_ateccx08a_kithid_default()):
        raise Exception('Unable to connect to a device')


@pytest.mark.parametrize("struct_name", [
    pytest.param('atcacert_device_loc_t'),
    pytest.param('atcacert_cert_loc_t'),
    pytest.param('atcacert_cert_element_t'),
    pytest.param('atcacert_def_t'),
    pytest.param('atcacert_tm_utc_t')
])
def test_atcacert_struct_sizes(test_atcacert_init_lib, struct_name):
    assert sizeof(eval(struct_name)) == get_size_by_name(struct_name)

# --------------------ATCACERT_DEF----------------------

def test_atcacert_get_response(test_atcacert_init):
    device_private_key_slot = 1
    challenge = bytearray(32)
    response = bytearray(64)
    assert atcacert_get_response(device_private_key_slot, challenge, response) == CertStatus.ATCACERT_E_SUCCESS
    assert response == bytearray(atcab_mock.r_response)


def test_atcacert_read_cert(test_atcacert_init):
    cert_def = atcacert_def_t()
    ca_public_key = bytearray(64)
    cert = bytearray(65)
    cert_size = AtcaReference(len(cert))
    assert atcacert_read_cert(cert_def, ca_public_key, cert, cert_size) == CertStatus.ATCACERT_E_SUCCESS
    assert cert == bytearray(atcab_mock.r_cert)
    assert cert_size.value == atcab_mock.r_cert_size.value


def test_atcacert_write_cert(test_atcacert_init):
    cert_def = atcacert_def_t()
    cert = bytearray(64)
    cert_size = 64
    assert atcacert_write_cert(cert_def, cert, cert_size) == CertStatus.ATCACERT_E_SUCCESS


def test_atcacert_create_csr(test_atcacert_init):
    csr_def = atcacert_def_t()
    csr = bytearray(65)
    csr_size = AtcaReference(len(csr))
    assert atcacert_create_csr(csr_def, csr, csr_size) == CertStatus.ATCACERT_E_SUCCESS
    assert csr == bytearray(atcab_mock.r_csr)
    assert csr_size.value == atcab_mock.r_csr_size.value


def test_atcacert_create_csr_pem(test_atcacert_init):
    csr_def = atcacert_def_t()
    csr = bytearray(65)
    csr_size = AtcaReference(len(csr))
    assert atcacert_create_csr_pem(csr_def, csr, csr_size) == CertStatus.ATCACERT_E_SUCCESS
    assert csr == bytearray(atcab_mock.r_csr)
    assert csr_size.value == atcab_mock.r_csr_size.value

def test_atacert_max_cert_size(test_atcacert_init):
    cert_def = atcacert_def_t()
    max_cert_size = AtcaReference(0)
    assert atcacert_max_cert_size(cert_def, max_cert_size) == CertStatus.ATCACERT_E_SUCCESS
    assert max_cert_size.value == atcab_mock.r_max_cert_size.value

# --------------------ATCACERT_DATE----------------------

def test_atcacert_tm_utc_t():
    timestamp = atcacert_tm_utc_t(1, 2, 3, 4, 5, 1990)
    assert timestamp.tm_sec == 1
    assert timestamp.tm_min == 2
    assert timestamp.tm_hour == 3
    assert timestamp.tm_mday == 4
    assert timestamp.tm_mon == 5
    assert timestamp.tm_year == 90


def test_atcacert_tm_utc_t_empty_params():
    c = datetime.utcnow()
    t = atcacert_tm_utc_t()
    assert t.tm_min == c.minute
    assert t.tm_hour == c.hour
    assert t.tm_mday == c.day
    assert t.tm_mon == c.month - 1


@pytest.mark.parametrize("sec,min,hour,day,mon,year", [
    pytest.param(-1, 2, 3, 4, 5, 1990, id='Seconds'),
    pytest.param(1, -1, 3, 4, 5, 1990, id='Minutes'),
    pytest.param(1, 2, -1, 4, 5, 1990, id='Hours'),
    pytest.param(1, 2, 3, 0, 5, 1990, id='Days'),
    pytest.param(1, 2, 3, 4, -1, 1990, id='Months'),
    pytest.param(1, 2, 3, 4, 5, -1, id='Years')
])
def test_atcacert_tm_utc_t_invalid_low(sec, min, hour, day, mon, year):
    with pytest.raises(ValueError):
        timestamp = atcacert_tm_utc_t(sec, min, hour, day, mon, year)

@pytest.mark.parametrize("sec,min,hour,day,mon,year", [
    pytest.param(60, 2, 3, 4, 5, 1990, id='Seconds'),
    pytest.param(1, 60, 3, 4, 5, 1990, id='Minutes'),
    pytest.param(1, 2, 24, 4, 5, 1990, id='Hours'),
    pytest.param(1, 2, 3, 32, 5, 1990, id='Days'),
    pytest.param(1, 2, 3, 4, 12, 1990, id='Months'),
])
def test_atcacert_tm_utc_t_invalid_high(sec, min, hour, day, mon, year):
    with pytest.raises(ValueError):
        timestamp = atcacert_tm_utc_t(sec, min, hour, day, mon, year)


def test_atcacert_date_enc(test_atcacert_init_lib):
    date_format = atcacert_date_format_t.DATEFMT_RFC5280_UTC
    timestamp = atcacert_tm_utc_t(1, 1, 1, 1, 1, 1990)
    formatted_date = bytearray(23)
    formatted_date_size = AtcaReference(len(formatted_date))
    assert atcacert_date_enc(date_format, timestamp, formatted_date, formatted_date_size) == CertStatus.ATCACERT_E_SUCCESS
    assert formatted_date == bytearray(b'900201010101Z')
    assert formatted_date_size.value == len(formatted_date)


def test_atcacert_date_dec(test_atcacert_init_lib):
    date_format = atcacert_date_format_t.DATEFMT_RFC5280_UTC
    formatted_date = bytearray(b'910201010112Z')
    formatted_date_size = len(formatted_date)
    timestamp = atcacert_tm_utc_t(1, 1, 1, 1, 1, 1990)
    assert atcacert_date_dec(date_format, formatted_date, formatted_date_size, timestamp) == CertStatus.ATCACERT_E_SUCCESS
    assert timestamp.tm_sec == 12
    assert timestamp.tm_year == 91


def test_atcacert_date_enc_compcert(test_atcacert_init_lib):
    issue_date = atcacert_tm_utc_t(0, 0, 10, 7, 2, 2021)
    expire_date = 28
    enc_dates = bytearray(3)
    assert atcacert_date_enc_compcert(issue_date, expire_date, enc_dates) == CertStatus.ATCACERT_E_SUCCESS
    assert enc_dates == bytearray([0xA9, 0x9D, 0x5C])


def test_atcacert_date_dec_compcert(test_atcacert_init_lib):
    enc_dates = bytearray([0xA9, 0x9D, 0x5C])
    expire_date_format = atcacert_date_format_t.DATEFMT_RFC5280_UTC

    issue_date_ref = atcacert_tm_utc_t(0, 0, 10, 7, 2, 2021)
    expire_date_ref = atcacert_tm_utc_t(0, 0, 10, 7, 2, 2049)

    issue_date = atcacert_tm_utc_t()
    expire_date = atcacert_tm_utc_t()
    assert atcacert_date_dec_compcert(enc_dates, expire_date_format, issue_date, expire_date) == CertStatus.ATCACERT_E_SUCCESS

    for n, _ in issue_date._fields_:
        assert getattr(issue_date, n) == getattr(issue_date_ref, n)
    for n, _ in expire_date._fields_:
        assert getattr(expire_date, n) == getattr(expire_date_ref, n)


def test_atcacert_date_get_max_date(test_atcacert_init_lib):
    date_format = atcacert_date_format_t.DATEFMT_RFC5280_UTC
    timestamp = atcacert_tm_utc_t(1, 2, 3, 4, 5, 1990)
    assert atcacert_date_get_max_date(date_format, timestamp) == CertStatus.ATCACERT_E_SUCCESS
    assert timestamp.tm_year == 2049 - 1900


def test_atcacert_round_trip_qa(test_atcacert_init_live):
    """
    This test performs a round trip QA check with a live device based on the certificate definition
    """

    # Create a certdef object from the configuration
    cert_def = atcacert_def_t(**ATCACERT_DEF_DEVICE_CONFIG)

    # Attach the template to the cert_def
    cert_def.cert_template_size = len(ATCACERT_DEF_DEVICE_TEMPLATE_VECTOR)
    cert_def.cert_template = POINTER(c_uint8)(create_string_buffer(bytes(ATCACERT_DEF_DEVICE_TEMPLATE_VECTOR),
                                                                   cert_def.cert_template_size))

    # Create a device certificate using the device key information and test signing key
    (cert, ca_pub_key) = create_device_cert(cert_def)

    # Write the device certificate
    assert CertStatus.ATCACERT_E_SUCCESS == atcacert_write_cert(cert_def, cert, len(cert))

    # Read back the device certificate
    qa_cert_len = AtcaReference(0)
    assert CertStatus.ATCACERT_E_SUCCESS == atcacert_max_cert_size(cert_def, qa_cert_len)
    qa_cert = bytearray(qa_cert_len.value)
    assert CertStatus.ATCACERT_E_SUCCESS == atcacert_read_cert(cert_def, ca_pub_key, qa_cert, qa_cert_len)

    print('Input: ', len(cert))
    print(pretty_print_hex(cert))
    print('Output:', qa_cert_len, len(qa_cert))
    print(pretty_print_hex(qa_cert))

    assert cert == bytes(qa_cert)
    atcab_release()
