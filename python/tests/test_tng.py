import pytest

from cryptoauthlib import *
from cryptoauthlib.library import load_cryptoauthlib, get_size_by_name
from cryptoauthlib_mock import atcab_mock


@pytest.fixture
def test_tng_init():
    """
    Run tests against the library mock
    """
    load_cryptoauthlib(atcab_mock())


@pytest.fixture
def test_tng_init_lib(test_init_with_lib):
    """
    Run tests against a built library on the platform
    """
    load_cryptoauthlib()


@pytest.fixture
def test_tng_init_live(test_init_with_device):
    """
    Use real hardware for these tests - otherwise skip
    """
    load_cryptoauthlib()
    if Status.ATCA_SUCCESS != atcab_init(cfg_ateccx08a_kithid_default()):
        raise Exception('Unable to connect to a device')


def test_tng_get_device_pubkey(test_tng_init):
    public_key = bytearray(64)
    assert tng_get_device_pubkey(public_key) == Status.ATCA_SUCCESS
    assert public_key == bytearray(atcab_mock.r_genkey_pubkey)


def test_tng_atcacert_max_device_cert_size(test_tng_init):
    max_cert_size = AtcaReference(0)
    assert tng_atcacert_max_device_cert_size(max_cert_size) == CertStatus.ATCACERT_E_SUCCESS
    assert max_cert_size.value == atcab_mock.r_max_cert_size.value


def test_tng_atcacert_read_device_cert_no_signer(test_tng_init):
    cert = bytearray(1024)
    cert_size = AtcaReference(len(cert))
    assert tng_atcacert_read_device_cert(cert, cert_size) == CertStatus.ATCACERT_E_SUCCESS
    assert cert_size.value == atcab_mock.r_cert_size.value
    assert cert == bytearray(atcab_mock.r_cert)


def test_tng_atcacert_read_device_cert_signer(test_tng_init):
    cert = bytearray(1024)
    cert_size = AtcaReference(len(cert))
    signer_cert = bytes(512)
    assert tng_atcacert_read_device_cert(cert, cert_size, signer_cert) == CertStatus.ATCACERT_E_SUCCESS
    assert cert_size.value == atcab_mock.r_cert_size.value
    assert cert == bytearray(atcab_mock.r_cert)


def test_tng_atcacert_device_public_key_no_cert(test_tng_init):
    public_key = bytearray(64)
    assert tng_atcacert_device_public_key(public_key) == CertStatus.ATCACERT_E_SUCCESS
    assert public_key == bytearray(atcab_mock.r_genkey_pubkey)


def test_tng_atcacert_device_public_key_cert(test_tng_init):
    public_key = bytearray(64)
    cert = bytes(512)
    assert tng_atcacert_device_public_key(public_key, cert) == CertStatus.ATCACERT_E_SUCCESS
    assert public_key == bytearray(atcab_mock.r_genkey_pubkey)


def test_tng_atcacert_max_signer_cert_size(test_tng_init):
    max_cert_size = AtcaReference(0)
    assert tng_atcacert_max_signer_cert_size(max_cert_size) == CertStatus.ATCACERT_E_SUCCESS
    assert max_cert_size.value == atcab_mock.r_max_cert_size.value


def test_tng_atcacert_read_device_cert(test_tng_init):
    cert = bytearray(1024)
    cert_size = AtcaReference(len(cert))
    assert tng_atcacert_read_signer_cert(cert, cert_size) == CertStatus.ATCACERT_E_SUCCESS
    assert cert_size.value == atcab_mock.r_cert_size.value
    assert cert == bytearray(atcab_mock.r_cert)


def test_tng_atcacert_signer_public_key_no_cert(test_tng_init):
    public_key = bytearray(64)
    assert tng_atcacert_signer_public_key(public_key) == CertStatus.ATCACERT_E_SUCCESS
    assert public_key == bytearray(atcab_mock.r_genkey_pubkey)


def test_tng_atcacert_signer_public_key_cert(test_tng_init):
    public_key = bytearray(64)
    cert = bytes(512)
    assert tng_atcacert_signer_public_key(public_key, cert) == CertStatus.ATCACERT_E_SUCCESS
    assert public_key == bytearray(atcab_mock.r_genkey_pubkey)


def test_tng_atcacert_root_cert_size(test_tng_init):
    cert_size = AtcaReference(0)
    assert tng_atcacert_root_cert_size(cert_size) == CertStatus.ATCACERT_E_SUCCESS
    assert cert_size.value == atcab_mock.r_cert_size.value


def test_tng_atcacert_root_cert(test_tng_init):
    cert = bytearray(1024)
    cert_size = AtcaReference(len(cert))
    assert tng_atcacert_root_cert(cert, cert_size) == CertStatus.ATCACERT_E_SUCCESS
    assert cert_size.value == atcab_mock.r_cert_size.value
    assert cert == bytearray(atcab_mock.r_cert)


def test_tng_atcacert_root_public_key(test_tng_init):
    public_key = bytearray(64)
    assert tng_atcacert_root_public_key(public_key) == CertStatus.ATCACERT_E_SUCCESS
    assert public_key == bytearray(atcab_mock.r_genkey_pubkey)
