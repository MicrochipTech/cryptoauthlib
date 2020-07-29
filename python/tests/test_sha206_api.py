import pytest

from cryptoauthlib import *
from cryptoauthlib.library import load_cryptoauthlib, get_cryptoauthlib, AtcaReference
from cryptoauthlib_mock import atcab_mock


@pytest.fixture
def test_sha206a_api_init():
    """
    Run tests against the library mock
    """
    load_cryptoauthlib(atcab_mock())

@pytest.fixture
def test_sha206a_api_init_lib(test_init_with_lib):
    """
    Run tests against a built library on the platform
    """
    load_cryptoauthlib()

@pytest.fixture
def test_sha206a_api_init_live(test_init_with_device):
    """
    Use real hardware for these tests - otherwise skip
    """
    load_cryptoauthlib()
    if Status.ATCA_SUCCESS != atcab_init(cfg_atsha20xa_kithid_default()):
        raise Exception('Unable to connect to a device')

def test_sha206a_diversify_parent_key(test_sha206a_api_init):
    parent_key = bytearray(32)
    diversified_key = bytearray(32)
    assert sha206a_diversify_parent_key(parent_key, diversified_key) == Status.ATCA_SUCCESS
    assert diversified_key == bytearray(atcab_mock.r_diversified_key)

def test_sha206a_generate_derive_key(test_sha206a_api_init):
    parent_key = bytearray(32)
    derived_key = bytearray(32)
    param1 = 0
    param2 = 0
    assert sha206a_generate_derive_key(parent_key, derived_key, param1, param2) == Status.ATCA_SUCCESS
    assert derived_key == bytearray(atcab_mock.r_derived_key)

def test_sha206a_generate_derive_key_with_bad_param(test_sha206a_api_init):
    parent_key = bytearray(32)
    param1 = 0
    param2 = 0
    assert sha206a_generate_derive_key(parent_key, None, param1, param2) == Status.ATCA_BAD_PARAM

def test_sha206a_generate_challenge_response_pair(test_sha206a_api_init):
    key = bytearray(32)
    challenge = bytearray(32)
    response = bytearray(32)
    assert sha206a_generate_challenge_response_pair(key, challenge, response) == Status.ATCA_SUCCESS
    assert response == bytearray(atcab_mock.r_challenge_response)

def test_sha206a_authenticate(test_sha206a_api_init):
    challenge = bytearray(32)
    expected_response = bytearray(32)
    is_verified = AtcaReference(2)
    assert sha206a_authenticate(challenge, expected_response, is_verified) == Status.ATCA_SUCCESS
    assert is_verified.value == atcab_mock.r_verify_is_verified.value

def test_sha206a_authenticate_with_bad_param(test_sha206a_api_init):
    challenge = bytearray(32)
    expected_response = bytearray(32)
    assert sha206a_authenticate(challenge, expected_response, None) == Status.ATCA_BAD_PARAM

def test_sha206a_write_data_store(test_sha206a_api_init):
    slot = 8
    data = bytearray(32)
    block = 0
    offset = 0
    length = 32
    lock_after_write = 0
    assert sha206a_write_data_store(slot, data, block, offset, length, lock_after_write) == Status.ATCA_SUCCESS

def test_sha206a_read_data_store(test_sha206a_api_init):
    slot = 8
    data = bytearray(32)
    offset = 0
    length = 32
    assert sha206a_read_data_store(slot, data, offset, length) == Status.ATCA_SUCCESS
    assert data == bytearray(atcab_mock.r_read_zone_data)

def test_sha206a_get_data_store_lock_status(test_sha206a_api_init):
    slot = 8
    is_locked = AtcaReference(2)
    assert sha206a_get_data_store_lock_status(slot, is_locked) == Status.ATCA_SUCCESS
    assert is_locked.value == atcab_mock.r_verify_is_locked.value

def test_sha206a_get_data_store_lock_status_with_bad_param(test_sha206a_api_init):
    slot = 8
    assert sha206a_get_data_store_lock_status(slot, None) == Status.ATCA_BAD_PARAM

def test_sha206a_get_dk_update_count(test_sha206a_api_init):
    dk_update_count = AtcaReference(2)
    assert sha206a_get_dk_update_count(dk_update_count) == Status.ATCA_SUCCESS
    assert dk_update_count.value == atcab_mock.r_dk_update_count.value

def test_sha206a_get_pk_useflag_count(test_sha206a_api_init):
    pk_avail_count = AtcaReference(2)
    assert sha206a_get_pk_useflag_count(pk_avail_count) == Status.ATCA_SUCCESS
    assert pk_avail_count.value == atcab_mock.r_pk_avail_count.value

def test_sha206a_get_dk_useflag_count(test_sha206a_api_init):
    dk_avail_count = AtcaReference(2)
    assert sha206a_get_dk_useflag_count(dk_avail_count) == Status.ATCA_SUCCESS
    assert dk_avail_count.value == atcab_mock.r_dk_avail_count.value

def test_sha206a_check_pk_useflag_validity(test_sha206a_api_init):
    is_consumed = AtcaReference(2)
    assert sha206a_check_pk_useflag_validity(is_consumed) == Status.ATCA_SUCCESS
    assert is_consumed.value == atcab_mock.r_verify_is_consumed.value

def test_sha206a_check_dk_useflag_validity(test_sha206a_api_init):
    is_consumed = AtcaReference(2)
    assert sha206a_check_dk_useflag_validity(is_consumed) == Status.ATCA_SUCCESS
    assert is_consumed.value == atcab_mock.r_verify_is_consumed.value

def test_sha206a_verify_device_consumption(test_sha206a_api_init):
    is_consumed = AtcaReference(2)
    assert sha206a_verify_device_consumption(is_consumed) == Status.ATCA_SUCCESS
    assert is_consumed.value == atcab_mock.r_verify_is_consumed.value

def test_sha206a_verify_device_consumption_with_bad_param(test_sha206a_api_init):
    assert sha206a_verify_device_consumption(None) == Status.ATCA_BAD_PARAM



