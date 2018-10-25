import pytest
from cryptoauthlib.status import *

@pytest.fixture(scope="module")
def test_status_init():
    pass

def test_atcaenum_to_string(test_status_init):
    assert isinstance(str(Status.ATCA_SUCCESS), str)


def test_atcaenum_from_string(test_status_init):
    assert Status.ATCA_BAD_PARAM == Status['ATCA_BAD_PARAM']


def test_atcaenum_to_int(test_status_init):
    assert isinstance(int(Status.ATCA_BAD_PARAM), int)


def test_atcaenum_from_int(test_status_init):
    assert Status.ATCA_BAD_PARAM == Status(0xE2)


def test_atcaenum_eq(test_status_init):
    assert Status.ATCA_SUCCESS == Status.ATCA_SUCCESS


def test_atcaenum_ne(test_status_init):
    assert Status.ATCA_BAD_PARAM != Status.ATCA_SUCCESS


def test_atcaenum_int_eq(test_status_init):
    assert Status.ATCA_SUCCESS == 0


def test_atcaenum_int_ne(test_status_init):
    assert Status.ATCA_SUCCESS != 226


def test_atcaenum_string_eq(test_status_init):
    assert Status.ATCA_SUCCESS == 'ATCA_SUCCESS'


def test_atcaenum_string_ne(test_status_init):
    assert Status.ATCA_SUCCESS != 'ATCA_BAD_PARAM'
