import pytest
from cryptoauthlib.library import load_cryptoauthlib, get_cryptoauthlib, AtcaReference
from cryptoauthlib_mock import atcab_mock


def test_library():
    inst = atcab_mock()
    load_cryptoauthlib(inst)
    assert get_cryptoauthlib() == inst


def test_library_load_dll(test_init_with_lib):
    load_cryptoauthlib()


def test_library_AtcaReference_integer():
    a = AtcaReference(4)
    assert 3 != a
    assert 3 < a
    assert 3 <= a
    assert 4 <= a
    assert 4 == a
    assert 4 >= a
    assert 5 > a
    assert 5 >= a
    assert 4 == int(a)
    assert '4' == str(a)


def test_library_AtcaReference_modify_integer():
    f = lambda x: setattr(x, 'value', x.value + 1)

    a = AtcaReference(4)
    f(a)
    assert 5 == a
    f(a)
    assert 6 == a
