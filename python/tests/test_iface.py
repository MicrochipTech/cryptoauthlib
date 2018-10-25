"""
These tests verify the structures match the expectation from what is in atca_cfs.c
If that file has been modified then the tests will fail. If the file has not been
modified then we can reasonably expect that there is a problem with the ctypes
definition or assumptions of the platform build and memory alignment is wrong
"""
import pytest
import ctypes
from cryptoauthlib.iface import *
from cryptoauthlib.library import load_cryptoauthlib, get_size_by_name


@pytest.fixture
def test_iface_init(test_init_with_lib):
    load_cryptoauthlib()


def test_iface_cfg_size(test_iface_init):
    assert ctypes.sizeof(ATCAIfaceCfg) == get_size_by_name('ATCAIfaceCfg')


def test_iface_cfg_ateccx08a_i2c(test_iface_init):
    cfg = cfg_ateccx08a_i2c_default()
    assert cfg.iface_type == ATCAIfaceType.ATCA_I2C_IFACE
    assert cfg.devtype == ATCADeviceType.ATECC508A
    assert cfg.cfg.atcai2c.slave_address == 0xC0
    assert cfg.cfg.atcai2c.bus == 2
    assert cfg.cfg.atcai2c.baud == 400000


def test_iface_cfg_ateccx08a_swi(test_iface_init):
    cfg = cfg_ateccx08a_swi_default()
    assert cfg.iface_type == ATCAIfaceType.ATCA_SWI_IFACE
    assert cfg.devtype == ATCADeviceType.ATECC508A
    assert cfg.cfg.atcaswi.bus == 4


def test_iface_cfg_ateccx08a_kithid(test_iface_init):
    cfg = cfg_ateccx08a_kithid_default()
    assert cfg.iface_type == ATCAIfaceType.ATCA_HID_IFACE
    assert cfg.devtype == ATCADeviceType.ATECC508A
    assert cfg.cfg.atcahid.vid == 0x03EB
    assert cfg.cfg.atcahid.pid == 0x2312


def test_iface_cfg_atsha204a_i2c(test_iface_init):
    cfg = cfg_atsha204a_i2c_default()
    assert cfg.iface_type == ATCAIfaceType.ATCA_I2C_IFACE
    assert cfg.devtype == ATCADeviceType.ATSHA204A
    assert cfg.cfg.atcai2c.slave_address == 0xC8
    assert cfg.cfg.atcai2c.bus == 2
    assert cfg.cfg.atcai2c.baud == 400000


def test_iface_cfg_atsha204a_swi(test_iface_init):
    cfg = cfg_atsha204a_swi_default()
    assert cfg.iface_type == ATCAIfaceType.ATCA_SWI_IFACE
    assert cfg.devtype == ATCADeviceType.ATSHA204A
    assert cfg.cfg.atcaswi.bus == 4


def test_iface_cfg_atsha204a_kithid(test_iface_init):
    cfg = cfg_atsha204a_kithid_default()
    assert cfg.iface_type == ATCAIfaceType.ATCA_HID_IFACE
    assert cfg.devtype == ATCADeviceType.ATSHA204A
    assert cfg.cfg.atcahid.vid == 0x03EB
    assert cfg.cfg.atcahid.pid == 0x2312
