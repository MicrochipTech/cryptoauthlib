"""
Device.py tests. Covers the configuration structures
"""
import pytest
import ctypes
from cryptoauthlib.device import *
from cryptoauthlib.library import load_cryptoauthlib, get_size_by_name, ctypes_to_bytes

# ATSHA204A Test Data
ATSHA204A_SER_NUM_VECTOR = bytearray.fromhex('01 23 6E AA CE FE 0B 8D EE')
ATSHA204A_DEVICE_CONFIG_VECTOR = bytearray.fromhex(
    '01 23 6E AA 00 09 04 00 CE FE 0B 8D EE 00 01 00'
    'C8 00 55 00 8F 80 80 A1 82 E0 C4 F4 84 00 A0 85'
    '86 40 87 07 0F 00 C4 64 8A 7A 0B 8B 0C 4C DD 4D'
    'C2 42 AF 8F FF 00 FF 00 FF 00 FF 00 FF 00 FF 00'
    'FF 00 FF 00 FF FF FF FF FF FF FF FF FF FF FF FF'
    'FF FF FF FF 00 00 55 55')
ATSHA204A_DEVICE_CONFIG = {
    'SN03': [0x01, 0x23, 0x6E, 0xAA],
    'RevNum': [0x00, 0x09, 0x04, 0x00],
    'SN48': [0xCE, 0xFE, 0x0B, 0x8D, 0xEE],
    'I2C_Enable': 0x01,
    'I2C_Address': 0xC8,
    'OTPmode': 0x55,
    'SlotConfig': [0x808F, 0xA180, 0xE082, 0xF4C4,
                   0x0084, 0x85A0, 0x4086, 0x0787,
                   0x000F, 0x64C4, 0x7A8A, 0x8B0B,
                   0x4C0C, 0x4DDD, 0x42C2, 0x8FAF],
    'Counter': [0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFF],
    'LastKeyUse': [0xFF, 0xFF, 0xFF, 0xFF,
                   0xFF, 0xFF, 0xFF, 0xFF,
                   0xFF, 0xFF, 0xFF, 0xFF,
                   0xFF, 0xFF, 0xFF, 0xFF],
    'LockValue': 0x55,
    'LockConfig': 0x55
}

# ATECC508A Test Data
ATECC508A_SER_NUM_VECTOR = bytearray.fromhex('01 23 72 E8 B9 63 B2 D3 EE')
ATECC508A_DEVICE_CONFIG_VECTOR = bytearray.fromhex(
    '01 23 72 E8 00 00 60 02 B9 63 B2 D3 EE 00 2D 00'
    'B0 00 55 00 8F 20 C4 44 87 20 87 20 8F 0F C4 36'
    '9F 0F 82 20 0F 0F C4 44 0F 0F 0F 0F 0F 0F 0F 0F'
    '0F 0F 0F 0F FF FF FF FF 00 00 00 00 FF FF FF FF'
    '00 00 00 00 FF FF FF FF FF FF FF FF FF FF FF FF'
    'FF FF FF FF 00 00 55 55 FF FF 00 00 00 00 00 00'
    '33 00 1C 00 13 00 13 00 7C 00 1C 00 3C 00 33 00'
    '3C 00 3C 00 3C 00 30 00 3C 00 3C 00 3C 00 30 00')
ATECC508A_DEVICE_CONFIG = {
    'SN03': [0x01, 0x23, 0x72, 0xE8],
    'RevNum': [0x00, 0x00, 0x60, 0x02],
    'SN48': [0xB9, 0x63, 0xB2, 0xD3, 0xEE],
    'I2C_Enable': 0x2D,
    'I2C_Address': 0xB0,
    'OTPmode': 0x55,
    'SlotConfig': [0x208F, 0x44C4, 0x2087, 0x2087,
                   0x0F8F, 0x36C4, 0x0F9F, 0x2082,
                   0x0F0F, 0x44C4, 0x0F0F, 0x0F0F,
                   0x0F0F, 0x0F0F, 0x0F0F, 0x0F0F],
    'Counter0': [0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00],
    'Counter1': [0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00],
    'LastKeyUse': [0xFF, 0xFF, 0xFF, 0xFF,
                   0xFF, 0xFF, 0xFF, 0xFF,
                   0xFF, 0xFF, 0xFF, 0xFF,
                   0xFF, 0xFF, 0xFF, 0xFF],
    'LockValue': 0x55,
    'LockConfig': 0x55,
    'SlotLocked': 0xFFFF,
    'KeyConfig': [0x0033, 0x001C, 0x0013, 0x0013,
                  0x007C, 0x001C, 0x003C, 0x0033,
                  0x003C, 0x003C, 0x003C, 0x0030,
                  0x003C, 0x003C, 0x003C, 0x0030]
}

# ATECC608 Test Data
ATECC608_SER_NUM_VECTOR = bytearray.fromhex('01 23 72 E8 B9 63 B2 D3 EE')
ATECC608_DEVICE_CONFIG_VECTOR = bytearray.fromhex(
    '01 23 72 E8 00 00 60 02 B9 63 B2 D3 EE 01 2D 00'
    'B0 00 55 01 8F 20 C4 44 87 20 87 20 8F 0F C4 36'
    '9F 0F 82 20 0F 0F C4 44 0F 0F 0F 0F 0F 0F 0F 0F'
    '0F 0F 0F 0F FF FF FF FF 00 00 00 00 FF FF FF FF'
    '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00'
    '00 00 00 00 00 00 00 00 FF FF 06 40 00 00 00 00'
    '33 00 1C 00 13 00 13 00 7C 00 1C 00 3C 00 33 00'
    '3C 00 3C 00 3C 00 30 00 3C 00 3C 00 3C 00 30 00')
ATECC608_DEVICE_CONFIG = {
    'SN03': [0x01, 0x23, 0x72, 0xE8],
    'RevNum': [0x00, 0x00, 0x60, 0x02],
    'SN48': [0xB9, 0x63, 0xB2, 0xD3, 0xEE],
    'AES_Enable': {'Enable': 1},
    'I2C_Enable': 0x2D,
    'I2C_Address': 0xB0,
    'ChipMode': 1,
    'CountMatch': 0x55,
    'SlotConfig': [0x208F, 0x44C4, 0x2087, 0x2087,
                   0x0F8F, 0x36C4, 0x0F9F, 0x2082,
                   0x0F0F, 0x44C4, 0x0F0F, 0x0F0F,
                   0x0F0F, 0x0F0F, 0x0F0F, 0x0F0F],
    'Counter0': [0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00],
    'Counter1': [0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00],
    'SlotLocked': 0xFFFF,
    'ChipOptions': {
        'IoProtectionKeyEnable': 1,
        'KdfAesEnable': 1,
        'IoProtectionKey': 4
    },
    'KeyConfig': [0x0033, 0x001C, 0x0013, 0x0013,
                  0x007C, 0x001C, 0x003C, 0x0033,
                  0x003C, 0x003C, 0x003C, 0x0030,
                  0x003C, 0x003C, 0x003C, 0x0030]
}


@pytest.mark.parametrize("config,size", [
    pytest.param(Atsha204aConfig, len(ATSHA204A_DEVICE_CONFIG_VECTOR), id='ATSHA204A'),
    pytest.param(Atecc508aConfig, len(ATECC508A_DEVICE_CONFIG_VECTOR), id='ATECC508A'),
    pytest.param(Atecc608Config, len(ATECC608_DEVICE_CONFIG_VECTOR), id='ATECC608')
])
def test_device_config_size(config, size):
    assert ctypes.sizeof(config) == size


@pytest.mark.parametrize("config,definition,vector", [
    pytest.param(Atsha204aConfig, ATSHA204A_DEVICE_CONFIG, ATSHA204A_DEVICE_CONFIG_VECTOR, id='ATSHA204A'),
    pytest.param(Atecc508aConfig, ATECC508A_DEVICE_CONFIG, ATECC508A_DEVICE_CONFIG_VECTOR, id='ATECC508A'),
    pytest.param(Atecc608Config, ATECC608_DEVICE_CONFIG, ATECC608_DEVICE_CONFIG_VECTOR, id='ATECC608')
])
def test_device_config_from_def(config, definition, vector):
    assert ctypes_to_bytes(config(**definition)) == bytes(vector)


@pytest.mark.parametrize("config,vector", [
    pytest.param(Atsha204aConfig, ATSHA204A_DEVICE_CONFIG_VECTOR, id='ATSHA204A'),
    pytest.param(Atecc508aConfig, ATECC508A_DEVICE_CONFIG_VECTOR, id='ATECC508A'),
    pytest.param(Atecc608Config, ATECC608_DEVICE_CONFIG_VECTOR, id='ATECC608')
])
def test_device_config_from_vector(config, vector):
    assert ctypes_to_bytes(config.from_buffer(vector)) == bytes(vector)

@pytest.mark.parametrize("config,definition,vector", [
    pytest.param(Atsha204aConfig, ATSHA204A_DEVICE_CONFIG, ATSHA204A_SER_NUM_VECTOR, id='ATSHA204A'),
    pytest.param(Atecc508aConfig, ATECC508A_DEVICE_CONFIG, ATECC508A_SER_NUM_VECTOR, id='ATECC508A'),
    pytest.param(Atecc608Config, ATECC608_DEVICE_CONFIG, ATECC608_SER_NUM_VECTOR, id='ATECC608')
])
def test_device_serial_number_from_def(config, definition, vector):
    config = config(**definition)
    sernum = ctypes_to_bytes(config.SN03) + ctypes_to_bytes(config.SN48)
    assert sernum == bytes(vector)
