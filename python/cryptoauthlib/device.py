"""
Cryptoauthlib Device Configuration
"""
# (c) 2015-2018 Microchip Technology Inc. and its subsidiaries.
#
# Subject to your compliance with these terms, you may use Microchip software
# and any derivatives exclusively with Microchip products. It is your
# responsibility to comply with third party license terms applicable to your
# use of third party software (including open source software) that may
# accompany Microchip software.
#
# THIS SOFTWARE IS SUPPLIED BY MICROCHIP "AS IS". NO WARRANTIES, WHETHER
# EXPRESS, IMPLIED OR STATUTORY, APPLY TO THIS SOFTWARE, INCLUDING ANY IMPLIED
# WARRANTIES OF NON-INFRINGEMENT, MERCHANTABILITY, AND FITNESS FOR A
# PARTICULAR PURPOSE. IN NO EVENT WILL MICROCHIP BE LIABLE FOR ANY INDIRECT,
# SPECIAL, PUNITIVE, INCIDENTAL OR CONSEQUENTIAL LOSS, DAMAGE, COST OR EXPENSE
# OF ANY KIND WHATSOEVER RELATED TO THE SOFTWARE, HOWEVER CAUSED, EVEN IF
# MICROCHIP HAS BEEN ADVISED OF THE POSSIBILITY OR THE DAMAGES ARE
# FORESEEABLE. TO THE FULLEST EXTENT ALLOWED BY LAW, MICROCHIP'S TOTAL
# LIABILITY ON ALL CLAIMS IN ANY WAY RELATED TO THIS SOFTWARE WILL NOT EXCEED
# THE AMOUNT OF FEES, IF ANY, THAT YOU HAVE PAID DIRECTLY TO MICROCHIP FOR
# THIS SOFTWARE.


from ctypes import Structure, c_uint16, c_uint8
from .library import AtcaStructure

# Because this module directly mirrors the C api the following is an exception to the python coding standard
# pylint: disable-msg=too-few-public-methods


class AesEnable(Structure):
    """AES Enable (608) Field Definition """
    _fields_ = [('Enable', c_uint8, 1),
                ('Reserved', c_uint8, 6)]
    _pack_ = 1


class I2cEnable(Structure):
    """I2C Enable Field Definition """
    _fields_ = [('Enable', c_uint8, 1),
                ('Reserved', c_uint8, 6)]
    _pack_ = 1


class CountMatch(Structure):
    """CountMatch (608) Field Definition """
    _fields_ = [('Enable', c_uint8, 1),
                ('Reserved', c_uint8, 3),
                ('CountMatchKey', c_uint8, 4)]
    _pack_ = 1


class ChipMode508(Structure):
    """ChipMode for 508 Field Definition """
    _fields_ = [('UserExtraAdd', c_uint8, 1),
                ('TTLenable', c_uint8, 1),
                ('WatchdogDuration', c_uint8, 1)]
    _pack_ = 1


class ChipMode608(Structure):
    """ChipMode for 608 Field Definition """
    _fields_ = [('UserExtraAdd', c_uint8, 1),
                ('TTLenable', c_uint8, 1),
                ('WatchdogDuration', c_uint8, 1),
                ('ClockDivider', c_uint8, 5)]
    _pack_ = 1


class Counter204(Structure):
    """Counter Definition for SHA204 """
    _fields_ = [('UseFlag', c_uint8),
                ('UpdateCount', c_uint8)]
    _pack_ = 1


class SlotConfig(Structure):
    """Slot Configuration Field Definition """
    _fields_ = [('ReadKey', c_uint16, 4),
                ('NoMac', c_uint16, 1),
                ('LimitedUse', c_uint16, 1),
                ('EncryptRead', c_uint16, 1),
                ('IsSecret', c_uint16, 1),
                ('WriteKey', c_uint16, 4),
                ('WriteConfig', c_uint16, 4)]
    _pack_ = 1


class UseLock(Structure):
    """UseLock Field Definition """
    _fields_ = [('UseLockEnable', c_uint8, 4),
                ('UseLockKey', c_uint8, 4)]
    _pack_ = 1


class VolatileKeyPermission(Structure):
    """VolatileKeyPermission Field Definition """
    _fields_ = [('VolatileKeyPermitSlot', c_uint8, 4),
                ('Reserved', c_uint8, 3),
                ('VolatileKeyPermitEnable', c_uint8, 1)]
    _pack_ = 1


class SecureBoot(Structure):
    """SecureBoot Field Definition """
    _fields_ = [('SecureBootMode', c_uint16, 2),
                ('Reserved0', c_uint16, 1),
                ('SecureBootPersistentEnable', c_uint16, 1),
                ('SecureBootRandNonce', c_uint16, 1),
                ('Reserved1', c_uint16, 3),
                ('SecureBootSigDig', c_uint16, 4),
                ('SecureBootPubKey', c_uint16, 4)]
    _pack_ = 1


class ChipOptions(Structure):
    """ChipOptions Field Definition """
    _fields_ = [('PowerOnSelfTest', c_uint16, 1),
                ('IoProtectionKeyEnable', c_uint16, 1),
                ('KdfAesEnable', c_uint16, 1),
                ('AutoClearFirstFail', c_uint16, 1),
                ('Reserved', c_uint16, 4),
                ('EcdhProtectionBits', c_uint16, 2),
                ('KdfProtectionBits', c_uint16, 2),
                ('IoProtectionKey', c_uint16, 4)]
    _pack_ = 1


class X509Format(Structure):
    """X509Format Field Definition """
    _fields_ = [('PublicPosition', c_uint8, 4),
                ('TemplateLength', c_uint8, 4)]
    _pack_ = 1


class KeyConfig(Structure):
    """KeyConfig Field Definition """
    _fields_ = [('Private', c_uint16, 1),
                ('PubInfo', c_uint16, 1),
                ('KeyType', c_uint16, 3),
                ('Lockable', c_uint16, 1),
                ('ReqRandom', c_uint16, 1),
                ('ReqAuth', c_uint16, 1),
                ('AuthKey', c_uint16, 4),
                ('PersistentDisable', c_uint16, 1),
                ('RFU', c_uint16, 1),
                ('X509id', c_uint16, 2)]
    _pack_ = 1


class Atsha204aConfig(AtcaStructure):
    """ATSHA204A Config Zone Definition """
    _fields_ = [('SN03', c_uint8*4),
                ('RevNum', c_uint8*4),
                ('SN48', c_uint8*5),
                ('Reserved13', c_uint8),
                ('I2C_Enable', I2cEnable),
                ('Reserved15', c_uint8),
                ('I2C_Address', c_uint8),
                ('CheckMacConfig', c_uint8),
                ('OTPmode', c_uint8),
                ('SelectorMode', c_uint8),
                ('SlotConfig', SlotConfig*16),
                ('Counter', Counter204*8),
                ('LastKeyUse', c_uint8*16),
                ('UserExtra', c_uint8),
                ('Selector', c_uint8),
                ('LockValue', c_uint8),
                ('LockConfig', c_uint8)]
    _pack_ = 1


class Atecc508aConfig(AtcaStructure):
    """ATECC508A Config Zone Definition """
    _fields_ = [('SN03', c_uint8*4),
                ('RevNum', c_uint8*4),
                ('SN48', c_uint8*5),
                ('Reserved13', c_uint8),
                ('I2C_Enable', I2cEnable),
                ('Reserved15', c_uint8),
                ('I2C_Address', c_uint8),
                ('Reserved17', c_uint8),
                ('OTPmode', c_uint8),
                ('ChipMode', ChipMode508),
                ('SlotConfig', SlotConfig*16),
                ('Counter0', c_uint8*8),
                ('Counter1', c_uint8*8),
                ('LastKeyUse', c_uint8*16),
                ('UserExtra', c_uint8),
                ('Selector', c_uint8),
                ('LockValue', c_uint8),
                ('LockConfig', c_uint8),
                ('SlotLocked', c_uint16),
                ('RFU', c_uint16),
                ('X509format', X509Format*4),
                ('KeyConfig', KeyConfig*16)]
    _pack_ = 1


class Atecc608aConfig(AtcaStructure):
    """ATECC608A Config Zone Definition """
    _fields_ = [('SN03', c_uint8*4),
                ('RevNum', c_uint8*4),
                ('SN48', c_uint8*5),
                ('AES_Enable', AesEnable),
                ('I2C_Enable', I2cEnable),
                ('Reserved15', c_uint8),
                ('I2C_Address', c_uint8),
                ('Reserved17', c_uint8),
                ('CountMatch', CountMatch),
                ('ChipMode', ChipMode608),
                ('SlotConfig', SlotConfig*16),
                ('Counter0', c_uint8*8),
                ('Counter1', c_uint8*8),
                ('UseLock', UseLock),
                ('VolatileKeyPermission', VolatileKeyPermission),
                ('SecureBoot', SecureBoot),
                ('KdfIvLoc', c_uint8),
                ('KdfIvStr', c_uint8*2),
                ('Reserved68', c_uint8*9),
                ('UserExtra', c_uint8),
                ('UserExtraAdd', c_uint8),
                ('LockValue', c_uint8),
                ('LockConfig', c_uint8),
                ('SlotLocked', c_uint16),
                ('ChipOptions', ChipOptions),
                ('X509format', X509Format*4),
                ('KeyConfig', KeyConfig*16)]
    _pack_ = 1


__all__ = ['Atsha204aConfig', 'Atecc508aConfig', 'Atecc608aConfig']
