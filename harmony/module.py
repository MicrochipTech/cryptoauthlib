"""*****************************************************************************
* Copyright (C) 2019 Microchip Technology Inc. and its subsidiaries.
*
* Subject to your compliance with these terms, you may use Microchip software
* and any derivatives exclusively with Microchip products. It is your
* responsibility to comply with third party license terms applicable to your
* use of third party software (including open source software) that may
* accompany Microchip software.
*
* THIS SOFTWARE IS SUPPLIED BY MICROCHIP "AS IS". NO WARRANTIES, WHETHER
* EXPRESS, IMPLIED OR STATUTORY, APPLY TO THIS SOFTWARE, INCLUDING ANY IMPLIED
* WARRANTIES OF NON-INFRINGEMENT, MERCHANTABILITY, AND FITNESS FOR A
* PARTICULAR PURPOSE.
*
* IN NO EVENT WILL MICROCHIP BE LIABLE FOR ANY INDIRECT, SPECIAL, PUNITIVE,
* INCIDENTAL OR CONSEQUENTIAL LOSS, DAMAGE, COST OR EXPENSE OF ANY KIND
* WHATSOEVER RELATED TO THE SOFTWARE, HOWEVER CAUSED, EVEN IF MICROCHIP HAS
* BEEN ADVISED OF THE POSSIBILITY OR THE DAMAGES ARE FORESEEABLE. TO THE
* FULLEST EXTENT ALLOWED BY LAW, MICROCHIP'S TOTAL LIABILITY ON ALL CLAIMS IN
* ANY WAY RELATED TO THIS SOFTWARE WILL NOT EXCEED THE AMOUNT OF FEES, IF ANY,
* THAT YOU HAVE PAID DIRECTLY TO MICROCHIP FOR THIS SOFTWARE.
*****************************************************************************"""

import os

_CALIB_SUPPORTED_DEVICES = ['ATECC108A', 'ATECC508A', 'ATECC608', 'ATSHA204A']
_TALIB_SUPPORTED_DEVICES = ['TA100']

def loadModule():
    cryptoAuthLib = Module.CreateSharedComponent("cryptoauthlib", "Core", "/Libraries/Cryptoauthlib", "/harmony/config/cryptoauthlib.py")
    cryptoAuthLib.setDisplayType("Crypto Authentication Library")
    cryptoAuthLib.addCapability("CAL_LIB_CAP", "CA_LIB", True)
    cryptoAuthLib.addDependency("FreeRTOS", "RTOS", True, False)
    cryptoAuthLib.addDependency("WolfSSL_Crypto_Dependency", "LIB_WOLFCRYPT", None, False, False)

    cryptoAuthLibTng = Module.CreateSharedComponent("cryptoauthlib_tng", "Trust&Go", "/Libraries/Cryptoauthlib", "/harmony/config/tng.py")
    cryptoAuthLibTng.setDisplayType("TNGTLS & TNGLORA Certificates")
    cryptoAuthLibTng.addDependency("CAL_LIB_CAP", "CA_LIB", True, False)

    cryptoAuthLibPkcs11 = Module.CreateSharedComponent("cryptoauthlib_pkcs11", "PKCS11", "/Libraries/Cryptoauthlib", "/harmony/config/pkcs11.py")
    cryptoAuthLibPkcs11.setDisplayType("PKCS#11 Interface")
    cryptoAuthLibPkcs11.addDependency("CAL_LIB_CAP", "CA_LIB", True, False)

    cryptoAuthLibTest = Module.CreateSharedComponent("cryptoauthlib_test", "Tester", "/Libraries/Cryptoauthlib", "/harmony/config/test_app.py")
    cryptoAuthLibTest.setDisplayType("Library Testing Application")
    cryptoAuthLibTest.addDependency("CAL_LIB_CAP", "CA_LIB", True, False)

    for dev in _CALIB_SUPPORTED_DEVICES:
        comp = Module.CreateGeneratorComponent(dev.lower(), dev, "/Harmony/Drivers/Crypto", "/harmony/config/device_common.py", "/harmony/config/device_instance.py")
        comp.addDependency("cryptoauthlib", "CA_LIB", True, False)
        comp.addMultiDependency('{}_DEP_PLIB_I2C'.format(dev.upper()), 'I2C', 'I2C', True)

    if os.path.exists(Module.getPath() + 'lib/talib/talib_basic.h'):
        for dev in _TALIB_SUPPORTED_DEVICES:
            comp = Module.CreateGeneratorComponent(dev.lower(), dev, "/Harmony/Drivers/Crypto", "/harmony/config/device_common.py", "/harmony/config/device_instance.py")
            comp.addDependency("cryptoauthlib", "CA_LIB", True, False)
            comp.addMultiDependency('{}_DEP_PLIB_I2C'.format(dev.upper()), 'I2C', 'I2C', False)
            comp.addMultiDependency('{}_DEP_PLIB_SPI'.format(dev.upper()), 'SPI', 'SPI', False)


