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

_CAL_SUPPORTED_DEVICES = ['ATECC108A', 'ATECC508A', 'ATECC608A', 'ATSHA204A']

def loadModule():
    cryptoAuthLib = Module.CreateSharedComponent("cryptoauthlib", "CryptoAuthLib", "/Libraries", "/harmony/config/cryptoauthlib.py")
    cryptoAuthLib.setDisplayType("Crypto Authentication Library")
    cryptoAuthLib.addCapability("CAL_LIB_CAP", "CA_LIB", True)
    cryptoAuthLib.addDependency("FreeRTOS", "RTOS", True, False)
    cryptoAuthLib.addDependency("WolfSSL_Crypto_Dependency", "LIB_WOLFCRYPT", None, False, False)

    cryptoAuthLib = Module.CreateSharedComponent("cryptoauthlib_tng", "CryptoAuthLib: Trust&Go", "/Libraries", "/harmony/config/tng.py")
    cryptoAuthLib.setDisplayType("TNGTLS & TNGLORA Certificates")
    cryptoAuthLib.addDependency("CAL_LIB_CAP", "CA_LIB", True, False)


    for dev in _CAL_SUPPORTED_DEVICES:
        comp = Module.CreateGeneratorComponent(dev.lower(), dev, "/Harmony/Drivers/Crypto", "/harmony/config/device_common.py", "/harmony/config/device_instance.py")
        comp.addDependency("cryptoauthlib", "CA_LIB", True, False)
        comp.addMultiDependency('{}_DEP_PLIB_I2C'.format(dev.upper()), 'I2C', 'I2C', True)


