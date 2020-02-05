# coding: utf-8
"""*****************************************************************************
* Copyright (C) 2018 Microchip Technology Inc. and its subsidiaries.
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

_DEFAULT_I2C_ADDRESS = {'ecc': 0xC0, 'sha': 0xC8}

def updateSercomPlibList(plib, inc):
    Database.sendMessage('cryptoauthlib', 'UPDATE_PLIB_LIST', {'id': plib.lower(), 'inc': inc})


def updatePartType(symbol, event):
    symObj = event["symbol"]

    if symObj.getSelectedKey() == "TNGTLS":
        Database.activateComponents(['cryptoauthlib_tng'])
        symbol.setValue(0x6A)
    elif symObj.getSelectedKey() == "TNGLORA":
        Database.activateComponents(['cryptoauthlib_tng'])
        symbol.setValue(0xB2)
    else:
        symbol.setValue(0xC0)


def instantiateComponent(deviceComponent, index):
    global devicePartType
    deviceID = deviceComponent.getID().upper()
    configName = Variables.get('__CONFIGURATION_NAME')

    #I2C Configuration
    devicePLIB = deviceComponent.createStringSymbol("DRV_I2C_PLIB", None)
    devicePLIB.setLabel("PLIB Used")
    devicePLIB.setReadOnly(True)
    devicePLIB.setDefaultValue("")

    interfaceType = deviceComponent.createStringSymbol('INTERFACE', None)
    interfaceType.setLabel('Interface Type')
    interfaceType.setReadOnly(True)
    interfaceType.setDefaultValue('')

    if '608' in deviceID:
        devicePartType = deviceComponent.createKeyValueSetSymbol("PART_TYPE", None)
        devicePartType.setLabel("Select Part Type")
        devicePartType.addKey("Custom", "0", "Trust Custom")
        devicePartType.addKey("TNGTLS", "1", "Trust & Go: TLS")
        devicePartType.addKey("TNGLORA", "2", "Trust & Go: LORA")
        devicePartType.setDefaultValue(0)
        devicePartType.setOutputMode("Key")
        devicePartType.setDisplayMode("Description")

        deviceAddress = deviceComponent.createHexSymbol("I2C_ADDR", devicePartType)
        deviceAddress.setLabel("I2C Address")
        deviceAddress.setDefaultValue(0xC0)
        deviceAddress.setDependencies(updatePartType, ["PART_TYPE"])
    else:
        deviceAddress = deviceComponent.createHexSymbol("I2C_ADDR", None)
        deviceAddress.setLabel("I2C Address")
       
        if 'ECC' in deviceID:
            deviceAddress.setDefaultValue(_DEFAULT_I2C_ADDRESS['ecc'])
        elif 'SHA' in deviceID:
            deviceAddress.setDefaultValue(_DEFAULT_I2C_ADDRESS['sha'])

    wakeupDelay = deviceComponent.createIntegerSymbol("WAKEUP_DELAY", None)
    wakeupDelay.setLabel("Wakeup Delay (us)")
    wakeupDelay.setDefaultValue(1500)

    receiveRetry = deviceComponent.createIntegerSymbol("RECEIVE_RETRY", None)
    receiveRetry.setLabel("Receive Retry")
    receiveRetry.setDefaultValue(20)

    deviceIndex = deviceComponent.createIntegerSymbol("INDEX", None)
    deviceIndex.setVisible(False)
    deviceIndex.setDefaultValue(index)

    deviceName = deviceComponent.createStringSymbol('NAME', None)
    deviceName.setVisible(False)
    deviceName.setDefaultValue(deviceComponent.getDisplayName())

    devInitDataFile = deviceComponent.createFileSymbol('DRV_{}_INIT_DATA'.format(deviceID), None)
    devInitDataFile.setSourcePath('harmony/templates/device_instance.c.ftl')
    devInitDataFile.setOutputName('{}.c'.format(deviceID))
    devInitDataFile.setDestPath('library/cryptoauthlib/hal')
    devInitDataFile.setProjectPath("config/" + configName + "/library/cryptoauthlib/hal")
    devInitDataFile.setType('SOURCE')
    devInitDataFile.setOverwrite(True)
    devInitDataFile.setMarkup(True)


def onAttachmentConnected(source, target):
    sourceID = source['id'].upper()
    targetID = target['component'].getID().upper()

    if 'I2C' in sourceID:
        source['component'].getSymbolByID('DRV_I2C_PLIB').setValue(targetID)
        source['component'].getSymbolByID('INTERFACE').setValue('ATCA_I2C_IFACE')
        updateSercomPlibList(targetID, True)


def onAttachmentDisconnected(source, target):
    sourceID = source['id'].upper()
    targetID = target['component'].getID().upper()

    if 'I2C' in sourceID:
        try:
            source['component'].getSymbolByID('DRV_I2C_PLIB').clearValue()
            source['component'].getSymbolByID('INTERFACE').clearValue()
        except AttributeError:
            # Happens when the instance is deleted while attached
            pass
        updateSercomPlibList(targetID, False)


