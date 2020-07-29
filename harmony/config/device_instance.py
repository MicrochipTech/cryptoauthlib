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

_DEFAULT_I2C_ADDRESS = {'ecc': 0xC0, 'sha': 0xC8, 'ta100': 0x2e}
_SWI_DEVICES = ['ATSHA204A', 'ATSHA206A', 'ATECC108A', 'ATECC508A', 'ATECC608']
_I2C_DEVICES = ['ATSHA204A', 'ATECC108A', 'ATECC508A', 'ATECC608', 'TA100']
_SPI_DEVICES = ['TA100']


def updateSercomPlibList(plib, inc):
    Database.sendMessage('cryptoauthlib', 'UPDATE_PLIB_LIST', {'id': plib.lower(), 'inc': inc})


def updateTngCapability(id, src):
    Database.sendMessage('cryptoauthlib_tng', 'UPDATE_TNG_TYPE', {'id': id, 'src': src})


def updatePartInterfaceSettings(symbol, event):
    symObj = event['symbol']
    updateId = event['id'].upper()
    selected_key = symObj.getSelectedKey()

    if updateId == 'INTERFACE':
        if selected_key == 'ATCA_SPI_IFACE':
            symbol.setVisible('SPI' in symbol.getID())
        elif selected_key == 'ATCA_I2C_IFACE':
            symbol.setVisible('I2C' in symbol.getID())
    elif updateId == 'PART_TYPE':
        if selected_key == "TNGTLS":
            Database.activateComponents(['cryptoauthlib_tng'])
            symbol.setValue(0x6A)
        elif selected_key == "TFLEX":
            Database.activateComponents(['cryptoauthlib_tng'])
            symbol.setValue(0x6C)
        elif selected_key == "TNGLORA":
            Database.activateComponents(['cryptoauthlib_tng'])
            symbol.setValue(0xB2)
        else:
            symbol.setValue(0xC0)

        updateTngCapability(selected_key, event['namespace'])


def sort_alphanumeric(l):
    import re
    convert = lambda text: int(text) if text.isdigit() else text.lower()
    alphanum_key = lambda key: [ convert(c) for c in re.split('([0-9]+)', key) ]
    return sorted(l, key = alphanum_key)


def instantiateComponent(deviceComponent, index):
    deviceID = deviceComponent.getID().upper()
    deviceType = deviceID.split('_')[0]
    configName = Variables.get('__CONFIGURATION_NAME')

    #I2C Configuration
    devicePLIB = deviceComponent.createStringSymbol("HAL_INTERFACE", None)
    devicePLIB.setLabel("PLIB Used")
    devicePLIB.setReadOnly(True)
    devicePLIB.setDefaultValue("")

    interfaceType = deviceComponent.createKeyValueSetSymbol('INTERFACE', None)
    interfaceType.setLabel('Interface Type')
    if deviceType in _I2C_DEVICES:
        interfaceType.addKey("ATCA_I2C_IFACE", "0", "I2C")
#    if deviceType in _SWI_DEVICES:
#        interfaceType.addKey("ATCA_SWI_IFACE", "1", "SWI")
    if deviceType in _SPI_DEVICES:
        interfaceType.addKey("ATCA_SPI_IFACE", "2", "SPI")
    interfaceType.setDefaultValue(0)
    interfaceType.setOutputMode("Key")
    interfaceType.setDisplayMode("Description")

    if '608' in deviceID:
        devicePartType = deviceComponent.createKeyValueSetSymbol("PART_TYPE", interfaceType)
        devicePartType.setLabel("Select Part Type")
        devicePartType.addKey("Custom", "0", "Trust Custom")
        devicePartType.addKey("TFLEX", "3", "Trust Flex")
        devicePartType.addKey("TNGTLS", "1", "Trust & Go: TLS")
        devicePartType.addKey("TNGLORA", "2", "Trust & Go: LORA")
        devicePartType.setDefaultValue(0)
        devicePartType.setOutputMode("Key")
        devicePartType.setDisplayMode("Description")

        deviceAddress = deviceComponent.createHexSymbol("I2C_ADDR", devicePartType)
        deviceAddress.setLabel("I2C Address")
        deviceAddress.setDefaultValue(0xC0)
    else:
        deviceAddress = deviceComponent.createHexSymbol("I2C_ADDR", interfaceType)
        deviceAddress.setLabel("I2C Address")

        if 'ECC' in deviceID:
            deviceAddress.setDefaultValue(_DEFAULT_I2C_ADDRESS['ecc'])
        elif 'SHA' in deviceID:
            deviceAddress.setDefaultValue(_DEFAULT_I2C_ADDRESS['sha'])
        elif 'TA' in deviceID:
            deviceAddress.setDefaultValue(_DEFAULT_I2C_ADDRESS['ta100'])

    deviceAddress.setDependencies(updatePartInterfaceSettings, ["PART_TYPE"])

    spiCsComment = deviceComponent.createCommentSymbol("SPI_CS_PINS_COMMENT", interfaceType)
    spiCsComment.setLabel("!!! Configure the Chip Select pin as GPIO OUTPUT in Pin Settings.!!! ")
    spiCsComment.setDependencies(updatePartInterfaceSettings, ["INTERFACE"])
    spiCsComment.setVisible(False)

    spiChipSelectPin = deviceComponent.createKeyValueSetSymbol("SPI_CS_PIN", interfaceType)
    spiChipSelectPin.setLabel("Chip Select Pin")
    spiChipSelectPin.setDefaultValue(0)
    spiChipSelectPin.setOutputMode("Key")
    spiChipSelectPin.setDisplayMode("Description")
    spiChipSelectPin.setDependencies(updatePartInterfaceSettings, ["INTERFACE"])
    spiChipSelectPin.setVisible(False)

    availablePinDictionary = {}
    availablePinDictionary = Database.sendMessage("core", "PIN_LIST", availablePinDictionary)

    for pad in sort_alphanumeric(availablePinDictionary.values()):
        key = pad
        value = list(availablePinDictionary.keys())[list(availablePinDictionary.values()).index(pad)]
        description = pad
        spiChipSelectPin.addKey(key, value, description)

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
        source['component'].getSymbolByID('HAL_INTERFACE').setValue(targetID)
        source['component'].getSymbolByID('INTERFACE').setReadOnly(True)
        source['component'].getSymbolByID('INTERFACE').setSelectedKey('ATCA_I2C_IFACE', 0)
        updateSercomPlibList(target['id'], True)
    elif 'SPI' in sourceID:
        source['component'].getSymbolByID('HAL_INTERFACE').setValue(targetID)
        source['component'].getSymbolByID('INTERFACE').setReadOnly(True)
        source['component'].getSymbolByID('INTERFACE').setSelectedKey('ATCA_SPI_IFACE', 1)
        updateSercomPlibList(target['id'], True)


def onAttachmentDisconnected(source, target):
    sourceID = source['id'].upper()
    targetID = target['component'].getID().upper()

    if 'I2C' in sourceID:
        try:
            source['component'].getSymbolByID('HAL_INTERFACE').clearValue()
            source['component'].getSymbolByID('INTERFACE').clearValue()
            source['component'].getSymbolByID('INTERFACE').setReadOnly(False)
        except AttributeError:
            # Happens when the instance is deleted while attached
            pass
        updateSercomPlibList(target['id'], False)
    elif 'SPI' in sourceID:
        try:
            source['component'].getSymbolByID('HAL_INTERFACE').clearValue()
            source['component'].getSymbolByID('INTERFACE').clearValue()
            source['component'].getSymbolByID('INTERFACE').setReadOnly(False)
        except AttributeError:
            # Happens when the instance is deleted while attached
            pass
        updateSercomPlibList(target['id'], False)


