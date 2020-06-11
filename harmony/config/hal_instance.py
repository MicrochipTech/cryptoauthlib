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


def updatePlibList(plib, inc):
    Database.sendMessage('cryptoauthlib', 'UPDATE_PLIB_LIST', {'id': plib.lower(), 'inc': inc})


def instantiateComponent(deviceComponent, index):
    global devicePartType
    deviceID = deviceComponent.getID().upper()
    configName = Variables.get('__CONFIGURATION_NAME')

    #I2C Configuration
    devicePLIB = deviceComponent.createStringSymbol("DRV_PLIB", None)
    devicePLIB.setLabel("PLIB Used")
    devicePLIB.setReadOnly(True)
    devicePLIB.setDefaultValue("")


def onAttachmentConnected(source, target):
    sourceID = source['id'].upper()
    targetID = target['component'].getID().upper()

    plib_type = target['id'].split('_')[1].upper()

    if plib_type in ['I2C', 'UART']:
        source['component'].getSymbolByID('DRV_PLIB').setValue(targetID)
        updatePlibList(target['id'], True)

        

def onAttachmentDisconnected(source, target):
    sourceID = source['id'].upper()
    targetID = target['component'].getID().upper()

    plib_type = target['id'].split('_')[1].upper()

    if plib_type in ['I2C', 'UART']:
        try:
            source['component'].getSymbolByID('DRV_PLIB').clearValue()
        except AttributeError:
            # Happens when the instance is deleted while attached
            pass
        updatePlibList(target['id'], False)


