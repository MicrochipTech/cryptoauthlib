# coding: utf-8
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
import glob

fileSymbolName = "CAL_FILE_SRC_KIT_HOST_"
numFileCntr = 0


def handleMessage(messageID, args):
    return {}


def updateSercomPlibList(plib, inc):
    Database.sendMessage('cryptoauthlib', 'UPDATE_PLIB_LIST', {'id': plib.lower(), 'inc': inc})


def onAttachmentConnected(source, target):
    if "uart" in target['id'].lower():
        source['component'].getSymbolByID('HAL_INTERFACE').setValue(target['id'])
        updateSercomPlibList(target['id'], True)


def onAttachmentDisconnected(source, target):
    if "uart" in target['id'].lower():
        source['component'].getSymbolByID('HAL_INTERFACE').clearValue()
        updateSercomPlibList(target['id'], False)


def CALSecFileUpdate(symbol, event):
    symObj = event['symbol']
    selected_key = symObj.getSelectedKey()

    if selected_key == "SECURE":
        symbol.setSecurity("SECURE")
    elif selected_key == "NON_SECURE":
        symbol.setSecurity("NON_SECURE")


def AddFile(component, src_path, dest_path, proj_path, file_type = "SOURCE", isMarkup = False, enable=True):
    global fileSymbolName
    global numFileCntr
    srcFile = component.createFileSymbol(fileSymbolName + str(numFileCntr) , None)
    srcFile.setSourcePath(src_path)
    srcFile.setDestPath(dest_path)
    srcFile.setProjectPath(proj_path)
    srcFile.setType(file_type)
    srcFile.setOutputName(os.path.basename(src_path))
    srcFile.setMarkup(isMarkup)
    srcFile.setEnabled(enable)
    srcFile.setDependencies(CALSecFileUpdate, ["CAL_NON_SECURE"])
    numFileCntr += 1


def AddFilesDir(component, base_path, search_pattern, destination_path, project_path, enable=True):
    modulePath = os.path.expanduser(Module.getPath())

    filelist = glob.iglob(modulePath + os.sep + base_path + os.sep + search_pattern)

    for x in filelist:
        _, ext = os.path.splitext(x)
        if ext in ['.c','.h']:
            source_path = os.path.relpath(os.path.abspath(x), modulePath)
            file_path = str(os.path.dirname(os.path.relpath(source_path, base_path)))
            file_destination = destination_path + os.sep + file_path
            file_project = project_path + '/' + file_path
            AddFile(component, source_path, file_destination, file_project.replace('\\','/'),
                file_type='HEADER' if ext is 'h' else 'SOURCE', enable=enable)


def instantiateComponent(kitHostComponent):
    # Makes sure the Library is included as well.
    Database.activateComponents(['cryptoauthlib'])

    configName = Variables.get("__CONFIGURATION_NAME")

    kitHostPlib = kitHostComponent.createStringSymbol("HAL_INTERFACE", None)
    kitHostPlib.setLabel("PLIB Used")
    kitHostPlib.setReadOnly(True)
    kitHostPlib.setDefaultValue("")

    AddFilesDir(kitHostComponent, 'app/kit_host', 'ascii_kit_host.c', 'library/cryptoauthlib/kit_host', 
            'config/{}/library/cryptoauthlib/kit_host'.format(configName))
    AddFilesDir(kitHostComponent, 'app/kit_host', 'ascii_kit_host.h', 'library/cryptoauthlib/kit_host', 
            'config/{}/library/cryptoauthlib/kit_host'.format(configName))
    
    AddFilesDir(kitHostComponent, 'lib/hal', 'kit_protocol.c', 'library/cryptoauthlib/hal',
            'config/{}/library/cryptoauthlib/hal'.format(configName))
    AddFilesDir(kitHostComponent, 'lib/hal', 'kit_protocol.h', 'library/cryptoauthlib/hal',
            'config/{}/library/cryptoauthlib/hal'.format(configName))


    calKitHostInitFile = kitHostComponent.createFileSymbol("CAL_KIT_HOST_DATA", None)
    calKitHostInitFile.setSourcePath("harmony/templates/kit_host_init.c.ftl")
    calKitHostInitFile.setOutputName("kit_host_init.c")
    calKitHostInitFile.setDestPath("library/cryptoauthlib/kit_host")
    calKitHostInitFile.setProjectPath("config/" + configName + "/library/cryptoauthlib/kit_host")
    calKitHostInitFile.setType("SOURCE")
    calKitHostInitFile.setOverwrite(True)
    calKitHostInitFile.setMarkup(True)
    calKitHostInitFile.setDependencies(CALSecFileUpdate, ["cryptoauthlib.CAL_NON_SECURE"])


