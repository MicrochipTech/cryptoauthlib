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

fileSymbolName = "CAL_FILE_SRC_PKCS11_"
numFileCntr = 0

_tng_type_tracker = {}


def AddFile(component, src_path, dest_path, proj_path, file_type = "SOURCE", isMarkup = False):
    global fileSymbolName
    global numFileCntr
    srcFile = component.createFileSymbol(fileSymbolName + str(numFileCntr) , None)
    srcFile.setSourcePath(src_path)
    srcFile.setDestPath(dest_path)
    srcFile.setProjectPath(proj_path)
    srcFile.setType(file_type)
    srcFile.setOutputName(os.path.basename(src_path))
    srcFile.setMarkup(isMarkup)
    numFileCntr += 1


def AddFilesDir(component, configName, dirPath):
    modulePath = Module.getPath()
    dirPath = str(modulePath + dirPath)
    for (root, dirs, files) in os.walk(dirPath):
        for filename in files:
            filepath = str(root + os.sep + filename)
            source_path = filepath[len(modulePath):]
            destination_path = "library" + os.sep + "cryptoauthlib" + os.sep + "pkcs11" + root[len(dirPath):]
            project_path = str("config" + os.sep + configName + os.sep + destination_path)
            if (".c" in filename):
                AddFile(component, source_path , destination_path, project_path)
            elif (".h" in filename):
                AddFile(component, source_path , destination_path, project_path, "HEADER")



def onAttachmentConnected(source, target):
    pass

def onAttachmentDisconnected(source, target):
    pass

def instantiateComponent(calPkcs11Component):
    # Makes sure the Library is included as well.
    Database.activateComponents(['cryptoauthlib'])

    configName = Variables.get("__CONFIGURATION_NAME")

    AddFilesDir(calPkcs11Component, configName, 'lib/pkcs11')


    calPkcs11TngFile = calPkcs11Component.createFileSymbol("CAL_FILE_SRC_FREERTOS", None)
    calPkcs11TngFile.setSourcePath("app/pkcs11/trust_pkcs11_config.c")
    calPkcs11TngFile.setOutputName("trust_pkcs11_config.c")
    calPkcs11TngFile.setDestPath("library/cryptoauthlib/app/pkcs11")
    calPkcs11TngFile.setProjectPath("config/" + configName + "/library/cryptoauthlib/app/pkcs11")
    calPkcs11TngFile.setType('SOURCE')
    calPkcs11TngFile.setEnabled(True)

    # Configuration options for the PKCS11 module
    calPkcs11ExternalFuncList = calPkcs11Component.createBooleanSymbol("CAL_PKCS11_EXT_FUNC_LIST", None)
    calPkcs11ExternalFuncList.setLabel("Enable external function list definition?")
    calPkcs11ExternalFuncList.setDefaultValue(False)
    calPkcs11ExternalFuncList.setVisible(True)
    
    calPkcs11DebugPrint = calPkcs11Component.createBooleanSymbol("CAL_PKCS11_ENABLE_DEBUG_PRINT", None)
    calPkcs11DebugPrint.setLabel("Enable Debug Print?")
    calPkcs11DebugPrint.setDefaultValue(False)

    calPkcs11AwsFreeRTOS = calPkcs11Component.createBooleanSymbol("CAL_PKCS11_AWS_FREERTOS", None)
    calPkcs11AwsFreeRTOS.setLabel("Enable AWS FreeRTOS Modifications?")
    calPkcs11AwsFreeRTOS.setDefaultValue(False)

    calPkcs11MaxSlots = calPkcs11Component.createIntegerSymbol('CAL_PKCS11_MAX_SLOTS', None)
    calPkcs11MaxSlots.setLabel('Maximum number of PKCS11 slots')
    calPkcs11MaxSlots.setDefaultValue(1)

    calPkcs11MaxSessions = calPkcs11Component.createIntegerSymbol('CAL_PKCS11_MAX_SESSIONS', None)
    calPkcs11MaxSessions.setLabel('Maximum number of PKCS11 sessions')
    calPkcs11MaxSessions.setDefaultValue(2)
    
    calPkcs11MaxObjects = calPkcs11Component.createIntegerSymbol('CAL_PKCS11_MAX_OBJECTS', None)
    calPkcs11MaxObjects.setLabel('Maximum number of PKCS11 objects')
    calPkcs11MaxObjects.setDefaultValue(16)
    
    calPkcs11MaxLabelSize = calPkcs11Component.createIntegerSymbol('CAL_PKCS11_MAX_LABEL_LENGTH', None)
    calPkcs11MaxLabelSize.setLabel('Maximum length of PKCS11 labels')
    calPkcs11MaxLabelSize.setDefaultValue(30)

    # Configuration header file 
    pkcs11ConfigFile = calPkcs11Component.createFileSymbol("CAL_LIB_PKCS11_CONFIG_DATA", None)
    pkcs11ConfigFile.setSourcePath("harmony/templates/pkcs11_config.h.ftl")
    pkcs11ConfigFile.setOutputName("pkcs11_config.h")
    pkcs11ConfigFile.setDestPath("library/cryptoauthlib/pkcs11")
    pkcs11ConfigFile.setProjectPath("config/" + configName + "/library/cryptoauthlib/pkcs11")
    pkcs11ConfigFile.setType("HEADER")
    pkcs11ConfigFile.setOverwrite(True)
    pkcs11ConfigFile.setMarkup(True)



