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

fileSymbolName = "CAL_FILE_SRC_WPC_"
numFileCntr = 0

_wpc_type_tracker = {}


def CALSecFileUpdate(symbol, event):
    symObj = event['symbol']
    selected_key = symObj.getSelectedKey()

    if selected_key == "SECURE":
        symbol.setSecurity("SECURE")
    elif selected_key == "NON_SECURE":
        symbol.setSecurity("NON_SECURE")


def updateTracker(id, src):
    global _wpc_type_tracker
    _wpc_type_tracker[src] = id

    values = set(_wpc_type_tracker.values())

    tflxwpc = Database.getComponentByID('cryptoauthlib_wpc').getSymbolByID('CAL_TFLXWPC_SUPPORT')
    tflxwpc.setValue('TFLXWPC' in values)

def handleMessage(messageID, args):
    if (messageID == 'UPDATE_WPC_TYPE'):
        if isinstance(args, dict):
            updateTracker(**args)

    return {}

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
    try:
        CALSecValue = Database.getComponentByID('cryptoauthlib').getSymbolByID('CAL_NON_SECURE').getValue()
        if CALSecValue == True:
            srcFile.setSecurity("SECURE")
    except:
        pass
    srcFile.setDependencies(CALSecFileUpdate, ["cryptoauthlib.CAL_NON_SECURE"])
    numFileCntr += 1

def AddFilesDir(component, configName, dirPath):
    modulePath = Module.getPath()
    dirPath = str(modulePath + dirPath)
    for (root, dirs, files) in os.walk(dirPath):
        for filename in files:
            filepath = str(root + os.sep + filename)
            source_path = filepath[len(modulePath):]
            destination_path = "library" + os.sep + "cryptoauthlib" + os.sep + os.path.basename(dirPath) + root[len(dirPath):]
            project_path = str("config" + os.sep + configName + os.sep + destination_path)
            if (".c" in filename):
                AddFile(component, source_path , destination_path, project_path)
            elif (".h" in filename):
                AddFile(component, source_path , destination_path, project_path, "HEADER")



def onAttachmentConnected(source, target):
    pass

def onAttachmentDisconnected(source, target):
    pass

def instantiateComponent(wpcComponent):
    # Makes sure the Library is included as well.
    Database.activateComponents(['cryptoauthlib'])

    configName = Variables.get("__CONFIGURATION_NAME")
    
    targetPath = '../src/config/' + configName + '/library/cryptoauthlib/wpc'
    
    # Append the include paths in MPLABX IDE
    defSym = wpcComponent.createSettingSymbol("CAL_XC32_INCLUDE_DIRS", None)
    defSym.setCategory("C32")
    defSym.setKey("extra-include-directories")

    defSym.setValue( '{0}'.format(targetPath))
    defSym.setAppend(True, ';')
    defSym.setDependencies(CALSecFileUpdate, ["CAL_NON_SECURE"])

    AddFilesDir(wpcComponent, configName, 'app/wpc')

