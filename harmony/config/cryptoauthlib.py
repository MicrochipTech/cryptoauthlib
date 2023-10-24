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

fileSymbolName = "CAL_FILE_SRC_"
numFileCntr = 0
_ca_dev_cnt = 0
_ta_dev_cnt = 0

calPlibTracker = {}
calHalTracker = {}

_HAL_FILES = ["atca_hal.c", "atca_hal.h"]
_CORE_PATHS = ['crypto/**/*', 'crypto/*', 'jwt/*', '*']
_CA_PATHS = ['atcacert/*', 'calib/*', 'host/*']
_TA_PATHS = ['talib/*']
_SHA206_PATHS = ['api_206a/*']
_EXCL_FILES = ['atca_utils_sizes.c']

def CALSecFileUpdate(symbol, event):
    symObj = event['symbol']
    selected_key = symObj.getSelectedKey()

    if selected_key == "SECURE":
        symbol.setSecurity("SECURE")
    elif selected_key == "NON_SECURE":
        symbol.setSecurity("NON_SECURE")


def add_value_to_list(symbol_list, value):
    values = list(symbol_list.getValues())
    if value not in values:
        symbol_list.addValue(value)


def del_value_from_list(symbol_list, value):
    values = list(symbol_list.getValues())
    if value in values:
        symbol_list.clearValues()
        values.remove(value)
        for v in values:
            symbol_list.addValue(v)


def updateHalTracker(id, inc):
    global calHalTracker
    cnt = calHalTracker.pop(id, 0)
    if inc:
        cnt += 1
        calHalTracker[id] = cnt
    elif cnt > 0:
        cnt -= 1

    symbol = Database.getComponentByID('cryptoauthlib').getSymbolByID('CAL_FILE_SRC_HAL_' + id)
    symbol.setEnabled(cnt > 0)

    try:
        symbol = Database.getComponentByID('cryptoauthlib').getSymbolByID('CAL_FILE_SRC_HAL_{}_HEADER'.format(id))
        symbol.setEnabled(cnt > 0)
    except:
        pass

    calHalList = Database.getComponentByID('cryptoauthlib').getSymbolByID('CAL_HAL_LIST_ENTRIES')

    if cnt == 0:
        del_value_from_list(calHalList, id)
    else:
        add_value_to_list(calHalList, id)


def updatePlibTracker(id, inc):
    # id is of the form: <plib>_<hal>_<mode>
    global calPlibTracker
    cnt = calPlibTracker.pop(id, 0)
    if inc:
        cnt += 1
        calPlibTracker[id] = cnt
    elif cnt > 0:
        cnt -= 1

    hal_ids = id.upper().split('_')[1:]
    if len(hal_ids) > 1:
        updateHalTracker('_'.join(hal_ids), inc)
        updateHalTracker(hal_ids[1], inc)
    else:
        updateHalTracker(hal_ids[0], inc)

    calPlibList = Database.getComponentByID('cryptoauthlib').getSymbolByID('CAL_PLIB_LIST_ENTRIES')

    if cnt == 0:
        del_value_from_list(calPlibList, id)
    else:
        add_value_to_list(calPlibList, id)


def updateDevCfgTracker(id, inc):
    calDevCfgList = Database.getComponentByID('cryptoauthlib').getSymbolByID('CAL_DEV_CFG_LIST_ENTRIES')

    if inc:
        add_value_to_list(calDevCfgList, id)
    else:
        del_value_from_list(calDevCfgList, id)


def extendDevCfgList(new_list, cnt):
    calDevCfgList = Database.getComponentByID('cryptoauthlib').getSymbolByID('CAL_DEV_CFG_LIST_ENTRIES')

    for value in new_list:
        values = list(calDevCfgList.getValues())
        if value not in values:
            calDevCfgList.addValue(value)


def handleMessage(messageID, args):
    global calPlibTracker

    if (messageID == 'UPDATE_PLIB_LIST'):
        if isinstance(args, dict):
            updatePlibTracker(**args)

    if (messageID == 'UPDATE_DEV_CFG_LIST'):
        if isinstance(args, dict):
            updateDevCfgTracker(**args)

    if (messageID == 'EXTEND_DEV_CFG_LIST'):
        if isinstance(args, dict):
            extendDevCfgList(**args)

    return {}


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


def updateFileEnable(component, pattern, enable):
    global numFileCntr
    for x in range(numFileCntr):
        srcFile = component.getSymbolByID(fileSymbolName + str(x))
        if srcFile is not None:
            if any(p.replace('/*','') in srcFile.getDestPath() for p in pattern):
                srcFile.setEnabled(enable)


def excludeFiles(component, file_names):
    global numFileCntr
    for x in range(numFileCntr):
        srcFile = component.getSymbolByID(fileSymbolName + str(x))
        if srcFile and (srcFile.getOutputName() in file_names):
            srcFile.setEnabled(False)


def check_if_file_exists(component, pattern):
    global numFileCntr
    for x in range(numFileCntr):
        srcFile = component.getSymbolByID(fileSymbolName + str(x))
        if srcFile is not None:
            if pattern.replace('/*','') in srcFile.getOutputName():
                return True
    return False


def onAttachmentConnected(source, target):
    global _ca_dev_cnt
    global _ta_dev_cnt
    srcComponent = source["component"]
    srcConnectionID = source["id"]

    targetComponentID = target["component"].getID().upper()

    # Check if a dependency got satisfied
    if srcConnectionID == 'CAL_LIB_CAP' and 'CRYPTOAUTHLIB' not in targetComponentID and '_' in targetComponentID:
        calDeviceList = srcComponent.getSymbolByID('CAL_DEVICE_LIST_ENTRIES')
        add_value_to_list(calDeviceList, targetComponentID.split('_')[0])
        if ('TA10' in targetComponentID):
            _ta_dev_cnt += 1
            updateFileEnable(srcComponent, _TA_PATHS, True)
            calTaConfig = srcComponent.getSymbolByID('TALIB_CONFIG_DATA')
            calTaConfig.setEnabled(True)
            if check_if_file_exists(srcComponent, 'talib_fce'):
                calTaEnableFce = srcComponent.getSymbolByID('CAL_ENABLE_TA10x_FCE')
                calTaEnableFce.setValue(True)
        else:
            _ca_dev_cnt += 1
            if 'SHA206' in targetComponentID:
                updateFileEnable(srcComponent, _SHA206_PATHS, True)
            updateFileEnable(srcComponent, _CA_PATHS, True)

    if srcConnectionID == 'FreeRTOS':
        calEnableRtos = srcComponent.getSymbolByID('CAL_ENABLE_RTOS')
        calEnableRtos.setValue(True)

        # Include the FreeRTOS OSAL in the project
        srcComponent.getSymbolByID('CAL_FILE_SRC_FREERTOS').setEnabled(True)

    if targetComponentID == 'LIB_WOLFCRYPT':
        calEnableWolfCrypto = srcComponent.getSymbolByID('CAL_ENABLE_WOLFCRYPTO')
        calEnableWolfCrypto.setValue(True)

        WolfCrypto = srcComponent.getSymbolByID('CAL_FILE_SRC_WOLFSSL_WRAPPER')
        WolfCrypto.setEnabled(True)

        calTaEnableAesAuth = srcComponent.getSymbolByID('CAL_ENABLE_TA10x_AES_AUTH')
        calTaEnableAesAuth.setValue(True)

    excludeFiles(srcComponent, _EXCL_FILES)



def onAttachmentDisconnected(source, target):
    global _ca_dev_cnt
    global _ta_dev_cnt
    srcComponent = source["component"]
    srcConnectionID = source["id"]

    targetComponentID = target["component"].getID().upper()

    if srcConnectionID == 'CAL_LIB_CAP' and '_' in targetComponentID:
        calDeviceList = srcComponent.getSymbolByID('CAL_DEVICE_LIST_ENTRIES')
        del_value_from_list(calDeviceList, targetComponentID.split('_')[0])
        if ('TA10' in targetComponentID):
            _ta_dev_cnt -= 1
            if 0 == _ta_dev_cnt:
                updateFileEnable(srcComponent, _TA_PATHS, False)
                calTaEnableFce = srcComponent.getSymbolByID('CAL_ENABLE_TA10x_FCE')
                calTaEnableFce.setValue(False)
                calTaConfig = srcComponent.getSymbolByID('TALIB_CONFIG_DATA')
                calTaConfig.setEnabled(False)
                calTaEnableAesAuth = srcComponent.getSymbolByID('CAL_ENABLE_TA10x_AES_AUTH')
                calTaEnableAesAuth.setValue(False)
        else:
            _ca_dev_cnt -= 1
            if 0 == _ca_dev_cnt:
                if 'SHA206' in targetComponentID:
                    updateFileEnable(srcComponent, _SHA206_PATHS, False)
                updateFileEnable(srcComponent, _CA_PATHS, False)


    if srcConnectionID == 'FreeRTOS':
        calEnableRtos = srcComponent.getSymbolByID('CAL_ENABLE_RTOS')
        calEnableRtos.setValue(False)

        # Removes the FreeRTOS OSAL from the project
        srcComponent.getSymbolByID('CAL_FILE_SRC_FREERTOS').setEnabled(False)

    if targetComponentID == 'LIB_WOLFCRYPT':
        WolfCrypto = srcComponent.getSymbolByID('CAL_ENABLE_WOLFCRYPTO')
        WolfCrypto.setValue(False)

        WolfCrypto = srcComponent.getSymbolByID('CAL_FILE_SRC_WOLFSSL_WRAPPER')
        WolfCrypto.setEnabled(False)

        calTaEnableAesAuth = srcComponent.getSymbolByID('CAL_ENABLE_TA10x_AES_AUTH')
        calTaEnableAesAuth.setValue(False)



def instantiateComponent(calComponent):
    global processor

    calInstanceIndex = calComponent.createIntegerSymbol("INDEX", None)
    calInstanceIndex.setVisible(False)
    calInstanceIndex.setDefaultValue(0)

    configName = Variables.get("__CONFIGURATION_NAME")
    processor =     Variables.get( "__PROCESSOR" )
    architecture = Variables.get('__ARCH_DIR').split('\\')[-1]

    targetPath = '../src/config/' + configName + '/library/cryptoauthlib'

    # Append the include paths in MPLABX IDE
    defSym = calComponent.createSettingSymbol("CAL_XC32_INCLUDE_DIRS", None)
    defSym.setCategory("C32")
    defSym.setKey("extra-include-directories")

    defSym.setValue( '{0};{0}/crypto;{0}/pkcs11'.format(targetPath))
    defSym.setAppend(True, ';')
    defSym.setDependencies(CALSecFileUpdate, ["CAL_NON_SECURE"])

    # Add core library files
    for search_path in _CORE_PATHS:
        AddFilesDir(calComponent, 'lib', search_path, 'library/cryptoauthlib',
            'config/{}/library/cryptoauthlib'.format(configName))

    # Add device library files (default disabled)
    for search_path in _CA_PATHS:
        AddFilesDir(calComponent, 'lib', search_path, 'library/cryptoauthlib',
            'config/{}/library/cryptoauthlib'.format(configName), enable=False)

    for search_path in _TA_PATHS:
        AddFilesDir(calComponent, 'lib', search_path, 'library/cryptoauthlib',
            'config/{}/library/cryptoauthlib'.format(configName), enable=False)

    for search_path in _SHA206_PATHS:
        AddFilesDir(calComponent, 'app', search_path, 'library/cryptoauthlib/app',
            'config/{}/library/cryptoauthlib/app'.format(configName), enable=False)

    # Add individual files
    for hal_file in _HAL_FILES:
        AddFilesDir(calComponent, 'lib/hal', hal_file, 'library/cryptoauthlib/hal',
            'config/{}/library/cryptoauthlib/hal'.format(configName))

    calEnableHeap = calComponent.createBooleanSymbol("CAL_ENABLE_HEAP", None)
    calEnableHeap.setLabel("Enable Heap?")
    calEnableHeap.setVisible(True)

    calDebugPrint = calComponent.createBooleanSymbol("CAL_ENABLE_DEBUG_PRINT", None)
    calDebugPrint.setLabel("Enable Debug Print?")
    calDebugPrint.setVisible(True)

    calPreprocessorWarning = calComponent.createBooleanSymbol("CAL_ENABLE_PREPROCESSOR_WARNING", None)
    calPreprocessorWarning.setLabel("Enable Preprocessor Warning?")
    calPreprocessorWarning.setVisible(True)

    calEnablePolling = calComponent.createBooleanSymbol("CAL_ENABLE_POLLING", None)
    calEnablePolling.setLabel("Enable Polling for Response?")
    calEnablePolling.setDefaultValue(True)
    calEnablePolling.setVisible(True)

    calPollingInitTime = calComponent.createIntegerSymbol('CAL_POLL_INIT_TIME', None)
    calPollingInitTime.setLabel('Polling Init Time (ms)')
    calPollingInitTime.setDefaultValue(1)

    calPollingPeriod = calComponent.createIntegerSymbol('CAL_POLL_PERIOD', None)
    calPollingPeriod.setLabel('Polling Period (ms)')
    calPollingPeriod.setDefaultValue(2)

    calPollingTimeout = calComponent.createIntegerSymbol('CAL_POLL_TIMEOUT', None)
    calPollingTimeout.setLabel('Polling Timeout (ms)')
    calPollingTimeout.setDefaultValue(2500)

    calEnablejwt = calComponent.createBooleanSymbol("CAL_ENABLE_JWT", None)
    calEnablejwt.setLabel("Enable jwt functionality?")
    calEnablejwt.setVisible(True)
    
    calMaxPacketSize = calComponent.createIntegerSymbol('CAL_MAX_PACKET_SIZE', None)
    calMaxPacketSize.setLabel('Maximum packet size (bytes)')
    calMaxPacketSize.setDefaultValue(1072)

    # Symmetric Cryptography Commands
    symmetricCommands = calComponent.createMenuSymbol("cal_symmetric_commands", None)
    symmetricCommands.setLabel("Symmetric Cryptography Commands")
    symmetricCommands.setVisible(True)

    # AES
    calAesEnabledSymbol = calComponent.createBooleanSymbol("cal_aes", symmetricCommands)
    calAesEnabledSymbol.setLabel("Support AES?")
    calAesEnabledSymbol.setDescription("Enable support for AES Command")
    calAesEnabledSymbol.setVisible(True)
    calAesEnabledSymbol.setDefaultValue(True)

    calAesEcbEnabledSymbol = calComponent.createBooleanSymbol("cal_aes_ecb", calAesEnabledSymbol)
    calAesEcbEnabledSymbol.setLabel("Support ECB Mode?")
    calAesEcbEnabledSymbol.setDescription("Enable support for AES ECB Mode")
    calAesEcbEnabledSymbol.setVisible(True)
    calAesEcbEnabledSymbol.setDefaultValue(True)
    calAesEcbEnabledSymbol.setDependencies(handleParentSymbolChange, ["cal_aes"])

    calAesGfmEnabledSymbol = calComponent.createBooleanSymbol("cal_aes_gfm", calAesEnabledSymbol)
    calAesGfmEnabledSymbol.setLabel("Support GFM Mode?")
    calAesGfmEnabledSymbol.setDescription("Enable support for AES GFM Mode")
    calAesGfmEnabledSymbol.setVisible(True)
    calAesGfmEnabledSymbol.setDefaultValue(True)
    calAesGfmEnabledSymbol.setDependencies(handleParentSymbolChange, ["cal_aes"])

    calAesGcmEnabledSymbol = calComponent.createBooleanSymbol("cal_aes_gcm", calAesEnabledSymbol)
    calAesGcmEnabledSymbol.setLabel("Support GCM Mode?")
    calAesGcmEnabledSymbol.setDescription("Enable support for AES GCM Mode")
    calAesGcmEnabledSymbol.setVisible(True)
    calAesGcmEnabledSymbol.setDefaultValue(True)
    calAesGcmEnabledSymbol.setDependencies(handleParentSymbolChange, ["cal_aes"])

    # CHECKMAC
    calCheckmacEnabledSymbol = calComponent.createBooleanSymbol("cal_checkmac", symmetricCommands)
    calCheckmacEnabledSymbol.setLabel("Support Checkmac?")
    calCheckmacEnabledSymbol.setDescription("Enable support for CHECKMAC Command")
    calCheckmacEnabledSymbol.setVisible(True)
    calCheckmacEnabledSymbol.setDefaultValue(True)

    # GENDIG
    calGendigEnabledSymbol = calComponent.createBooleanSymbol("cal_gendig", symmetricCommands)
    calGendigEnabledSymbol.setLabel("Support Gendig?")
    calGendigEnabledSymbol.setDescription("Enable support for GENDIG Command")
    calGendigEnabledSymbol.setVisible(True)
    calGendigEnabledSymbol.setDefaultValue(True)

    # KDF
    calKdfEnabledSymbol = calComponent.createBooleanSymbol("cal_kdf", symmetricCommands)
    calKdfEnabledSymbol.setLabel("Support KDF?")
    calKdfEnabledSymbol.setDescription("Enable support for KDF Command")
    calKdfEnabledSymbol.setVisible(True)
    calKdfEnabledSymbol.setDefaultValue(True)

    # MAC
    calMacEnabledSymbol = calComponent.createBooleanSymbol("cal_mac", symmetricCommands)
    calMacEnabledSymbol.setLabel("Support MAC?")
    calMacEnabledSymbol.setDescription("Enable support for MAC Command")
    calMacEnabledSymbol.setVisible(True)
    calMacEnabledSymbol.setDefaultValue(True)

    # HMAC
    calHmacEnabledSymbol = calComponent.createBooleanSymbol("cal_hmac", symmetricCommands)
    calHmacEnabledSymbol.setLabel("Support HMAC?")
    calHmacEnabledSymbol.setDescription("Enable support for Hmac Command")
    calHmacEnabledSymbol.setVisible(True)
    calHmacEnabledSymbol.setDefaultValue(True)

    # Asymmetric Cryptography Commands
    asymmetricCommands = calComponent.createMenuSymbol("cal_asymmetric_commands", None)
    asymmetricCommands.setLabel("Asymmetric Cryptography Commands")
    asymmetricCommands.setVisible(True)

    # ECDH
    calEcdhEnabledSymbol = calComponent.createBooleanSymbol("cal_ecdh", asymmetricCommands)
    calEcdhEnabledSymbol.setLabel("Support ECDH?")
    calEcdhEnabledSymbol.setDescription("Enable support for ECDH Command")
    calEcdhEnabledSymbol.setVisible(True)
    calEcdhEnabledSymbol.setDefaultValue(True)

    calEcdhEncEnabledSymbol = calComponent.createBooleanSymbol("cal_ecdh_enc", calEcdhEnabledSymbol)
    calEcdhEncEnabledSymbol.setLabel("Support ECDH Encryption?")
    calEcdhEncEnabledSymbol.setDescription("Enable support for ECDH ENC")
    calEcdhEncEnabledSymbol.setVisible(True)
    calEcdhEncEnabledSymbol.setDefaultValue(True)
    calEcdhEncEnabledSymbol.setDependencies(handleParentSymbolChange, ["cal_ecdh"])

    # GENKEY
    calGenkeyEnabledSymbol = calComponent.createBooleanSymbol("cal_genkey", asymmetricCommands)
    calGenkeyEnabledSymbol.setLabel("Support Genkey?")
    calGenkeyEnabledSymbol.setDescription("Enable support for Genkey Command")
    calGenkeyEnabledSymbol.setVisible(True)
    calGenkeyEnabledSymbol.setDefaultValue(True)

    calGenkeyMacEnabledSymbol = calComponent.createBooleanSymbol("cal_genkey_mac", calGenkeyEnabledSymbol)
    calGenkeyMacEnabledSymbol.setLabel("Support Genkey MAC?")
    calGenkeyMacEnabledSymbol.setDescription("Enable support for GENKEY MAC")
    calGenkeyMacEnabledSymbol.setVisible(True)
    calGenkeyMacEnabledSymbol.setDefaultValue(True)

    # SIGN
    calSignEnabledSymbol = calComponent.createBooleanSymbol("cal_sign", asymmetricCommands)
    calSignEnabledSymbol.setLabel("Support Sign?")
    calSignEnabledSymbol.setDescription("Enable support for SIGN Command")
    calSignEnabledSymbol.setVisible(True)
    calSignEnabledSymbol.setDefaultValue(True)

    calSignInternalEnabledSymbol = calComponent.createBooleanSymbol("cal_sign_internal", calSignEnabledSymbol)
    calSignInternalEnabledSymbol.setLabel("Support Sign Internal?")
    calSignInternalEnabledSymbol.setDescription("Enable support for Sign Internal")
    calSignInternalEnabledSymbol.setVisible(True)
    calSignInternalEnabledSymbol.setDefaultValue(True)
    calSignInternalEnabledSymbol.setDependencies(handleParentSymbolChange, ["cal_sign"])

    # VERIFY
    calVerifyEnabledSymbol = calComponent.createBooleanSymbol("cal_verify", asymmetricCommands)
    calVerifyEnabledSymbol.setLabel("Support Verify?")
    calVerifyEnabledSymbol.setDescription("Enable support for VERIFY Command")
    calVerifyEnabledSymbol.setVisible(True)
    calVerifyEnabledSymbol.setDefaultValue(True)

    calVerifyStoredEnabledSymbol = calComponent.createBooleanSymbol("cal_verify_stored", calVerifyEnabledSymbol)
    calVerifyStoredEnabledSymbol.setLabel("Support Verify Stored?")
    calVerifyStoredEnabledSymbol.setDescription("Enable support for Verify Stored")
    calVerifyStoredEnabledSymbol.setVisible(True)
    calVerifyStoredEnabledSymbol.setDefaultValue(True)
    calVerifyStoredEnabledSymbol.setDependencies(handleParentSymbolChange, ["cal_verify"])

    calVerifyExternEnabledSymbol = calComponent.createBooleanSymbol("cal_verify_extern", calVerifyEnabledSymbol)
    calVerifyExternEnabledSymbol.setLabel("Support Verify Extern?")
    calVerifyExternEnabledSymbol.setDescription("Enable support for Verify Extern")
    calVerifyExternEnabledSymbol.setVisible(True)
    calVerifyExternEnabledSymbol.setDefaultValue(True)
    calVerifyExternEnabledSymbol.setDependencies(handleParentSymbolChange, ["cal_verify"])

    calVerifyValidateEnabledSymbol = calComponent.createBooleanSymbol("cal_verify_validate", calVerifyEnabledSymbol)
    calVerifyValidateEnabledSymbol.setLabel("Support Verify Validate?")
    calVerifyValidateEnabledSymbol.setDescription("Enable support for Verify Validate")
    calVerifyValidateEnabledSymbol.setVisible(True)
    calVerifyValidateEnabledSymbol.setDefaultValue(True)
    calVerifyValidateEnabledSymbol.setDependencies(handleParentSymbolChange, ["cal_verify"])

    calVerifyMacEnabledSymbol = calComponent.createBooleanSymbol("cal_verify_mac", calVerifyEnabledSymbol)
    calVerifyMacEnabledSymbol.setLabel("Support Verify Mac?")
    calVerifyMacEnabledSymbol.setDescription("Enable support for Verify Mac")
    calVerifyMacEnabledSymbol.setVisible(True)
    calVerifyMacEnabledSymbol.setDefaultValue(True)
    calVerifyMacEnabledSymbol.setDependencies(handleParentSymbolChange, ["cal_verify"])

    # General Device Commands
    deviceCommands = calComponent.createMenuSymbol("cal_device_commands", None)
    deviceCommands.setLabel("General Device Commands")
    deviceCommands.setVisible(True)

    # COUNTER
    calCounterEnabledSymbol = calComponent.createBooleanSymbol("cal_counter", deviceCommands)
    calCounterEnabledSymbol.setLabel("Support Counter?")
    calCounterEnabledSymbol.setDescription("Enable support for COUNTER Command")
    calCounterEnabledSymbol.setVisible(True)
    calCounterEnabledSymbol.setDefaultValue(True)

    # DELETE
    calDeleteEnabledSymbol = calComponent.createBooleanSymbol("cal_delete", deviceCommands)
    calDeleteEnabledSymbol.setLabel("Support Delete?")
    calDeleteEnabledSymbol.setDescription("Enable support for Delete Command")
    calDeleteEnabledSymbol.setVisible(True)
    calDeleteEnabledSymbol.setDefaultValue(False)

    # DERIVEKEY
    calDerivekeyEnabledSymbol = calComponent.createBooleanSymbol("cal_derivekey", deviceCommands)
    calDerivekeyEnabledSymbol.setLabel("Support Derivekey?")
    calDerivekeyEnabledSymbol.setDescription("Enable support for Derivekey Command")
    calDerivekeyEnabledSymbol.setVisible(True)
    calDerivekeyEnabledSymbol.setDefaultValue(True)

    # INFO
    calInfoEnabledSymbol = calComponent.createBooleanSymbol("cal_info", deviceCommands)
    calInfoEnabledSymbol.setLabel("Support Info?")
    calInfoEnabledSymbol.setDescription("Enable support for INFO Command")
    calInfoEnabledSymbol.setVisible(True)
    calInfoEnabledSymbol.setDefaultValue(True)

    # LOCK
    calLockEnabledSymbol = calComponent.createBooleanSymbol("cal_lock", deviceCommands)
    calLockEnabledSymbol.setLabel("Support Lock?")
    calLockEnabledSymbol.setDescription("Enable support for LOCK Command")
    calLockEnabledSymbol.setVisible(True)
    calLockEnabledSymbol.setDefaultValue(True)

    # NONCE
    calNonceEnabledSymbol = calComponent.createBooleanSymbol("cal_nonce", deviceCommands)
    calNonceEnabledSymbol.setLabel("Support Nonce?")
    calNonceEnabledSymbol.setDescription("Enable support for Nonce Command")
    calNonceEnabledSymbol.setVisible(True)
    calNonceEnabledSymbol.setDefaultValue(True)

    # PRIVWRITE
    calPrivWriteEnabledSymbol = calComponent.createBooleanSymbol("cal_privwrite", deviceCommands)
    calPrivWriteEnabledSymbol.setLabel("Support PrivWrite?")
    calPrivWriteEnabledSymbol.setDescription("Enable support for PrivWrite Command")
    calPrivWriteEnabledSymbol.setVisible(True)
    calPrivWriteEnabledSymbol.setDefaultValue(True)

    # RANDOM
    calRandomEnabledSymbol = calComponent.createBooleanSymbol("cal_random", deviceCommands)
    calRandomEnabledSymbol.setLabel("Support Random?")
    calRandomEnabledSymbol.setDescription("Enable support for Random Command")
    calRandomEnabledSymbol.setVisible(True)
    calRandomEnabledSymbol.setDefaultValue(True)

    # READ
    calReadEnabledSymbol = calComponent.createBooleanSymbol("cal_read", deviceCommands)
    calReadEnabledSymbol.setLabel("Support Read?")
    calReadEnabledSymbol.setDescription("Enable support for Read Command")
    calReadEnabledSymbol.setVisible(True)
    calReadEnabledSymbol.setDefaultValue(True)

    calReadEncEnabledSymbol = calComponent.createBooleanSymbol("cal_read_enc", calReadEnabledSymbol)
    calReadEncEnabledSymbol.setLabel("Support Encrypted Read?")
    calReadEncEnabledSymbol.setDescription("Enable support for READ ENC")
    calReadEncEnabledSymbol.setVisible(True)
    calReadEncEnabledSymbol.setDefaultValue(True)
    calReadEncEnabledSymbol.setDependencies(handleParentSymbolChange, ["cal_read"])

    # SECUREBOOT
    calSecurebootEnabledSymbol = calComponent.createBooleanSymbol("cal_secureboot", deviceCommands)
    calSecurebootEnabledSymbol.setLabel("Support Secureboot?")
    calSecurebootEnabledSymbol.setDescription("Enable support for Secureboot Command")
    calSecurebootEnabledSymbol.setVisible(True)
    calSecurebootEnabledSymbol.setDefaultValue(True)

    calSecurebootMacEnabledSymbol = calComponent.createBooleanSymbol("cal_secureboot_mac", calSecurebootEnabledSymbol)
    calSecurebootMacEnabledSymbol.setLabel("Support Secureboot MAC?")
    calSecurebootMacEnabledSymbol.setDescription("Enable support for SECUREBOOT MAC")
    calSecurebootMacEnabledSymbol.setVisible(True)
    calSecurebootMacEnabledSymbol.setDefaultValue(True)
    calSecurebootMacEnabledSymbol.setDependencies(handleParentSymbolChange, ["cal_secureboot"])

    # SELFTEST
    calSelftestEnabledSymbol = calComponent.createBooleanSymbol("cal_selftest", deviceCommands)
    calSelftestEnabledSymbol.setLabel("Support Selftest?")
    calSelftestEnabledSymbol.setDescription("Enable support for Selftest Command")
    calSelftestEnabledSymbol.setVisible(True)
    calSelftestEnabledSymbol.setDefaultValue(True)

    # SHA
    calShaEnabledSymbol = calComponent.createBooleanSymbol("cal_sha", deviceCommands)
    calShaEnabledSymbol.setLabel("Support SHA?")
    calShaEnabledSymbol.setDescription("Enable support for Sha Command")
    calShaEnabledSymbol.setVisible(True)
    calShaEnabledSymbol.setDefaultValue(True)

    calShaHmacEnabledSymbol = calComponent.createBooleanSymbol("cal_sha_hmac", calShaEnabledSymbol)
    calShaHmacEnabledSymbol.setLabel("Support SHA HMAC?")
    calShaHmacEnabledSymbol.setDescription("Enable support for SHA HMAC")
    calShaHmacEnabledSymbol.setVisible(True)
    calShaHmacEnabledSymbol.setDefaultValue(True)
    calShaHmacEnabledSymbol.setDependencies(handleParentSymbolChange, ["cal_sha"])

    calShaContextEnabledSymbol = calComponent.createBooleanSymbol("cal_sha_context", calShaEnabledSymbol)
    calShaContextEnabledSymbol.setLabel("Support SHA Context?")
    calShaContextEnabledSymbol.setDescription("Enable support for SHA CONTEXT")
    calShaContextEnabledSymbol.setVisible(True)
    calShaContextEnabledSymbol.setDefaultValue(True)
    calShaContextEnabledSymbol.setDependencies(handleParentSymbolChange, ["cal_sha"])

    # UPDATEEXTRA
    calUpdateextraEnabledSymbol = calComponent.createBooleanSymbol("cal_updateextra", deviceCommands)
    calUpdateextraEnabledSymbol.setLabel("Support UpdateExtra?")
    calUpdateextraEnabledSymbol.setDescription("Enable support for Updateextra Command")
    calUpdateextraEnabledSymbol.setVisible(True)
    calUpdateextraEnabledSymbol.setDefaultValue(True)

    # WRITE
    calWriteEnabledSymbol = calComponent.createBooleanSymbol("cal_write", deviceCommands)
    calWriteEnabledSymbol.setLabel("Support Write?")
    calWriteEnabledSymbol.setDescription("Enable support for Write Command")
    calWriteEnabledSymbol.setVisible(True)
    calWriteEnabledSymbol.setDefaultValue(True)

    calWriteEncEnabledSymbol = calComponent.createBooleanSymbol("cal_write_enc", calWriteEnabledSymbol)
    calWriteEncEnabledSymbol.setLabel("Support Encrypted Write?")
    calWriteEncEnabledSymbol.setDescription("Enable support for WRITE ENC")
    calWriteEncEnabledSymbol.setVisible(True)
    calWriteEncEnabledSymbol.setDefaultValue(True)
    calWriteEncEnabledSymbol.setDependencies(handleParentSymbolChange, ["cal_write"])

    # Configurations for crypto implementations external library support
    calCryptoConfig = calComponent.createMenuSymbol("cal_crypto_config", None)
    calCryptoConfig.setLabel("Crypto Configurations")
    calCryptoConfig.setVisible(True)

    # Crypto HW AES
    calHwAesEnabledSymbol = calComponent.createBooleanSymbol("cal_hw_aes", calCryptoConfig)
    calHwAesEnabledSymbol.setLabel("Support Crypto Hw AES?")
    calHwAesEnabledSymbol.setDescription("Enable support for HArdware AES")
    calHwAesEnabledSymbol.setVisible(True)
    calHwAesEnabledSymbol.setDefaultValue(True)

    # Crypto HW AES-CBC
    calCryptoHWAESCBCEnabledSymbol = calComponent.createBooleanSymbol("cal_crypto_aes_cbc", calHwAesEnabledSymbol)
    calCryptoHWAESCBCEnabledSymbol.setLabel("Support Crypto Hw AES-CBC?")
    calCryptoHWAESCBCEnabledSymbol.setDescription("Enable support for Hardware AES-CBC")
    calCryptoHWAESCBCEnabledSymbol.setVisible(True)
    calCryptoHWAESCBCEnabledSymbol.setDefaultValue(True)
    calCryptoHWAESCBCEnabledSymbol.setDependencies(handleParentSymbolChange, ["cal_hw_aes"])

    calCryptoHWAESCBCEncEnabledSymbol = calComponent.createBooleanSymbol("cal_crypto_aes_cbc_encrypt", calCryptoHWAESCBCEnabledSymbol)
    calCryptoHWAESCBCEncEnabledSymbol.setLabel("Support Crypto Hw AES-CBC Encrypt?")
    calCryptoHWAESCBCEncEnabledSymbol.setDescription("Enable support for Hardware AES-CBC Encrypt")
    calCryptoHWAESCBCEncEnabledSymbol.setVisible(True)
    calCryptoHWAESCBCEncEnabledSymbol.setDefaultValue(True)
    calCryptoHWAESCBCEncEnabledSymbol.setDependencies(handleParentSymbolChange, ["cal_crypto_aes_cbc"])

    calCryptoHWAESCBCDecEnabledSymbol = calComponent.createBooleanSymbol("cal_crypto_aes_cbc_decrypt", calCryptoHWAESCBCEnabledSymbol)
    calCryptoHWAESCBCDecEnabledSymbol.setLabel("Support Crypto Hw AES-CBC Decrypt?")
    calCryptoHWAESCBCDecEnabledSymbol.setDescription("Enable support for Hardware AES-CBC Decrypt")
    calCryptoHWAESCBCDecEnabledSymbol.setVisible(True)
    calCryptoHWAESCBCDecEnabledSymbol.setDefaultValue(True)
    calCryptoHWAESCBCDecEnabledSymbol.setDependencies(handleParentSymbolChange, ["cal_crypto_aes_cbc"])

    # Crypto HW AES-CBCMAC
    calCryptoHWAESCBCMACEnabledSymbol = calComponent.createBooleanSymbol("cal_crypto_aes_cbcmac", calHwAesEnabledSymbol)
    calCryptoHWAESCBCMACEnabledSymbol.setLabel("Support Crypto Hw AES-CBCMAC?")
    calCryptoHWAESCBCMACEnabledSymbol.setDescription("Enable support for Hardware AES-CBCMAC")
    calCryptoHWAESCBCMACEnabledSymbol.setVisible(True)
    calCryptoHWAESCBCMACEnabledSymbol.setDefaultValue(True)
    calCryptoHWAESCBCMACEnabledSymbol.setDependencies(handleParentSymbolChange, ["cal_hw_aes"])

    # Crypto HW AES-CTR
    calCryptoHWAESCTREnabledSymbol = calComponent.createBooleanSymbol("cal_crypto_aes_ctr", calHwAesEnabledSymbol)
    calCryptoHWAESCTREnabledSymbol.setLabel("Support Crypto Hw AES-CTR?")
    calCryptoHWAESCTREnabledSymbol.setDescription("Enable support for Hardware AES-CTR")
    calCryptoHWAESCTREnabledSymbol.setVisible(True)
    calCryptoHWAESCTREnabledSymbol.setDefaultValue(True)
    calCryptoHWAESCTREnabledSymbol.setDependencies(handleParentSymbolChange, ["cal_hw_aes"])

    calCryptoHWAESCTRRANDEnabledSymbol = calComponent.createBooleanSymbol("cal_crypto_aes_ctr_rand_iv", calCryptoHWAESCTREnabledSymbol)
    calCryptoHWAESCTRRANDEnabledSymbol.setLabel("Support Crypto Hw AES-CTR Random Nonce?")
    calCryptoHWAESCTRRANDEnabledSymbol.setDescription("Enable support for Hardware AES-CTR Random Nonce")
    calCryptoHWAESCTRRANDEnabledSymbol.setVisible(True)
    calCryptoHWAESCTRRANDEnabledSymbol.setDefaultValue(True)
    calCryptoHWAESCTRRANDEnabledSymbol.setDependencies(handleParentSymbolChange, ["cal_crypto_aes_ctr"])

    # Crypto HW AES-CCM
    calCryptoHWAESCCMEnabledSymbol = calComponent.createBooleanSymbol("cal_crypto_aes_ccm", calHwAesEnabledSymbol)
    calCryptoHWAESCCMEnabledSymbol.setLabel("Support Crypto Hw AES-CCM?")
    calCryptoHWAESCCMEnabledSymbol.setDescription("Enable support for Hardware AES-CCM")
    calCryptoHWAESCCMEnabledSymbol.setVisible(True)
    calCryptoHWAESCCMEnabledSymbol.setDefaultValue(True)
    calCryptoHWAESCCMEnabledSymbol.setDependencies(handleParentSymbolChange, ["cal_hw_aes"])

    calCryptoHWAESCCMRANDEnabledSymbol = calComponent.createBooleanSymbol("cal_crypto_aes_ccm_rand_iv", calCryptoHWAESCCMEnabledSymbol)
    calCryptoHWAESCCMRANDEnabledSymbol.setLabel("Support Crypto Hw AES-CCM Random Nonce?")
    calCryptoHWAESCCMRANDEnabledSymbol.setDescription("Enable support for Hardware AES-CCM Random Nonce")
    calCryptoHWAESCCMRANDEnabledSymbol.setVisible(True)
    calCryptoHWAESCCMRANDEnabledSymbol.setDefaultValue(True)
    calCryptoHWAESCCMRANDEnabledSymbol.setDependencies(handleParentSymbolChange, ["cal_crypto_aes_ccm"])

    # Crypto HW AES-CMAC
    calCryptoHWAESCMACEnabledSymbol = calComponent.createBooleanSymbol("cal_crypto_aes_cmac", calHwAesEnabledSymbol)
    calCryptoHWAESCMACEnabledSymbol.setLabel("Support Crypto Hw AES-CMAC?")
    calCryptoHWAESCMACEnabledSymbol.setDescription("Enable support for Hardware AES-CMAC")
    calCryptoHWAESCMACEnabledSymbol.setVisible(True)
    calCryptoHWAESCMACEnabledSymbol.setDefaultValue(True)
    calCryptoHWAESCMACEnabledSymbol.setDependencies(handleParentSymbolChange, ["cal_hw_aes"])

    # Crypto SW SHA
    calSwShaEnabledSymbol = calComponent.createBooleanSymbol("cal_sw_sha", calCryptoConfig)
    calSwShaEnabledSymbol.setLabel("Support Crypto Sw SHA?")
    calSwShaEnabledSymbol.setDescription("Enable support for Software SHA")
    calSwShaEnabledSymbol.setVisible(True)
    calSwShaEnabledSymbol.setDefaultValue(True)

    # Crypto SW SHA1
    calCryptoSwSha1EnabledSymbol = calComponent.createBooleanSymbol("cal_sw_sha1", calSwShaEnabledSymbol)
    calCryptoSwSha1EnabledSymbol.setLabel("Support Crypto Sw SHA1?")
    calCryptoSwSha1EnabledSymbol.setDescription("Enable support for Software SHA1")
    calCryptoSwSha1EnabledSymbol.setVisible(True)
    calCryptoSwSha1EnabledSymbol.setDefaultValue(True)
    calCryptoSwSha1EnabledSymbol.setDependencies(handleParentSymbolChange, ["cal_sw_sha"])

    # Crypto SW SHA256
    calCryptoSwSha2EnabledSymbol = calComponent.createBooleanSymbol("cal_sw_sha2", calSwShaEnabledSymbol)
    calCryptoSwSha2EnabledSymbol.setLabel("Support Crypto Sw SHA256?")
    calCryptoSwSha2EnabledSymbol.setDescription("Enable support for Software SHA256")
    calCryptoSwSha2EnabledSymbol.setVisible(True)
    calCryptoSwSha2EnabledSymbol.setDefaultValue(True)
    calCryptoSwSha2EnabledSymbol.setDependencies(handleParentSymbolChange, ["cal_sw_sha"])

    # Crypto SW SHA256 Hmac
    calCryptoSwSha2HmacEnabledSymbol = calComponent.createBooleanSymbol("cal_sw_sha2_hmac", calSwShaEnabledSymbol)
    calCryptoSwSha2HmacEnabledSymbol.setLabel("Support Crypto Sw SHA256 Hmac?")
    calCryptoSwSha2HmacEnabledSymbol.setDescription("Enable support for Software SHA256 Hmac")
    calCryptoSwSha2HmacEnabledSymbol.setVisible(True)
    calCryptoSwSha2HmacEnabledSymbol.setDefaultValue(True)
    calCryptoSwSha2HmacEnabledSymbol.setDependencies(handleParentSymbolChange, ["cal_sw_sha"])

    # Crypto SW SHA Hmac Counter
    calCryptoSwSha2HmacCtrEnabledSymbol = calComponent.createBooleanSymbol("cal_sw_sha2_hmac_ctr", calSwShaEnabledSymbol)
    calCryptoSwSha2HmacCtrEnabledSymbol.setLabel("Support Crypto Sw SHA256 Hmac Counter?")
    calCryptoSwSha2HmacCtrEnabledSymbol.setDescription("Enable support for Software SHA256 Hmac Counter")
    calCryptoSwSha2HmacCtrEnabledSymbol.setVisible(True)
    calCryptoSwSha2HmacCtrEnabledSymbol.setDefaultValue(True)
    calCryptoSwSha2HmacCtrEnabledSymbol.setDependencies(handleParentSymbolChange, ["cal_sw_sha"])

    # Crypto SW PBKDF2 SHA256
    calCryptoSwPbkdf2EnabledSymbol = calComponent.createBooleanSymbol("cal_sw_pbkdf2_sha2", calSwShaEnabledSymbol)
    calCryptoSwPbkdf2EnabledSymbol.setLabel("Support Crypto Sw PBKDF2 SHA256?")
    calCryptoSwPbkdf2EnabledSymbol.setDescription("Support Crypto Sw PBKDF2 SHA256")
    calCryptoSwPbkdf2EnabledSymbol.setVisible(True)
    calCryptoSwPbkdf2EnabledSymbol.setDefaultValue(True)
    calCryptoSwPbkdf2EnabledSymbol.setDependencies(handleParentSymbolChange, ["cal_sw_sha"])

    # Crypto SW Random
    calHostSwRandEnabledSymbol = calComponent.createBooleanSymbol("cal_sw_rand", calCryptoConfig)
    calHostSwRandEnabledSymbol.setLabel("Enable SW crypto implementation to get random num")
    calHostSwRandEnabledSymbol.setDescription("Enable support for Software Random")
    calHostSwRandEnabledSymbol.setVisible(True)
    calHostSwRandEnabledSymbol.setDefaultValue(True)

    # Crypto SW Sign
    calHostSwSignEnabledSymbol = calComponent.createBooleanSymbol("cal_sw_sign", calCryptoConfig)
    calHostSwSignEnabledSymbol.setLabel("Enable SW crypto implementation to perform sign?")
    calHostSwSignEnabledSymbol.setDescription("Enable Software Implementation to perform sign")
    calHostSwSignEnabledSymbol.setVisible(True)
    calHostSwSignEnabledSymbol.setDefaultValue(True)

    # Crypto SW Verify
    calHostSwVerifyEnabledSymbol = calComponent.createBooleanSymbol("cal_sw_verify", calCryptoConfig)
    calHostSwVerifyEnabledSymbol.setLabel("Enable SW crypto implementation to perform verify?")
    calHostSwVerifyEnabledSymbol.setDescription("Enable Software Implementation to perform verify")
    calHostSwVerifyEnabledSymbol.setVisible(True)
    calHostSwVerifyEnabledSymbol.setDefaultValue(True)

    # FreeRTOS Support - The hal file gets included as a symbol here and turned on/off via connections
    calEnableRtos = calComponent.createBooleanSymbol("CAL_ENABLE_RTOS", None)
    calEnableRtos.setValue(False)
    calEnableRtos.setVisible(False)

    calLibFreeRTOSSrcFile = calComponent.createFileSymbol("CAL_FILE_SRC_FREERTOS", None)
    calLibFreeRTOSSrcFile.setSourcePath("lib/hal/hal_freertos.c")
    calLibFreeRTOSSrcFile.setOutputName("hal_freertos.c")
    calLibFreeRTOSSrcFile.setDestPath("library/cryptoauthlib/hal")
    calLibFreeRTOSSrcFile.setProjectPath("config/" + configName + "/library/cryptoauthlib/hal/")
    calLibFreeRTOSSrcFile.setType('SOURCE')
    calLibFreeRTOSSrcFile.setEnabled(False)
    calLibFreeRTOSSrcFile.setDependencies(CALSecFileUpdate, ["CAL_NON_SECURE"])

    # Replaces cryptoauthlib host functions with WolfCrypto provided ones
    calEnableWolfCrypto = calComponent.createBooleanSymbol('CAL_ENABLE_WOLFCRYPTO', None)
    calEnableWolfCrypto.setValue(False)
    calEnableWolfCrypto.setVisible(False)

    calLibWolfSSLSrcFile = calComponent.createFileSymbol("CAL_FILE_SRC_WOLFSSL_WRAPPER", None)
    calLibWolfSSLSrcFile.setSourcePath("lib/wolfssl/atca_wolfssl_interface.c")
    calLibWolfSSLSrcFile.setOutputName("atca_wolfssl_interface.c")
    calLibWolfSSLSrcFile.setDestPath("library/cryptoauthlib/wolfssl")
    calLibWolfSSLSrcFile.setProjectPath("config/" + configName + "/library/cryptoauthlib/wolfssl/")
    calLibWolfSSLSrcFile.setType('SOURCE')
    calLibWolfSSLSrcFile.setEnabled(False)
    calLibWolfSSLSrcFile.setDependencies(CALSecFileUpdate, ["CAL_NON_SECURE"])

    # Add HAL Drivers
    calLibI2cHalSrcFile = calComponent.createFileSymbol("CAL_FILE_SRC_HAL_I2C", None)
    calLibI2cHalSrcFile.setSourcePath("lib/hal/hal_i2c_harmony.c")
    calLibI2cHalSrcFile.setOutputName("hal_i2c_harmony.c")
    calLibI2cHalSrcFile.setDestPath("library/cryptoauthlib/hal")
    calLibI2cHalSrcFile.setProjectPath("config/" + configName + "/library/cryptoauthlib/hal/")
    calLibI2cHalSrcFile.setType('SOURCE')
    calLibI2cHalSrcFile.setEnabled(False)
    calLibI2cHalSrcFile.setDependencies(CALSecFileUpdate, ["CAL_NON_SECURE"])

    calLibUartHalSrcFile = calComponent.createFileSymbol("CAL_FILE_SRC_HAL_UART", None)
    calLibUartHalSrcFile.setSourcePath("lib/hal/hal_uart_harmony.c")
    calLibUartHalSrcFile.setOutputName("hal_uart_harmony.c")
    calLibUartHalSrcFile.setDestPath("library/cryptoauthlib/hal")
    calLibUartHalSrcFile.setProjectPath("config/" + configName + "/library/cryptoauthlib/hal/")
    calLibUartHalSrcFile.setType('SOURCE')
    calLibUartHalSrcFile.setEnabled(False)
    calLibUartHalSrcFile.setDependencies(CALSecFileUpdate, ["CAL_NON_SECURE"])

    calLibSwiUartHalSrcFile = calComponent.createFileSymbol("CAL_FILE_SRC_HAL_SWI_UART", None)
    calLibSwiUartHalSrcFile.setSourcePath("lib/hal/hal_swi_uart.c")
    calLibSwiUartHalSrcFile.setOutputName("hal_swi_uart.c")
    calLibSwiUartHalSrcFile.setDestPath("library/cryptoauthlib/hal")
    calLibSwiUartHalSrcFile.setProjectPath("config/" + configName + "/library/cryptoauthlib/hal/")
    calLibSwiUartHalSrcFile.setType('SOURCE')
    calLibSwiUartHalSrcFile.setEnabled(False)
    calLibSwiUartHalSrcFile.setDependencies(CALSecFileUpdate, ["CAL_NON_SECURE"])

    calLibSwiBBHalSrcFile = calComponent.createFileSymbol("CAL_FILE_SRC_HAL_SWI_BB", None)
    calLibSwiBBHalSrcFile.setSourcePath("lib/hal/hal_swi_gpio.c")
    calLibSwiBBHalSrcFile.setOutputName("hal_swi_gpio.c")
    calLibSwiBBHalSrcFile.setDestPath("library/cryptoauthlib/hal")
    calLibSwiBBHalSrcFile.setProjectPath("config/" + configName + "/library/cryptoauthlib/hal/")
    calLibSwiBBHalSrcFile.setType('SOURCE')
    calLibSwiBBHalSrcFile.setEnabled(False)
    calLibSwiBBHalSrcFile.setDependencies(CALSecFileUpdate, ["CAL_NON_SECURE"])

    calLibSwiBBHalHdrFile = calComponent.createFileSymbol("CAL_FILE_SRC_HAL_SWI_BB_HEADER", None)
    calLibSwiBBHalHdrFile.setSourcePath("lib/hal/hal_swi_gpio.h")
    calLibSwiBBHalHdrFile.setOutputName("hal_swi_gpio.h")
    calLibSwiBBHalHdrFile.setDestPath("library/cryptoauthlib/hal")
    calLibSwiBBHalHdrFile.setProjectPath("config/" + configName + "/library/cryptoauthlib/hal/")
    calLibSwiBBHalHdrFile.setType('HEADER')
    calLibSwiBBHalHdrFile.setEnabled(False)
    calLibSwiBBHalHdrFile.setDependencies(CALSecFileUpdate, ["CAL_NON_SECURE"])

    calLibSpiHalSrcFile = calComponent.createFileSymbol("CAL_FILE_SRC_HAL_SPI", None)
    calLibSpiHalSrcFile.setSourcePath("lib/hal/hal_spi_harmony.c")
    calLibSpiHalSrcFile.setOutputName("hal_spi_harmony.c")
    calLibSpiHalSrcFile.setDestPath("library/cryptoauthlib/hal")
    calLibSpiHalSrcFile.setProjectPath("config/" + configName + "/library/cryptoauthlib/hal/")
    calLibSpiHalSrcFile.setType('SOURCE')
    calLibSpiHalSrcFile.setEnabled(False)
    calLibSpiHalSrcFile.setDependencies(CALSecFileUpdate, ["CAL_NON_SECURE"])

    # List of HALs that will be included based on device connections
    calHalList = calComponent.createListSymbol('CAL_HAL_LIST', None)
    calHalList = calComponent.createListEntrySymbol('CAL_HAL_LIST_ENTRIES', None)
    calHalList.setTarget('cryptoauthlib.CAL_HAL_LIST')

    calPlibList = calComponent.createListSymbol('CAL_PLIB_LIST', None)
    calPlibList = calComponent.createListEntrySymbol('CAL_PLIB_LIST_ENTRIES', None)
    calPlibList.setTarget('cryptoauthlib.CAL_PLIB_LIST')

    # List of devices that will be supported by the library based on those selected in the graph
    calDeviceList = calComponent.createListSymbol('CAL_DEVICE_LIST', None)
    calDeviceList = calComponent.createListEntrySymbol('CAL_DEVICE_LIST_ENTRIES', None)
    calDeviceList.setTarget('cryptoauthlib.CAL_DEVICE_LIST')

    # List of specific device instances
    calDevCfgList = calComponent.createListSymbol('CAL_DEV_CFG_LIST', None)
    calDevCfgList = calComponent.createListEntrySymbol('CAL_DEV_CFG_LIST_ENTRIES', None)
    calDevCfgList.setTarget('cryptoauthlib.CAL_DEV_CFG_LIST')

    # Add device specific options
    calTaEnableAesAuth = calComponent.createBooleanSymbol('CAL_ENABLE_TA10x_AES_AUTH', None)
    calTaEnableAesAuth.setValue(False)
    calTaEnableAesAuth.setVisible(True)

    calTaEnableFce = calComponent.createBooleanSymbol('CAL_ENABLE_TA10x_FCE', None)
    calTaEnableFce.setValue(False)
    calTaEnableFce.setVisible(True)

    ################# Templated files to be included #######################

    # cryptoauthlib configuration structures that are create per device instance
    calLibCoreM0PlusSrcFile = calComponent.createFileSymbol("CAL_HARMONY_INIT_DATA", None)
    calLibCoreM0PlusSrcFile.setSourcePath("harmony/templates/hal_harmony_init.c.ftl")
    calLibCoreM0PlusSrcFile.setOutputName("hal_harmony_init.c")
    calLibCoreM0PlusSrcFile.setDestPath("library/cryptoauthlib/hal")
    calLibCoreM0PlusSrcFile.setProjectPath("config/" + configName + "/library/cryptoauthlib/hal/")
    calLibCoreM0PlusSrcFile.setType("SOURCE")
    calLibCoreM0PlusSrcFile.setOverwrite(True)
    calLibCoreM0PlusSrcFile.setMarkup(True)
    calLibCoreM0PlusSrcFile.setDependencies(CALSecFileUpdate, ["CAL_NON_SECURE"])

    # cryptoauthlib configuration structures that are create per device instance
    calLibCoreM0PlusSrcFile = calComponent.createFileSymbol("CAL_HAL_HARMONY_GPIO", None)
    calLibCoreM0PlusSrcFile.setSourcePath("harmony/templates/hal_gpio_harmony.c.ftl")
    calLibCoreM0PlusSrcFile.setOutputName("hal_gpio_harmony.c")
    calLibCoreM0PlusSrcFile.setDestPath("library/cryptoauthlib/hal")
    calLibCoreM0PlusSrcFile.setProjectPath("config/" + configName + "/library/cryptoauthlib/hal/")
    calLibCoreM0PlusSrcFile.setType("SOURCE")
    calLibCoreM0PlusSrcFile.setOverwrite(True)
    calLibCoreM0PlusSrcFile.setMarkup(True)
    calLibCoreM0PlusSrcFile.setDependencies(CALSecFileUpdate, ["CAL_NON_SECURE"])

    # Configuration header file
    calLibConfigFile = calComponent.createFileSymbol("CAL_LIB_CONFIG_DATA", None)
    calLibConfigFile.setSourcePath("harmony/templates/atca_config.h.ftl")
    calLibConfigFile.setOutputName("atca_config.h")
    calLibConfigFile.setDestPath("library/cryptoauthlib")
    calLibConfigFile.setProjectPath("config/" + configName + "/library/cryptoauthlib/")
    calLibConfigFile.setType("HEADER")
    calLibConfigFile.setOverwrite(True)
    calLibConfigFile.setMarkup(True)
    calLibConfigFile.setDependencies(CALSecFileUpdate, ["CAL_NON_SECURE"])

    # Conditionally add talib configuration header
    talibConfigFile = calComponent.createFileSymbol("TALIB_CONFIG_DATA", None)
    talibConfigFile.setSourcePath("harmony/templates/talib_config.h.ftl")
    talibConfigFile.setOutputName("talib_config.h")
    talibConfigFile.setDestPath("library/cryptoauthlib")
    talibConfigFile.setProjectPath("config/" + configName + "/library/cryptoauthlib/")
    talibConfigFile.setType("HEADER")
    talibConfigFile.setOverwrite(True)
    talibConfigFile.setMarkup(True)
    talibConfigFile.setDependencies(CALSecFileUpdate, ["CAL_NON_SECURE"])
    talibConfigFile.setEnabled(False)

    # This selects and configures the proper processor specific delay implementation as one
    # does not exist as driver source in harmony
    calLibDelaySrcFile = calComponent.createFileSymbol('CAL_LIB_SRC_DELAY', None)
    if 'cortex_m'in architecture :
        calLibDelaySrcFile.setSourcePath("harmony/templates/hal_cortex_m_delay.c.ftl")
        calLibDelaySrcFile.setOutputName("hal_cortex_m_delay.c")
    else:
        calLibDelaySrcFile.setSourcePath("harmony/templates/hal_pic32_delay.c.ftl")
        calLibDelaySrcFile.setOutputName("hal_pic32_delay.c")

    calLibDelaySrcFile.setDestPath("library/cryptoauthlib/hal")
    calLibDelaySrcFile.setProjectPath("config/" + configName + "/library/cryptoauthlib/hal/")
    calLibDelaySrcFile.setType("SOURCE")
    calLibDelaySrcFile.setOverwrite(True)
    calLibDelaySrcFile.setMarkup(True)
    calLibDelaySrcFile.setDependencies(CALSecFileUpdate, ["CAL_NON_SECURE"])

    if Variables.get("__TRUSTZONE_ENABLED") != None and Variables.get("__TRUSTZONE_ENABLED") == "true":
        calSecurity = calComponent.createKeyValueSetSymbol("CAL_NON_SECURE", None)
        calSecurity.setLabel("Security mode")
        calSecurity.addKey("NON_SECURE", "0", "False")
        calSecurity.addKey("SECURE", "1", "True")
        calSecurity.setOutputMode("Key")
        calSecurity.setDisplayMode("Key")
        calSecurity.setVisible(True)
        calSecurity.setDefaultValue(0)

def handleParentSymbolChange(symbol, event):
    symbol.setVisible(event["value"])
