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

_HAL_FILES = ["atca_hal.c", "atca_hal.h", "atca_start_config.h", "atca_start_iface.h"]
_CORE_PATHS = ['crypto/**/*', 'crypto/*', 'jwt/*', '*']
_CA_PATHS = ['atcacert/*', 'calib/*', 'host/*']
_TA_PATHS = ['talib/*']


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
    
    symbol = Database.getComponentByID('cryptoauthlib').getSymbolByID('CAL_FILE_SRC_HAL_' + id.upper())
    symbol.setEnabled(cnt > 0)


def updatePlibTracker(id, inc):
    global calPlibTracker
    cnt = calPlibTracker.pop(id, 0)
    if inc:
        cnt += 1
        calPlibTracker[id] = cnt
    elif cnt > 0:
        cnt -= 1

    updateHalTracker(id.split('_')[1], inc)

    calPlibList = Database.getComponentByID('cryptoauthlib').getSymbolByID('CAL_PLIB_LIST_ENTRIES')

    if cnt == 0:
        del_value_from_list(calPlibList, id)
    else:
        add_value_to_list(calPlibList, id)


def handleMessage(messageID, args):
    global calPlibTracker

    if (messageID == 'UPDATE_PLIB_LIST'):
        if isinstance(args, dict):
            updatePlibTracker(**args)

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
        if 'TA100' in targetComponentID:
            _ta_dev_cnt += 1
            updateFileEnable(srcComponent, _TA_PATHS, True)
        else:
            _ca_dev_cnt += 1
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
        print('connected lib_wolfcrypt')


def onAttachmentDisconnected(source, target):
    global _ca_dev_cnt
    global _ta_dev_cnt
    srcComponent = source["component"]
    srcConnectionID = source["id"]

    targetComponentID = target["component"].getID().upper()

    if srcConnectionID == 'CAL_LIB_CAP' and '_' in targetComponentID:
        calDeviceList = srcComponent.getSymbolByID('CAL_DEVICE_LIST_ENTRIES')
        del_value_from_list(calDeviceList, targetComponentID.split('_')[0])
        if 'TA100' in targetComponentID:
            _ta_dev_cnt -= 1
            if 0 == _ta_dev_cnt:
                updateFileEnable(srcComponent, _TA_PATHS, False)
        else:
            _ca_dev_cnt -= 1
            if 0 == _ca_dev_cnt:
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
        
        print('disconnected lib_wolfcrypt')


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

    # Add HAL Drivers
    calLibI2cHalSrcFile = calComponent.createFileSymbol("CAL_FILE_SRC_HAL_I2C", None)
    calLibI2cHalSrcFile.setSourcePath("lib/hal/hal_i2c_harmony.c")
    calLibI2cHalSrcFile.setOutputName("hal_i2c_harmony.c")
    calLibI2cHalSrcFile.setDestPath("library/cryptoauthlib/hal")
    calLibI2cHalSrcFile.setProjectPath("config/" + configName + "/library/cryptoauthlib/hal/")
    calLibI2cHalSrcFile.setType('SOURCE')
    calLibI2cHalSrcFile.setEnabled(False)
    
    calLibSpiHalSrcFile = calComponent.createFileSymbol("CAL_FILE_SRC_HAL_SPI", None)
    calLibSpiHalSrcFile.setSourcePath("lib/hal/hal_spi_harmony.c")
    calLibSpiHalSrcFile.setOutputName("hal_spi_harmony.c")
    calLibSpiHalSrcFile.setDestPath("library/cryptoauthlib/hal")
    calLibSpiHalSrcFile.setProjectPath("config/" + configName + "/library/cryptoauthlib/hal/")
    calLibSpiHalSrcFile.setType('SOURCE')
    calLibSpiHalSrcFile.setEnabled(False)

    # List of HALs that will be included based on device connections
    calPlibList = calComponent.createListSymbol('CAL_PLIB_LIST', None)
    calPlibList = calComponent.createListEntrySymbol('CAL_PLIB_LIST_ENTRIES', None)
    calPlibList.setTarget('cryptoauthlib.CAL_PLIB_LIST')

    # List of devices that will be supported by the library based on those selected in the graph
    calDeviceList = calComponent.createListSymbol('CAL_DEVICE_LIST', None)
    calDeviceList = calComponent.createListEntrySymbol('CAL_DEVICE_LIST_ENTRIES', None)
    calDeviceList.setTarget('cryptoauthlib.CAL_DEVICE_LIST')


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

    # Configuration header file 
    calLibConfigFile = calComponent.createFileSymbol("CAL_LIB_CONFIG_DATA", None)
    calLibConfigFile.setSourcePath("harmony/templates/atca_config.h.ftl")
    calLibConfigFile.setOutputName("atca_config.h")
    calLibConfigFile.setDestPath("library/cryptoauthlib")
    calLibConfigFile.setProjectPath("config/" + configName + "/library/cryptoauthlib/")
    calLibConfigFile.setType("HEADER")
    calLibConfigFile.setOverwrite(True)
    calLibConfigFile.setMarkup(True)


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



