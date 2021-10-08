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
        if 'TA100' in targetComponentID:
            _ta_dev_cnt += 1
            updateFileEnable(srcComponent, _TA_PATHS, True)
            if check_if_file_exists(srcComponent, 'talib_fce'):
                calTaEnableFce = srcComponent.getSymbolByID('CAL_ENABLE_TA100_FCE')
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

        calTaEnableAesAuth = srcComponent.getSymbolByID('CAL_ENABLE_TA100_AES_AUTH')
        calTaEnableAesAuth.setValue(True)


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
                calTaEnableFce = srcComponent.getSymbolByID('CAL_ENABLE_TA100_FCE')
                calTaEnableFce.setValue(False)
                calTaEnableAesAuth = srcComponent.getSymbolByID('CAL_ENABLE_TA100_AES_AUTH')
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

        calTaEnableAesAuth = srcComponent.getSymbolByID('CAL_ENABLE_TA100_AES_AUTH')
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
    calTaEnableAesAuth = calComponent.createBooleanSymbol('CAL_ENABLE_TA100_AES_AUTH', None)
    calTaEnableAesAuth.setValue(False)
    calTaEnableAesAuth.setVisible(True)

    calTaEnableFce = calComponent.createBooleanSymbol('CAL_ENABLE_TA100_FCE', None)
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
