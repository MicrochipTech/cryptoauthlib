"""
Status codes and status to exception conversions.
"""
# (c) 2015-2018 Microchip Technology Inc. and its subsidiaries.
#
# Subject to your compliance with these terms, you may use Microchip software
# and any derivatives exclusively with Microchip products. It is your
# responsibility to comply with third party license terms applicable to your
# use of third party software (including open source software) that may
# accompany Microchip software.
#
# THIS SOFTWARE IS SUPPLIED BY MICROCHIP "AS IS". NO WARRANTIES, WHETHER
# EXPRESS, IMPLIED OR STATUTORY, APPLY TO THIS SOFTWARE, INCLUDING ANY IMPLIED
# WARRANTIES OF NON-INFRINGEMENT, MERCHANTABILITY, AND FITNESS FOR A
# PARTICULAR PURPOSE. IN NO EVENT WILL MICROCHIP BE LIABLE FOR ANY INDIRECT,
# SPECIAL, PUNITIVE, INCIDENTAL OR CONSEQUENTIAL LOSS, DAMAGE, COST OR EXPENSE
# OF ANY KIND WHATSOEVER RELATED TO THE SOFTWARE, HOWEVER CAUSED, EVEN IF
# MICROCHIP HAS BEEN ADVISED OF THE POSSIBILITY OR THE DAMAGES ARE
# FORESEEABLE. TO THE FULLEST EXTENT ALLOWED BY LAW, MICROCHIP'S TOTAL
# LIABILITY ON ALL CLAIMS IN ANY WAY RELATED TO THIS SOFTWARE WILL NOT EXCEED
# THE AMOUNT OF FEES, IF ANY, THAT YOU HAVE PAID DIRECTLY TO MICROCHIP FOR
# THIS SOFTWARE.

# Because all modules are setup to be import * safe the following is an exception to the python coding standard
# pylint: disable-msg=wildcard-import, unused-wildcard-import

from .atcaenum import AtcaEnum
from .exceptions import *

class Status(AtcaEnum):
    """
    Status codes returned from cryptoauthlib commands and their meanings. See atca_status.h
    """
    # Success
    ATCA_SUCCESS = 0x00
    # Config Zone Locked
    ATCA_CONFIG_ZONE_LOCKED = 0x01
    # Configuration Enabled
    ATCA_DATA_ZONE_LOCKED = 0x02
    # Response status byte indicates CheckMac failure (status byte = 0x01)
    ATCA_WAKE_FAILED = 0xD0
    # Response status byte indicates CheckMac failure (status byte = 0x01)
    ATCA_CHECKMAC_VERIFY_FAILED = 0xD1
    # Response status byte indicates parsing error (status byte = 0x03)
    ATCA_PARSE_ERROR = 0xD2
    # response status byte indicates CRC error (status byte = 0xFF)
    ATCA_STATUS_CRC = 0xD4
    # response status byte is unknown
    ATCA_STATUS_UNKNOWN = 0xD5
    # response status byte is ECC fault (status byte = 0x05)
    ATCA_STATUS_ECC = 0xD6
    # Function could not execute due to incorrect condition / state.
    ATCA_FUNC_FAIL = 0xE0
    # unspecified error
    ATCA_GEN_FAIL = 0xE1
    # bad argument (out of range, null pointer, etc.)
    ATCA_BAD_PARAM = 0xE2
    # invalid device id, id not set
    ATCA_INVALID_ID = 0xE3
    # Count value is out of range or greater than buffer size.
    ATCA_INVALID_SIZE = 0xE4
    # incorrect CRC received
    ATCA_BAD_CRC = 0xE5
    # Timed out while waiting for response. Number of bytes received is > 0.
    ATCA_RX_FAIL = 0xE6
    # Not an error while the Command layer is polling for a command response.
    ATCA_RX_NO_RESPONSE = 0xE7
    # Re-synchronization succeeded, but only after generating a Wake-up
    ATCA_RESYNC_WITH_WAKEUP = 0xE8
    # For protocols needing parity
    ATCA_PARITY_ERROR = 0xE9
    # For Microchip Kit PHY protocol, timeout on transmission waiting for master
    ATCA_TX_TIMEOUT = 0xEA
    # For Microchip Kit PHY protocol, timeout on receipt waiting for master
    ATCA_RX_TIMEOUT = 0xEB
    # Communication with device failed. Same as in hardware dependent modules.
    ATCA_COMM_FAIL = 0xF0
    # Timed out while waiting for response. Number of bytes received is 0.
    ATCA_TIMEOUT = 0xF1
    # opcode is not supported by the device
    ATCA_BAD_OPCODE = 0xF2
    # Received proper wake token
    ATCA_WAKE_SUCCESS = 0xF3
    # Chip was in a state where it could not execute the command, response status byte indicates command
    # execution error (status byte = 0x0F)
    ATCA_EXECUTION_ERROR = 0xF4
    # Function or some element of it hasn't been implemented yet
    ATCA_UNIMPLEMENTED = 0xF5
    # Code failed run-time consistency check
    ATCA_ASSERT_FAILURE = 0xF6
    # Failed to write
    ATCA_TX_FAIL = 0xF7
    # required zone was not locked
    ATCA_NOT_LOCKED = 0xF8
    # For protocols that support device discovery (kit protocol), no devices were found
    ATCA_NO_DEVICES = 0xF9
    # Random number generator health test error
    ATCA_HEALTH_TEST_ERROR = 0xFA
    # Couldn't allocate required memory
    ATCA_ALLOC_FAILURE = 0xFB
    # The library has not been initialized so the command could not be executed
    ATCA_NOT_INITIALIZED = 0xFC


STATUS_EXCEPTION_MAP = {
    int(Status.ATCA_SUCCESS): None,
    int(Status.ATCA_CONFIG_ZONE_LOCKED): ConfigZoneLockedError,
    int(Status.ATCA_DATA_ZONE_LOCKED): DataZoneLockedError,
    int(Status.ATCA_WAKE_FAILED): WakeFailedError,
    int(Status.ATCA_CHECKMAC_VERIFY_FAILED): CheckmacVerifyFailedError,
    int(Status.ATCA_PARSE_ERROR): ParseError,
    int(Status.ATCA_STATUS_CRC): CrcError,
    int(Status.ATCA_STATUS_UNKNOWN): StatusUnknownError,
    int(Status.ATCA_STATUS_ECC): EccFaultError,
    int(Status.ATCA_FUNC_FAIL): FunctionError,
    int(Status.ATCA_GEN_FAIL): GenericError,
    int(Status.ATCA_BAD_PARAM): BadArgumentError,
    int(Status.ATCA_INVALID_ID): InvalidIdentifierError,
    int(Status.ATCA_INVALID_SIZE): InvalidSizeError,
    int(Status.ATCA_BAD_CRC): BadCrcError,
    int(Status.ATCA_RX_FAIL): ReceiveError,
    int(Status.ATCA_RX_NO_RESPONSE): NoResponseError,
    int(Status.ATCA_RESYNC_WITH_WAKEUP): ResyncWithWakeupError,
    int(Status.ATCA_PARITY_ERROR): ParityError,
    int(Status.ATCA_TX_TIMEOUT): TransmissionTimeoutError,
    int(Status.ATCA_RX_TIMEOUT): ReceiveTimeoutError,
    int(Status.ATCA_COMM_FAIL): CommunicationError,
    int(Status.ATCA_TIMEOUT): TimeOutError,
    int(Status.ATCA_BAD_OPCODE): BadOpcodeError,
    int(Status.ATCA_WAKE_SUCCESS): None,
    int(Status.ATCA_EXECUTION_ERROR): ExecutionError,
    int(Status.ATCA_UNIMPLEMENTED): UnimplementedError,
    int(Status.ATCA_ASSERT_FAILURE): AssertionFailure,
    int(Status.ATCA_TX_FAIL): TransmissionError,
    int(Status.ATCA_NOT_LOCKED): ZoneNotLockedError,
    int(Status.ATCA_NO_DEVICES): NoDevicesFoundError,
    int(Status.ATCA_HEALTH_TEST_ERROR): HealthTestError,
    int(Status.ATCA_ALLOC_FAILURE): LibraryMemoryError,
    int(Status.ATCA_NOT_INITIALIZED): LibraryNotInitialized
}


def check_status(status, *args, **kwargs):
    """
    Look up the status return code from an API call and raise the exception that matches
    """
    ex = STATUS_EXCEPTION_MAP.get(status, None)
    if ex is not None:
        raise ex(*args, **kwargs)

__all__ = ['Status']
