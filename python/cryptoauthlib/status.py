"""
Status codes and status to exception conversions.
"""
from enum import Enum

class Status(Enum):
    """
    Status.ATCA_SUCCESS]  Success
    Status.ATCA_CONFIG_ZONE_LOCKED  Config Zone Locked
    Status.ATCA_DATA_ZONE_LOCKED  Configuration Enabled
    Status.ATCA_WAKE_FAILED response status byte indicates CheckMac failure (status byte = 0x01)
    Status.ATCA_CHECKMAC_VERIFY_FAILED response status byte indicates CheckMac failure (status byte = 0x01)
    Status.ATCA_PARSE_ERROR response status byte indicates parsing error (status byte = 0x03)
    Status.ATCA_STATUS_CRC response status byte indicates CRC error (status byte = 0xFF)
    Status.ATCA_STATUS_UNKNOWN response status byte is unknown
    Status.ATCA_STATUS_ECC response status byte is ECC fault (status byte = 0x05)
    Status.ATCA_FUNC_FAIL Function could not execute due to incorrect condition / state.
    Status.ATCA_GEN_FAIL unspecified error
    Status.ATCA_BAD_PARAM bad argument (out of range, null pointer, etc.)
    Status.ATCA_INVALID_ID invalid device id, id not set
    Status.ATCA_INVALID_SIZE Count value is out of range or greater than buffer size.
    Status.ATCA_BAD_CRC incorrect CRC received
    Status.ATCA_RX_FAIL Timed out while waiting for response. Number of bytes received is > 0.
    Status.ATCA_RX_NO_RESPONSE Not an error while the Command layer is polling for a command response.
    Status.ATCA_RESYNC_WITH_WAKEUP Re-synchronization succeeded, but only after generating a Wake-up
    Status.ATCA_PARITY_ERROR for protocols needing parity
    Status.ATCA_TX_TIMEOUT = for Atmel PHY protocol, timeout on transmission waiting for master
    Status.ATCA_RX_TIMEOUT = for Atmel PHY protocol, timeout on receipt waiting for master
    Status.ATCA_COMM_FAIL = Communication with device failed. Same as in hardware dependent modules.
    Status.ATCA_TIMEOUT = Timed out while waiting for response. Number of bytes received is 0.
    Status.ATCA_BAD_OPCODE = opcode is not supported by the device
    Status.ATCA_WAKE_SUCCESS = received proper wake token
    Status.ATCA_EXECUTION_ERROR = chip was in a state where it could not execute the command, response status byte indicates command execution error (status byte = 0x0F)
    Status.ATCA_UNIMPLEMENTED = Function or some element of it hasn't been implemented yet
    Status.ATCA_ASSERT_FAILURE = Code failed run-time consistency check
    Status.ATCA_TX_FAIL = Failed to write
    Status.ATCA_NOT_LOCKED = required zone was not locked
    Status.ATCA_NO_DEVICES = For protocols that support device discovery (kit protocol), no devices were found
    Status.ATCA_NOT_INIT = Indication that library or context was not initialized prior to an API call
    """
    ATCA_SUCCESS = 0x00
    ATCA_CONFIG_ZONE_LOCKED = 0x01
    ATCA_DATA_ZONE_LOCKED = 0x02
    ATCA_WAKE_FAILED = 0xD0
    ATCA_CHECKMAC_VERIFY_FAILED = 0xD1
    ATCA_PARSE_ERROR = 0xD2
    ATCA_STATUS_CRC = 0xD4
    ATCA_STATUS_UNKNOWN = 0xD5
    ATCA_STATUS_ECC = 0xD6
    ATCA_FUNC_FAIL = 0xE0
    ATCA_GEN_FAIL = 0xE1
    ATCA_BAD_PARAM = 0xE2
    ATCA_INVALID_ID = 0xE3
    ATCA_INVALID_SIZE = 0xE4
    ATCA_BAD_CRC = 0xE5
    ATCA_RX_FAIL = 0xE6
    ATCA_RX_NO_RESPONSE = 0xE7
    ATCA_RESYNC_WITH_WAKEUP = 0xE8
    ATCA_PARITY_ERROR = 0xE9
    ATCA_TX_TIMEOUT = 0xEA
    ATCA_RX_TIMEOUT = 0xEB
    ATCA_COMM_FAIL = 0xF0
    ATCA_TIMEOUT = 0xF1
    ATCA_BAD_OPCODE = 0xF2
    ATCA_WAKE_SUCCESS = 0xF3
    ATCA_EXECUTION_ERROR = 0xF4
    ATCA_UNIMPLEMENTED = 0xF5
    ATCA_ASSERT_FAILURE = 0xF6
    ATCA_TX_FAIL = 0xF7
    ATCA_NOT_LOCKED = 0xF8
    ATCA_NO_DEVICES = 0xF9
    ATCA_NOT_INIT = 0xFA

__all__ = ['Status']
