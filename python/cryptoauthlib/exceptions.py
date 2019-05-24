"""
Cryptoauthlib Exceptions
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


class CryptoError(Exception):
    """Standard CryptoAuthLib Exceptions"""


class LibraryLoadError(CryptoError):
    """CryptpAuthLib failed to Load"""


class ConfigZoneLockedError(CryptoError):
    """Config Zone Locked"""


class DataZoneLockedError(CryptoError):
    """Configuration Enabled"""


class WakeFailedError(CryptoError):
    """Device Wake failed"""


class CheckmacVerifyFailedError(CryptoError):
    """response status byte indicates CheckMac failure (status byte = 0x01)"""


class ParseError(CryptoError):
    """response status byte indicates parsing error (status byte = 0x03)"""


class CrcError(CryptoError):
    """response status byte indicates CRC error (status byte = 0xFF)"""


class StatusUnknownError(CryptoError):
    """Response status byte is unknown"""


class EccFaultError(CryptoError):
    """response status byte is ECC fault (status byte = 0x05)"""


class FunctionError(CryptoError):
    """Function could not execute due to incorrect condition / state."""


class GenericError(CryptoError):
    """unspecified error"""


class BadArgumentError(CryptoError):
    """bad argument (out of range, null pointer, etc.)"""


class InvalidIdentifierError(CryptoError):
    """invalid device id, id not set"""


class InvalidSizeError(CryptoError):
    """Count value is out of range or greater than buffer size."""


class BadCrcError(CryptoError):
    """incorrect CRC received"""


class ReceiveError(CryptoError):
    """Timed out while waiting for response. Number of bytes received is > 0."""


class NoResponseError(CryptoError):
    """error while the Command layer is polling for a command response."""


class ResyncWithWakeupError(CryptoError):
    """Re-synchronization succeeded, but only after generating a Wake-up"""


class ParityError(CryptoError):
    """for protocols needing parity"""


class TransmissionTimeoutError(CryptoError):
    """for Microchip PHY protocol, timeout on transmission waiting for master"""


class ReceiveTimeoutError(CryptoError):
    """for Microchip PHY protocol, timeout on receipt waiting for master"""


class CommunicationError(CryptoError):
    """Communication with device failed. Same as in hardware dependent modules."""


class TimeOutError(CryptoError):
    """Timed out while waiting for response. Number of bytes received is 0."""


class BadOpcodeError(CryptoError):
    """Opcode is not supported by the device"""


class ExecutionError(CryptoError):
    """chip was in a state where it could not execute the command, response
    status byte indicates command execution error (status byte = 0x0F)"""


class UnimplementedError(CryptoError):
    """Function or some element of it hasn't been implemented yet"""


class AssertionFailure(CryptoError):
    """Code failed run-time consistency check"""


class TransmissionError(CryptoError):
    """Failed to write"""


class ZoneNotLockedError(CryptoError):
    """required zone was not locked"""


class NoDevicesFoundError(CryptoError):
    """For protocols that support device discovery (kit protocol), no devices were found"""


class HealthTestError(CryptoError):
    """Random number generator health test error"""


class LibraryMemoryError(CryptoError):
    """CryptoAuthLib was unable to allocate memory"""


class LibraryNotInitialized(CryptoError):
    """Indication that library or context was not initialized prior to an API call"""
