"""
SHA206 API: classes and functions for interacting with SHA206A device
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

from ctypes import c_uint8, byref, create_string_buffer
from .status import Status
from .library import get_cryptoauthlib, AtcaReference

# Because this module directly mirrors the C api the following is an exception to the python coding standard
# pylint: disable-msg=too-many-arguments

def sha206a_generate_derive_key(parent_key, derived_key, param1, param2):
    """
    Generates the derived key based on the parent key and other parameters provided

    Args:
        parent_key      input data contains device's parent key
                        (Expects bytearray of size 32)

        derived key     output derived key is returned here
                        (Expects bytearray of size 32)

        param1          input data to be used in derive key calculation (int)

        param2          input data to be used in derive key calculation (int)

    Returns:
        Status Code
    """
    c_derived_key = create_string_buffer(32)
    if not isinstance(derived_key, bytearray):
        status = Status.ATCA_BAD_PARAM
    else:
        status = get_cryptoauthlib().sha206a_generate_derive_key(bytes(parent_key), byref(c_derived_key),
                                                                 param1, param2)
        derived_key[0:] = bytes(c_derived_key.raw)
    return status

def sha206a_generate_challenge_response_pair(key, challenge, response):
    """
    Generates the response based on Key and Challenge provided

    Args:
        key             input data contains device's key
                        (Expects bytearray of size 32)

        challenge       input data to be used in challenge response calculation
                        (Expects bytearray of size 32)

        response        output response is returned here
                        (Expects bytearray of size 32)

    Returns:
        Status Code
    """
    c_response = create_string_buffer(32)
    if not isinstance(response, bytearray):
        status = Status.ATCA_BAD_PARAM
    else:
        status = get_cryptoauthlib().sha206a_generate_challenge_response_pair(bytes(key), bytes(challenge),
                                                                              byref(c_response))
        response[0:] = bytes(c_response.raw)
    return status

def sha206a_authenticate(challenge, expected_response, is_verified):
    """
    verifies the challenge and provided response using key in device

    Args:
        challenge           Challenge to be used in the response calculations
                            (Expects bytearray of size 32)

        expected_response   Expected response from the device
                            (Expects bytearray of size 32)

        is_authenticated    result of expected of response and calcualted response
                            (AtcaReference expected)

    Returns:
        Status Code
    """
    if not isinstance(is_verified, AtcaReference):
        status = Status.ATCA_BAD_PARAM
    else:
        c_is_verified = c_uint8(is_verified.value)
        status = get_cryptoauthlib().sha206a_authenticate(bytes(challenge), bytes(expected_response),
                                                          byref(c_is_verified))
        is_verified.value = c_is_verified.value
    return status

def sha206a_write_data_store(slot, data, block, offset, length, lock_after_write):
    """
    Update the data store slot with user data and lock it if necessary

    Args:
        slot               Slot number to be written with data (int)

        data               Pointer that holds the data
                           (Expected bytearray of size 32)

        block              32-byte block to write (int)

        offset             4-byte word within the specified block to write to. If
                           performing a 32-byte write, this should be 0. (int)

        length             data length (int)

        lock_after_write   set 1 to lock slot after write, otherwise 0
                           (Expected bool/int)

    Returns:
        Status Code
    """
    status = get_cryptoauthlib().sha206a_write_data_store(slot, bytes(data), block, offset, length,
                                                          lock_after_write)
    return status

def sha206a_read_data_store(slot, data, offset, length):
    """
    Read the data stored in Data store

    Args:
        slot               Slot number to read from (int)

        data               Pointer that holds the data
                           (Expected bytearray of size 32)

        offset             Byte offset within the zone to read from. (int)

        length             data length (int)

    Returns:
        Status Code
    """
    if not isinstance(data, bytearray):
        status = Status.ATCA_BAD_PARAM
    else:
        c_read_data = create_string_buffer(32)
        status = get_cryptoauthlib().sha206a_read_data_store(slot, byref(c_read_data), offset, length)
        data[0:] = bytes(c_read_data.raw)
    return status

def sha206a_get_data_store_lock_status(slot, is_locked):
    """
    Returns the lock status of the given data store

    Args:
        slot               Slot number of the data store (int)

        is_locked          lock status of the data store slot
                           (Expected AtcaReference)

    Returns:
        Status Code
    """
    if not isinstance(is_locked, AtcaReference):
        status = Status.ATCA_BAD_PARAM
    else:
        c_is_locked = c_uint8(is_locked.value)
        status = get_cryptoauthlib().sha206a_get_data_store_lock_status(slot, byref(c_is_locked))
        is_locked.value = c_is_locked.value
    return status

def sha206a_get_dk_update_count(dk_update_count):
    """
    Read Derived Key slot update count. It will be wraps around 256

    Args:
        dk_update_count       returns number of times the slot has been
                              updated with derived key (Expected AtcaReference)

    Returns:
        Status Code
    """
    if not isinstance(dk_update_count, AtcaReference):
        status = Status.ATCA_BAD_PARAM
    else:
        c_dk_update_count = c_uint8(dk_update_count.value)
        status = get_cryptoauthlib().sha206a_get_dk_update_count(byref(c_dk_update_count))
        dk_update_count.value = c_dk_update_count.value

    return status

def sha206a_get_pk_useflag_count(pk_avail_count):
    """
    calculates available Parent Key use counts

    Args:
        pk_avail_count        counts available bit's as 1 (int)

    Returns:
        Status Code
    """
    if not isinstance(pk_avail_count, AtcaReference):
        status = Status.ATCA_BAD_PARAM
    else:
        c_pk_avail_count = c_uint8(pk_avail_count.value)
        status = get_cryptoauthlib().sha206a_get_pk_useflag_count(byref(c_pk_avail_count))
        pk_avail_count.value = c_pk_avail_count.value
    return status

def sha206a_get_dk_useflag_count(dk_avail_count):
    """
    calculates available Derived Key use counts

    Args:
        dk_avail_count        counts available bit's as 1 (int)

    Returns:
        Status Code
    """
    if not isinstance(dk_avail_count, AtcaReference):
        status = Status.ATCA_BAD_PARAM
    else:
        c_dk_avail_count = c_uint8(dk_avail_count.value)
        status = get_cryptoauthlib().sha206a_get_dk_useflag_count(byref(c_dk_avail_count))
        dk_avail_count.value = c_dk_avail_count.value
    return status

def sha206a_check_pk_useflag_validity(is_consumed):
    """
    verifies Parent Key use flags for consumption

    Args:
        is_consumed            indicates if parent key is available for consumption
                               (Expected AtcaReference)

    Returns:
        Status Code
    """
    if not isinstance(is_consumed, AtcaReference):
        status = Status.ATCA_BAD_PARAM
    else:
        c_is_consumed = c_uint8(is_consumed.value)
        status = get_cryptoauthlib().sha206a_check_pk_useflag_validity(byref(c_is_consumed))
        is_consumed.value = c_is_consumed.value
    return status

def sha206a_check_dk_useflag_validity(is_consumed):
    """
    verifies Derived Key use flags for consumption

    Args:
        is_consumed            indicates if derived key is available for consumption
                               (Expected AtcaReference)

    Returns:
        Status Code
    """
    if not isinstance(is_consumed, AtcaReference):
        status = Status.ATCA_BAD_PARAM
    else:
        c_is_consumed = c_uint8(is_consumed.value)
        status = get_cryptoauthlib().sha206a_check_dk_useflag_validity(byref(c_is_consumed))
        is_consumed.value = c_is_consumed.value
    return status

def sha206a_verify_device_consumption(is_consumed):
    """
    verifies the device is fully consumed or not based on Parent and Derived Key use flags.

    Args:
        is_consumed            result of device consumption is returned here
                               (Expected AtcaReference)

    Returns:
        Status Code
    """
    if not isinstance(is_consumed, AtcaReference):
        status = Status.ATCA_BAD_PARAM
    else:
        c_is_consumed = c_uint8(is_consumed.value)
        status = get_cryptoauthlib().sha206a_verify_device_consumption(byref(c_is_consumed))
        is_consumed.value = c_is_consumed.value
    return status

def sha206a_diversify_parent_key(parent_key, diversified_key):
    """
    Computes the diversified key based on the parent key provided and device serial number

    Args:
        parent_key             parent key to be diversified (Expected bytearray of size 32)

        diversified_key        output diversified key is returned here
                               (Expected bytearray of size 32)
    Returns:
        Status Code
    """
    if not isinstance(diversified_key, bytearray):
        status = Status.ATCA_BAD_PARAM
    else:
        c_diversified_key = create_string_buffer(32)
        status = get_cryptoauthlib().sha206a_diversify_parent_key(bytes(parent_key), byref(c_diversified_key))
        diversified_key[0:] = bytes(c_diversified_key.raw)
    return status
