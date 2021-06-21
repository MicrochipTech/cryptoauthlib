"""
Trust Anchor Interface
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

from ctypes import c_uint8, byref, create_string_buffer, c_uint16, c_size_t, POINTER, cast, Array
from .status import Status
from .library import get_cryptoauthlib, AtcaReference, AtcaStructure, AtcaUnion, create_byte_buffer


class ta_handle_properties_public_key(AtcaStructure):
    """
    Class: 0
    """
    _fields_ = [
        ('Path_Length', c_uint8),
        ('Secure_Boot', c_uint8, 1),
        ('Root', c_uint8, 2),
        ('CRL_Sign', c_uint8, 1),
        ('Special_Only', c_uint8, 1),
        ('Reserved', c_uint8, 3)
    ]
    _pack_ = 1


class ta_handle_properties_private_key(AtcaStructure):
    """
    Class 1:
    """
    _fields_ = [
        ('Pub_Key', c_uint8),
        ('Session', c_uint8, 1),
        ('Key_Gen', c_uint8, 1),
        ('Sign_Use', c_uint8, 2),
        ('Agree_Use', c_uint8, 2),
        ('Reserved', c_uint8, 2)
    ]
    _pack_ = 1


class ta_handle_properties_symmetric_key(AtcaStructure):
    """
    Class 2
    """
    _fields_ = [
        ('Granted_Rights', c_uint8),
        ('Sym_Usage', c_uint8, 2),
        ('Session_Use', c_uint8, 3),
        ('Key_Group_OK', c_uint8, 1),
        ('Reserved', c_uint8, 2)
    ]
    _pack_ = 1

class ta_handle_properties_data(AtcaStructure):
    """
    Class 3
    """
    _fields_ = [
        ('Size', c_uint16, 12),
        ('Template', c_uint16, 1),
        ('Reserved', c_uint16, 3)
    ]
    _pack_ = 1


class ta_handle_properties_certificate(AtcaStructure):
    """
    Class 4
    """
    _fields_ = [
        ('Granted_Rights', c_uint8),
        ('Secure_Boot', c_uint8, 1),
        ('CA_OK', c_uint8, 1),
        ('CA_Parent', c_uint8, 1),
        ('CRL_Sign', c_uint8, 1),
        ('Special_Only', c_uint8, 1),
        ('Reserved', c_uint8, 3)
    ]
    _pack_ = 1


class ta_handle_properties_key_group(AtcaStructure):
    """
    Class 6
    """
    _fields_ = [
        ('Num_Keys', c_uint8, 5),
        ('Handles', c_uint8, 1),
        ('Reserved0', c_uint8, 2),
        ('Reserved1', c_uint8)
    ]
    _pack_ = 1


class ta_handle_properties_crl(AtcaStructure):
    _fields_ = [
        ('Num_Digests', c_uint8),
        ('Reserved', c_uint8)
    ]
    _pack_ = 1


class ta_element_attributes_properties(AtcaUnion):
    _fields_ = [
        ('public', ta_handle_properties_public_key),
        ('private', ta_handle_properties_private_key),
        ('symmetric', ta_handle_properties_symmetric_key),
        ('data', ta_handle_properties_data),
        ('certificate', ta_handle_properties_certificate),
        ('key_group', ta_handle_properties_key_group),
        ('crl', ta_handle_properties_crl)
    ]
    _pack_ = 1


class ta_element_attributes_t(AtcaStructure):
    _fields_ = [
        ('Class', c_uint8, 3),
        ('Key_Type', c_uint8, 4),
        ('Alg_Mode', c_uint8, 1),
        ('Property', ta_element_attributes_properties),
        ('Usage_Key', c_uint8),
        ('Write_Key', c_uint8),
        ('Read_Key', c_uint8),
        ('Usage_Perm', c_uint8, 2),
        ('Write_Perm', c_uint8, 2),
        ('Read_Perm', c_uint8, 2),
        ('Delete_Perm', c_uint8, 2),
        ('Use_Count', c_uint8, 2),
        ('Reserved0', c_uint8, 1),
        ('Exportable', c_uint8, 1),
        ('Lockable', c_uint8, 1),
        ('Access_Limit', c_uint8, 2),
        ('Reserved1', c_uint8, 1)
    ]
    _pack_ = 1


def talib_handle_init_public_key(attributes, key_type, alg_mode, secure_boot_enable, root_key_enable):
    return get_cryptoauthlib().talib_handle_init_public_key(byref(attributes), key_type, alg_mode, secure_boot_enable,
                                                            root_key_enable)

def talib_handle_init_private_key(attributes, key_type, alg_mode, sign_use, key_agreement_use):
    return get_cryptoauthlib().talib_handle_init_private_key(byref(attributes), key_type, alg_mode, sign_use,
                                                             key_agreement_use)


def talib_handle_init_symmetric_key(attributes, key_type, sym_usage):
    return get_cryptoauthlib().talib_handle_init_symmetric_key(byref(attributes), key_type, sym_usage)


def talib_handle_init_data(attributes, data_size):
    return get_cryptoauthlib().talib_handle_init_data(byref(attributes), data_size)


def talib_handle_init_extracated_certificate(attributes, key_type, alg_mode, secure_boot_use, intermediate_ca_enable):
    return get_cryptoauthlib().talib_handle_init_extracated_certificate(byref(attributes), key_type, alg_mode,
                                                                        secure_boot_use, intermediate_ca_enable)


def talib_handle_init_fast_crypto_key_group(attributes, key_type, num_keys, handles):
    return get_cryptoauthlib().talib_handle_init_fast_crypto_key_group(byref(attributes), key_type, num_keys, handles)


def talib_handle_set_permissions(attributes, usage_perm, write_perm, read_perm, delete_perm):
    return get_cryptoauthlib().talib_handle_set_permissions(byref(attributes), usage_perm, write_perm, read_perm,
                                                            delete_perm)

def talib_handle_set_usage_permission(attributes, usage_perm):
    return get_cryptoauthlib().talib_handle_set_usage_permission(byref(attributes), usage_perm)


def talib_handle_set_write_permission(attributes, write_perm):
    return get_cryptoauthlib().talib_handle_set_write_permission(byref(attributes), write_perm)


def talib_handle_set_read_permission(attributes, read_perm):
    return get_cryptoauthlib().talib_handle_set_read_permission(byref(attributes), read_perm)


def talib_handle_set_delete_permission(attributes, delete_perm):
    return get_cryptoauthlib().talib_handle_set_delete_permission(byref(attributes), delete_perm)


def talib_create(device, mode, details, handle_in, handle_config, handle_out):
    if not isinstance(handle_out, AtcaReference):
        status = Status.ATCA_BAD_PARAM
    else:
        c_handle_out = c_uint16(handle_out.value)
        status = get_cryptoauthlib().talib_create(device, details, handle_in, byref(handle_config), byref(c_handle_out))
        handle_out.value = c_handle_out.value
    return status


def talib_create_element(device, handle_config, handle_out):
    if not isinstance(handle_out, AtcaReference):
        status = Status.ATCA_BAD_PARAM
    else:
        c_handle_out = c_uint16(handle_out.value)
        status = get_cryptoauthlib().talib_create_element(device, handle_config, byref(c_handle_out))
        handle_out.value = c_handle_out.value
    return status


def talib_create_element_with_handle(device, handle_in, handle_config):
    return get_cryptoauthlib().talib_create_element_with_handle(device, handle_in, byref(handle_config))


def talib_create_ephemeral_element_with_handle(device, details, handle_in, handle_config):
    return get_cryptoauthlib().talib_create_ephemeral_element_with_handle(device, details, handle_in,
                                                                          byref(handle_config))


def talib_create_hmac_element(device, key_size, handle_config, handle_out):
    if not isinstance(handle_out, AtcaReference):
        status = Status.ATCA_BAD_PARAM
    else:
        c_handle_out = c_uint16(handle_out.value)
        status = get_cryptoauthlib().talib_create_hmac_element(device, key_size, byref(handle_config),
                                                               byref(c_handle_out))
        handle_out.value = c_handle_out.value
    return status


def talib_create_hmac_element_with_handle(device, key_size, handle_in, handle_config):
    return get_cryptoauthlib().talib_create_hmac_element_with_handle(device, key_size, handle_in, byref(handle_config))


def talib_delete_handle(device, handle):
    return get_cryptoauthlib().talib_delete_handle(device, handle)


def talib_is_handle_valid(device, target_handle, is_valid):
    if not isinstance(is_valid, AtcaReference):
        status = Status.ATCA_BAD_PARAM
    else:
        c_is_valid = c_uint8(is_valid.value)
        status = get_cryptoauthlib().talib_is_handle_valid(device, target_handle, byref(c_is_valid))
        is_valid.value = c_is_valid.value
    return status


def talib_info(device, revision):
    """
    Used to get the device revision number. (DevRev)

    Args:
        revision            8-byte bytearray receiving the revision number
                            from the device. (Expects bytearray)

    Returns:
        Status code
    """
    c_revision = create_string_buffer(8)
    if not isinstance(revision, bytearray):
        status = Status.ATCA_BAD_PARAM
    else:
        status = get_cryptoauthlib().talib_info(device, c_revision)
        revision[0:] = bytes(c_revision.raw)
    return status


def talib_info_get_handle_info(device, target_handle, handle_info):
    if not isinstance(handle_info, ta_element_attributes_t):
        status = Status.ATCA_BAD_PARAM
    else:
        info_array = create_string_buffer(9)
        status = get_cryptoauthlib().talib_info_get_handle_info(device, target_handle, info_array)
        handle_info.update_from_buffer(info_array)
    return status


#ATCA_STATUS talib_info_get_handle_info(ATCADevice device, uint32_t target_handle, uint8_t handle_info[STATIC_ARRAY TA_HANDLE_INFO_SIZE]);


def talib_info_get_handles_array(device, handles):
    if not isinstance(handles, list):
        status = Status.ATCA_BAD_PARAM
    else:
        results = (c_uint16*100)()
        count = c_size_t(100)
        status = get_cryptoauthlib().talib_info_get_handles_array(device, cast(results, POINTER(c_uint16)), byref(count))
        handles[0:] = results[:count.value]
    return status


#ATCA_STATUS talib_info_get_handle_size(ATCADevice device, uint32_t target_handle, size_t* out_size);


def talib_write_element(device, handle, length, data):
    status = get_cryptoauthlib().talib_write_element(device, handle, length, bytes(data))

    return status


def talib_auth_generate_nonce(device, handle, options, i_nonce):
    cbuf = create_string_buffer(16)
    cbuf[0:] = i_nonce[0:16]
    status = get_cryptoauthlib().talib_auth_generate_nonce(device, handle, options, cbuf)
    i_nonce[0:] = cbuf[:len(cbuf)]
    return status


def talib_auth_startup(device, handle, alg_id, max_cmd, key_len, key, i_nonce, r_nonce):
    status = get_cryptoauthlib().talib_auth_startup(device, handle, alg_id, max_cmd, key_len, key,
                                                    create_byte_buffer(i_nonce), create_byte_buffer(r_nonce))
    return status


def talib_auth_terminate(device):
    return get_cryptoauthlib().talib_auth_terminate(device)

# Make module import * safe - keep at the end of the file
__all__ = ['ta_element_attributes_t']
__all__ += [x for x in dir() if x.startswith(__name__.split('.')[-1])]
