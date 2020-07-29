"""
Dynamic link library loading under ctypes and HAL initilization/release functions
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

from ctypes import c_uint8, c_uint32, byref, create_string_buffer, Structure, c_char, c_uint16, c_void_p, c_bool
from .status import Status
from .library import get_cryptoauthlib, AtcaReference

# Because this module directly mirrors the C api the following is an exception to the python coding standard
# pylint: disable-msg=too-many-arguments, invalid-name, too-few-public-methods


class atca_aes_cbc_ctx(Structure):
    """AES CBC Context"""
    _fields_ = [("key_id", c_uint16),
                ("key_block", c_uint8),
                ("ciphertext", c_char*16)]


class atca_aes_cmac_ctx(Structure):
    """AES CMAC Context"""
    _fields_ = [("cbc_ctx", atca_aes_cbc_ctx),
                ("block_size", c_uint32),
                ("block", c_char*16)]


class atca_aes_ctr_ctx(Structure):
    """AES CTR Context"""
    _fields_ = [("key_id", c_uint16),
                ("key_block", c_uint8),
                ("iv", c_char*16),
                ("counter_size", c_uint8)]


class atca_sha256_ctx(Structure):
    """SHA256 context"""
    _fields_ = [("total_msg_size", c_uint32),
                ("block_size", c_uint32),
                ("block", c_char*64*2)]

class atca_aes_gcm_ctx(Structure):
    """Context structure for AES GCM operations"""
    _fields_ = [("key_id", c_uint16),
                ("key_block", c_uint8),
                ("cb", c_char*16),
                ("data_size", c_uint32),
                ("aad_size", c_uint32),
                ("h", c_char*16),
                ("j0", c_char*16),
                ("y", c_char*16),
                ("partial_aad", c_char*16),
                ("partial_aad_size", c_uint32),
                ("enc_cb", c_char*16),
                ("ciphertext_block", c_char*16)]

class atca_hmac_sha256_ctx(atca_sha256_ctx):
    """HMAC-SHA256 context"""


def atcab_init(iface_cfg):
    """
    Initialize the communication stack and initializes the ATCK590 kit
    Communication over USB HID and Kit Protocol by default
    raise CryptoException
    """
    status = get_cryptoauthlib().atcab_init(byref(iface_cfg))
    return status


def atcab_release():
    """
    Release the kit and the communication stack
    raise CryptoException
    """
    return get_cryptoauthlib().atcab_release()


def atcab_get_device():
    """
    Return the global device instance
    """
    return get_cryptoauthlib().atcab_get_device()


def atcab_get_device_type():
    """
    Return the device type of the currently initialized device.
    """
    return get_cryptoauthlib().atcab_get_device_type()


# CryptoAuthLib Basic API methods for AES command.
#
# The AES command supports 128-bit AES encryption or decryption of small
# messages or data packets in ECB mode. Also can perform GFM (Galois Field
# Multiply) calculation in support of AES-GCM.


def atcab_aes(mode, key_id, aes_in, aes_out):
    """
    Compute the AES-128 encrypt, decrypt, or GFM calculation.

    Args:
        mode                The mode for the AES command. (int)
        key_id              Key location. Can either be a slot number or
                            ATCA_TEMPKEY_KEYID for TempKey. (int)
        aes_in              Input data to the AES command (16 bytes). (Can be of type bytearray or bytes)
        aes_out             Output data from the AES command is returned here
                            (16 bytes). (Expects bytearray of size 16)

    Returns:
        Status Code
    """
    c_aes_out = create_string_buffer(16)
    if not isinstance(aes_out, bytearray):
        status = Status.ATCA_BAD_PARAM
    else:
        status = get_cryptoauthlib().atcab_aes(mode, key_id, bytes(aes_in), byref(c_aes_out))
        aes_out[0:] = bytes(c_aes_out.raw)
    return status


def atcab_aes_encrypt(key_id, key_block, plaintext, ciphertext):
    """
    Perform an AES-128 encrypt operation with a key in the device.

    Args:
        key_id              Key location. Can either be a slot number or
                            ATCA_TEMPKEY_KEYID for TempKey. (int)
        key_block           Index of the 16-byte block to use within the key
                            location for the actual key.(int)
        plaintext           Input plaintext to be encrypted (16 bytes).
                            (Can be of type bytearray or bytes)
        ciphertext          Output ciphertext is returned here (16 bytes).
                            (Expects bytearray of size 16)

    Returns:
        Status Code
    """
    c_ciphertext = create_string_buffer(16)
    if not isinstance(ciphertext, bytearray):
        status = Status.ATCA_BAD_PARAM
    else:
        status = get_cryptoauthlib().atcab_aes_encrypt(key_id, key_block, bytes(plaintext), byref(c_ciphertext))
        ciphertext[0:] = bytes(c_ciphertext.raw)
    return status


def atcab_aes_decrypt(key_id, key_block, ciphertext, plaintext):
    """
    Perform an AES-128 decrypt operation with a key in the device.

    Args:
        key_id              Key location. Can either be a slot number or
                            ATCA_TEMPKEY_KEYID for TempKey.(int)
        key_block           Index of the 16-byte block to use within the key
                            location for the actual key. (int)
        ciphertext          Input ciphertext to be decrypted (16 bytes).
                            (bytearray or bytes)
        plaintext           Output plaintext is returned here (16 bytes).
                            (Expects bytearray of size 16)s

    Returns:
        Status Code
    """
    c_plaintext = create_string_buffer(16)
    if not isinstance(plaintext, bytearray):
        status = Status.ATCA_BAD_PARAM
    else:
        status = get_cryptoauthlib().atcab_aes_decrypt(key_id, key_block, bytes(ciphertext), byref(c_plaintext))
        plaintext[0:] = bytes(c_plaintext.raw)
    return status


def atcab_aes_gfm(hash_key, inp, output):
    """
    Perform a Galois Field Multiply (GFM) operation.

    Args:
        hash_key            First input value (16 bytes).
                            (bytearray or bytes)
        inp                 Second input value (16 bytes).
                            (bytearray or bytes)
        output              GFM result is returned here (16 bytes).
                            (Expects bytearray of size 16)

    Returns:
        Status Code
    """
    c_output = create_string_buffer(16)
    if not isinstance(output, bytearray):
        status = Status.ATCA_BAD_PARAM
    else:
        status = get_cryptoauthlib().atcab_aes_gfm(bytes(hash_key), bytes(inp), byref(c_output))
        output[0:] = bytes(c_output.raw)
    return status


def atcab_aes_cbc_init(ctx, key_id, key_block, iv):
    """
    Initialize context for AES CBC operation.
    Args:
        ctx                 AES CBC context to be initialized
        key_id              Key location. Can either be a slot number
                            or ATCA_TEMPKEY_KEYID for TempKey.
        key_block           Index of the 16-byte block to use within the
                            key location for the actual key.
        iv                  Initialization vector (16 bytes). Bytearray format

    Returns:
        Status Code
    """
    if not isinstance(iv, bytearray):
        status = Status.ATCA_BAD_PARAM
    else:
        status = get_cryptoauthlib().atcab_aes_cbc_init(byref(ctx), key_id, key_block, bytes(iv))
    return status


def atcab_aes_cbc_encrypt_block(ctx, plaintext, ciphertext):
    """
    Encrypt a block of data using CBC mode and a key within the
    ATECC608. atcab_aes_cbc_init() should be called before the
    first use of this function.

    Args:
        ctx                 AES CBC context.
        plaintext           Plaintext to be encrypted (16 bytes).
                            (Bytearray or bytes)
        ciphertext          Encrypted data is returned here (16 bytes).
                            (Bytearray or bytes)

    Returns:
        Status code
    """
    c_ciphertext = create_string_buffer(16)
    if not isinstance(ciphertext, bytearray):
        status = Status.ATCA_BAD_PARAM
    else:
        status = get_cryptoauthlib().atcab_aes_cbc_encrypt_block(byref(ctx), bytes(plaintext), byref(c_ciphertext))
        ciphertext[0:] = bytes(c_ciphertext.raw)
    return status


def atcab_aes_cbc_decrypt_block(ctx, ciphertext, plaintext):
    """
    Decrypt a block of data using CBC mode and a key within the
    ATECC608. atcab_aes_cbc_init() should be called before the
    first use of this function.

    Args:
        ctx                 AES CBC context.
        ciphertext          Ciphertext to be decrypted (16 bytes).
                            (Bytearray or bytes)
        plaintext           Decrypted data is returned here (16 bytes).
                            (Bytearray or bytes)

    Returns:
        Status code
    """
    c_plaintext = create_string_buffer(16)
    if not isinstance(plaintext, bytearray):
        status = Status.ATCA_BAD_PARAM
    else:
        status = get_cryptoauthlib().atcab_aes_cbc_decrypt_block(byref(ctx), bytes(ciphertext), byref(c_plaintext))
        plaintext[0:] = bytes(c_plaintext.raw)
    return status


def atcab_aes_cmac_init(ctx, key_id, key_block):
    """
    Initialize a CMAC calculation using an AES-128 key in the ATECC608.

    Args:
        ctx                 AES-128 CMAC context.
        key_id              Key location. Can either be a slot number
                            or ATCA_TEMPKEY_KEYID for TempKey.
        key_block           Index of the 16-byte block to use within
                            the key location for the actual key.

    Returns:
        Status code
    """
    status = get_cryptoauthlib().atcab_aes_cmac_init(byref(ctx), key_id, key_block)
    return status


def atcab_aes_cmac_update(ctx, data, data_size):
    """
    Add data to an initialized CMAC calculation.

    Args:
        ctx                 AES-128 CMAC context.
        data                Data to be added.
        data_size           Size of the data to be added in bytes.

    Returns:
        Status code
    """
    if not isinstance(data, bytearray):
        status = Status.ATCA_BAD_PARAM
    else:
        status = get_cryptoauthlib().atcab_aes_cmac_update(byref(ctx), bytes(data), data_size)
    return status


def atcab_aes_cmac_finish(ctx, cmac, size):
    """
    Finish a CMAC operation returning the CMAC value.

    Args:
        ctx                 AES-128 CMAC context.
        cmac                CMAC is returned here.
        cmac_size           Size of CMAC requested in bytes (max 16 bytes).

    Returns:
        Status code
    """
    c_cmac = create_string_buffer(16)
    if not isinstance(cmac, bytearray):
        status = Status.ATCA_BAD_PARAM
    else:
        status = get_cryptoauthlib().atcab_aes_cmac_finish(byref(ctx), byref(c_cmac), size)
        cmac[0:] = bytes(c_cmac.raw)
    return status


def atcab_aes_ctr_init(ctx, key_id, key_block, counter_size, iv):
    """
    Initialize context for AES CTR operation with an existing IV, which
    is common when start a decrypt operation.

    The IV is a combination of nonce (left-field) and big-endian counter
    (right-field). The counter_size field sets the size of the counter and the
    remaining bytes are assumed to be the nonce.

    Args:
        ctx                 AES CTR context to be initialized.
        key_id              Key location. Can either be a slot number or
                            ATCA_TEMPKEY_KEYID for TempKey.
        key_block           Index of the 16-byte block to use within the key
                            location for the actual key.
        counter_size        Size of counter in IV in bytes. 4 bytes is a
                            common size.
        iv                  Initialization vector (concatenation of nonce and
                            counter) 16 bytes.

    Returns:
        ATCA_SUCCESS on success, otherwise an error code.
    """
    status = get_cryptoauthlib().atcab_aes_ctr_init(byref(ctx), key_id, key_block, counter_size, bytes(iv))
    return status


def atcab_aes_ctr_init_rand(ctx, key_id, key_block, counter_size, iv):
    """
    Initialize context for AES CTR operation with a random nonce and
    counter set to 0 as the IV, which is common when starting an
    encrypt operation.

    The IV is a combination of nonce (left-field) and big-endian counter
    (right-field). The counter_size field sets the size of the counter and the
    remaining bytes are assumed to be the nonce.

    Args:
        ctx                 AES CTR context to be initialized.
        key_id              Key location. Can either be a slot number or
                            ATCA_TEMPKEY_KEYID for TempKey.
        key_block           Index of the 16-byte block to use within the key
                            location for the actual key.
        counter_size        Size of counter in IV in bytes. 4 bytes is a
                            common size.
        iv                  Initialization vector (concatenation of nonce and
                            counter) is returned here (16 bytes).

    Returns:
        ATCA_SUCCESS on success, otherwise an error code.
    """
    c_iv = create_string_buffer(16)
    if not isinstance(iv, bytearray):
        status = Status.ATCA_BAD_PARAM
    else:
        status = get_cryptoauthlib().atcab_aes_ctr_init_rand(byref(ctx), key_id, key_block, counter_size, byref(c_iv))
        iv[0:] = bytes(c_iv.raw)
    return status


def atcab_aes_ctr_encrypt_block(ctx, plaintext, ciphertext):
    """
    Encrypt a block of data using CTR mode and a key within the
    ATECC608 device. atcab_aes_ctr_init() or atcab_aes_ctr_init_rand()
    should be called before the first use of this function.

    Args:
        ctx                 AES CTR context structure.
        plaintext           Plaintext to be encrypted (16 bytes).
        ciphertext          Encrypted data is returned here (16 bytes).

    Returns:
        Status code
    """
    c_ciphertext = create_string_buffer(16)
    if not isinstance(ciphertext, bytearray):
        status = Status.ATCA_BAD_PARAM
    else:
        status = get_cryptoauthlib().atcab_aes_ctr_encrypt_block(byref(ctx), bytes(plaintext), byref(c_ciphertext))
        ciphertext[0:] = bytes(c_ciphertext.raw)
    return status


def atcab_aes_ctr_decrypt_block(ctx, ciphertext, plaintext):
    """
    Decrypt a block of data using CTR mode and a key within the
    ATECC608 device. atcab_aes_ctr_init() or atcab_aes_ctr_init_rand()
    should be called before the first use of this function.

    Args:
        ctx                 AES CTR context structure.
        ciphertext          Ciphertext to be decrypted (16 bytes).
        plaintext           Decrypted data is returned here (16 bytes).

    Returns:
        Status code
    """
    c_plaintext = create_string_buffer(16)
    if not isinstance(plaintext, bytearray):
        status = Status.ATCA_BAD_PARAM
    else:
        status = get_cryptoauthlib().atcab_aes_ctr_decrypt_block(byref(ctx), bytes(ciphertext), byref(c_plaintext))
        plaintext[0:] = bytes(c_plaintext.raw)
    return status


def atcab_aes_gcm_init(ctx, key_id, key_block, iv, iv_size):
    """
    Initialize context for AES GCM operation with an existing IV, which
    is common when starting a decrypt operation.

    Args:
        ctx                 AES GCM context to be initialized.
        key_id              Key location. Can either be a slot number or
                            ATCA_TEMPKEY_KEYID for TempKey.
        key_block           Index of the 16-byte block to use within the key
                            location for the actual key.
        iv                  Initialization vector.
        iv_size       Size of IV in bytes. Standard is 12 bytes.
    Returns:
        ATCA_SUCCESS on success, otherwise an error code.
    """
    status = get_cryptoauthlib().atcab_aes_gcm_init(byref(ctx), key_id, key_block, bytes(iv), iv_size)
    return status

def atcab_aes_gcm_init_rand(ctx, key_id, key_block, rand_size, free_field, free_field_size, iv):
    """
    Initialize context for AES GCM operation with a IV composed of a
    random and optional fixed(free) field, which is common when
    starting an encrypt operation.

    Args:
        ctx                 AES CTR context to be initialized.
        key_id              Key location. Can either be a slot number or
                            ATCA_TEMPKEY_KEYID for TempKey.
        key_block           Index of the 16-byte block to use within the
                            key location for the actual key.
        rand_size           Size of the random field in bytes. Minimum and
                            recommended size is 12 bytes. Max is 32 bytes.
        free_field          Fixed data to include in the IV after the
                            random field. Can be NULL if not used.
        free_field_size     Size of the free field in bytes.
        iv                  Initialization vector is returned here. Its
                            size will be rand_size and free_field_size
                            combined.
    Returns:
        ATCA_SUCCESS on success, otherwise an error code.
    """
    c_iv = create_string_buffer(16)
    if not isinstance(iv, bytearray):
        status = Status.ATCA_BAD_PARAM
    else:
        status = get_cryptoauthlib().atcab_aes_gcm_init_rand(byref(ctx), key_id, key_block, rand_size,
                                                             bytes(free_field), free_field_size, byref(c_iv))
        iv[0:] = bytes(c_iv.raw)
    return status

def atcab_aes_gcm_aad_update(ctx, aad, aad_size):
    """
    Process Additional Authenticated Data (AAD) using GCM mode and a
    key within the ATECC608 device.

    This can be called multiple times. atcab_aes_gcm_init() or
    atcab_aes_gcm_init_rand() should be called before the first use of this
    function. When there is AAD to include, this should be called before
    atcab_aes_gcm_encrypt_update() or atcab_aes_gcm_decrypt_update().

    Args:
        ctx                 AES GCM context
        aad                 Additional authenticated data to be added
        aad_size            Size of aad in bytes

    Returns:
        ATCA_SUCCESS on success, otherwise an error code.
    """
    status = get_cryptoauthlib().atcab_aes_gcm_aad_update(byref(ctx), bytes(aad), aad_size)
    return status

def atcab_aes_gcm_encrypt_update(ctx, plaintext, plaintext_size, ciphertext):
    """
    Encrypt data using GCM mode and a key within the ATECC608 device.
    atcab_aes_gcm_init() or atcab_aes_gcm_init_rand() should be called
    before the first use of this function.

    Args:
        ctx                 AES GCM context structure.
        plaintext           Plaintext to be encrypted (16 bytes).
        plaintext_size      Size of plaintext in bytes.
        ciphertext          Encrypted data is returned here.

    Returns:
        ATCA_SUCCESS on success, otherwise an error code.
    """
    c_ciphertext = create_string_buffer(plaintext_size)
    if not isinstance(ciphertext, bytearray):
        status = Status.ATCA_BAD_PARAM
    else:
        status = get_cryptoauthlib().atcab_aes_gcm_encrypt_update(byref(ctx),
                                                                  bytes(plaintext), plaintext_size, byref(c_ciphertext))
        ciphertext[0:] = bytes(c_ciphertext.raw)
    return status

def atcab_aes_gcm_encrypt_finish(ctx, tag, tag_size):
    """
    Complete a GCM encrypt operation returning the authentication tag.

    Args:
        ctx                 AES GCM context structure.
        tag                 Authentication tag is returned here.
        tag_size            Tag size in bytes (12 to 16 bytes).

    Returns:
        ATCA_SUCCESS on success, otherwise an error code.
    """
    c_tag = create_string_buffer(tag_size)
    if not isinstance(tag, bytearray):
        status = Status.ATCA_BAD_PARAM
    else:
        status = get_cryptoauthlib().atcab_aes_gcm_encrypt_finish(byref(ctx), byref(c_tag), tag_size)
        tag[0:] = bytes(c_tag.raw)
    return status

def atcab_aes_gcm_decrypt_update(ctx, ciphertext, ciphertext_size, plaintext):
    """
    Decrypt data using GCM mode and a key within the ATECC608 device.
    atcab_aes_gcm_init() or atcab_aes_gcm_init_rand() should be called
    before the first use of this function.

    Args:
        ctx                 AES GCM context structure.
        ciphertext          Ciphertext to be decrypted.
        ciphertext_size     Size of ciphertext in bytes.
        plaintext           Decrypted data is returned here.

    Returns:
        ATCA_SUCCESS on success, otherwise an error code.
    """
    c_plaintext = create_string_buffer(ciphertext_size)
    if not isinstance(plaintext, bytearray):
        status = Status.ATCA_BAD_PARAM
    else:
        status = get_cryptoauthlib().atcab_aes_gcm_decrypt_update(byref(ctx), bytes(ciphertext),
                                                                  ciphertext_size, byref(c_plaintext))
        plaintext[0:] = bytes(c_plaintext.raw)
    return status

def atcab_aes_gcm_decrypt_finish(ctx, tag, tag_size, is_verified):
    """
    Complete a GCM decrypt operation verifying the authentication tag.

    Args:
        ctx                 AES GCM context structure.
        tag                 Expected authentication tag.
        tag_size            Size of tag in bytes (12 to 16 bytes).
        is_verified         Returns whether or not the tag verified.

    Returns:
        ATCA_SUCCESS on success, otherwise an error code.
    """
    if not isinstance(is_verified, AtcaReference):
        status = Status.ATCA_BAD_PARAM
    else:
        c_is_verified = c_uint8(is_verified.value)
        status = get_cryptoauthlib().atcab_aes_gcm_decrypt_finish(byref(ctx), bytes(tag),
                                                                  tag_size, byref(c_is_verified))
        is_verified.value = c_is_verified.value
    return status

# CryptoAuthLib Basic API methods for CheckMAC command.
#
# The CheckMac command calculates a MAC response that would have been
# generated on a different CryptoAuthentication device and then compares the
# result with input value.


def atcab_checkmac(mode, key_id, challenge, response, other_data):
    """
    Compares a MAC response with input values

    Args:
        mode                Controls which fields within the device are used in
                            the message (int)
        key_id              Key location in the CryptoAuth device to use for the
                            MAC (int)
        challenge           Challenge data (32 bytes) (bytearray or bytes)
        response            MAC response data (32 bytes) (bytearray or bytes)
        other_data          OtherData parameter (13 bytes) (bytearray or bytes)

    Returns:
        Status code
    """
    status = get_cryptoauthlib().atcab_checkmac(mode, key_id, bytes(challenge), bytes(response), bytes(other_data))
    return status


# CryptoAuthLib Basic API methods for Counter command.
#
# The Counter command reads or increments the binary count value for one of the
# two monotonic counters.


def atcab_counter(mode, counter_id, counter_value):
    """
    Compute the Counter functions

    Args:
        mode                The mode used for the counter (int)
        counter_id          The counter to be used (int)
        counter_value       Counter value returned from device
                            (AtcaReference expected)

    Returns:
        Status code
    """
    if not isinstance(counter_value, AtcaReference):
        status = Status.ATCA_BAD_PARAM
    else:
        c_counter_value = c_uint32(counter_value.value)
        status = get_cryptoauthlib().atcab_counter(mode, counter_id, byref(c_counter_value))
        counter_value.value = c_counter_value.value
    return status


def atcab_counter_increment(counter_id, counter_value):
    """
    Increments one of the device's monotonic counters

    Args:
        counter_id          Counter to be incremented (int)
        counter_value       New value of the counter is returned here
                            (AtcaReference expected)

    Returns:
        Status code
    """
    if not isinstance(counter_value, AtcaReference):
        status = Status.ATCA_BAD_PARAM
    else:
        c_counter_value = c_uint32(counter_value.value)
        status = get_cryptoauthlib().atcab_counter_increment(counter_id, byref(c_counter_value))
        counter_value.value = c_counter_value.value
    return status


def atcab_counter_read(counter_id, counter_value):
    """
    Reads one of the device's monotonic counters

    Args:
        counter_id          Counter to be read (int)
        counter_value       Counter value is returned here
                            (AtcaReference expected)

    Returns:
        Status code
    """
    if not isinstance(counter_value, AtcaReference):
        status = Status.ATCA_BAD_PARAM
    else:
        c_counter_value = c_uint32(counter_value.value)
        status = get_cryptoauthlib().atcab_counter_read(counter_id, byref(c_counter_value))
        counter_value.value = c_counter_value.value
    return status


# CryptoAuthLib Basic API methods for DeriveKey command.
#
# The DeriveKey command combines the current value of a key with the nonce
# stored in TempKey using SHA-256 and derives a new key.


def atcab_derivekey(mode, target_key, mac):
    """
    Executes the DeviveKey command for deriving a new key from a
    nonce (TempKey) and an existing key.

    Args:
        mode                Bit 2 must match the value in TempKey.SourceFlag (int)
        target_key          Key slot to be written (int)
        mac                 Optional 32 byte MAC used to validate operation.
                            (bytearray or bytes)

    Returns:
        Status code
    """
    status = get_cryptoauthlib().atcab_derivekey(mode, target_key, bytes(mac))
    return status


# CryptoAuthLib Basic API methods for ECDH command.
#
# The ECDH command implements the Elliptic Curve Diffie-Hellman algorithm to
# combine an internal private key with an external public key to calculate a
# shared secret.


def atcab_ecdh_base(mode, key_id, public_key, pms, out_nonce):
    """
    Base function for generating premaster secret key using ECDH.

    Args:
        mode                Mode to be used for ECDH computation (int)
        key_id              Slot of key for ECDH computation (int)
        public_key          Public key input to ECDH calculation. X and Y
                            integers in big-endian format. 64 bytes for P256
                            key. (bytearray or bytes)
        pms                 ByteArray - Computed ECDH pre-master secret is returned here (32
                            bytes) if returned directly. Otherwise NULL.
        out_nonce           ByteArray - Nonce used to encrypt pre-master secret. NULL if
                            output encryption not used.

    Returns:
        Status code
    """
    c_pms = create_string_buffer(32)
    c_out_nonce = create_string_buffer(32)

    if (not isinstance(pms, bytearray)) or (not isinstance(out_nonce, bytearray)):
        status = Status.ATCA_BAD_PARAM
    else:
        status = get_cryptoauthlib().atcab_ecdh_base(mode, key_id, bytes(public_key), byref(c_pms), byref(c_out_nonce))
        pms[0:] = bytes(c_pms.raw)
        out_nonce[0:] = bytes(c_out_nonce.raw)
    return status


def atcab_ecdh(key_id, public_key, pms):
    """
    ECDH command with a private key in a slot and the premaster secret
    is returned in the clear.

    Args:
        key_id              Slot of key for ECDH computation (int)
        public_key          Public key input to ECDH calculation. X and Y
                            integers in big-endian format. 64 bytes for P256
                            key.(bytearray or bytes)
        pms                 ByteArray - Computed ECDH premaster secret is returned
                            here (32 bytes).(Expects bytearray of size 32)

    Returns:
        Status code
    """
    c_pms = create_string_buffer(32)

    if not isinstance(pms, bytearray):
        status = Status.ATCA_BAD_PARAM
    else:
        status = get_cryptoauthlib().atcab_ecdh(key_id, bytes(public_key), byref(c_pms))
        pms[0:] = bytes(c_pms.raw)
    return status


def atcab_ecdh_enc(key_id, public_key, pms, read_key, read_key_id, num_in=None):
    """
    ECDH command with a private key in a slot and the premaster secret
    is read from the next slot. This function only works for even
    numbered slots with the proper configuration.

    Args:
        key_id              Slot of key for ECDH computation (int)
        public_key          Public key input to ECDH calculation. X and Y
                            integers in big-endian format. 64 bytes for P256
                            key. (bytearray or bytes)
        read_key            Read key for the premaster secret slot (key_id|1)
                            (32 bytes). (bytearray or bytes)
        read_key_id         Read key slot for read_key. (int)
        pms                 ByteArray - Computed ECDH premaster secret is returned
                            here (32 bytes).(Expects bytearray of size 32)
        num_in              Bytearray - Host nonce used to calculate nonce (20 bytes)
    Returns:
        Status code
    """
    c_pms = create_string_buffer(32)
    if num_in is None:
        num_in = bytearray(20)

    if not isinstance(pms, bytearray):
        status = Status.ATCA_BAD_PARAM
    else:
        status = get_cryptoauthlib().atcab_ecdh_enc(key_id, bytes(public_key),
                                                    byref(c_pms), bytes(read_key), read_key_id, bytes(num_in))
        pms[0:] = bytes(c_pms.raw)
    return status


def atcab_ecdh_ioenc(key_id, public_key, pms, io_key):
    """
    ECDH command with a private key in a slot and the premaster secret
    is returned encrypted using the IO protection key.

    Args:
        key_id              Slot of key for ECDH computation (int)
        public_key          Public key input to ECDH calculation. X and Y
                            integers in big-endian format. 64 bytes for P256
                            key. (bytearray or bytes)
        io_key              IO protection key (32 bytes). (bytearray or bytes)
        pms                 Computed ECDH premaster secret is returned here
                            (32 bytes). (Expects bytearray of size 32)

    Returns:
        Status code
    """
    c_pms = create_string_buffer(32)

    if not isinstance(pms, bytearray):
        status = Status.ATCA_BAD_PARAM
    else:
        status = get_cryptoauthlib().atcab_ecdh_ioenc(key_id, bytes(public_key), byref(c_pms), bytes(io_key))
        pms[0:] = bytes(c_pms.raw)
    return status


def atcab_ecdh_tempkey(public_key, pms):
    """
    ECDH command with a private key in TempKey and the premaster secret
    is returned in the clear.

    Args:
        public_key          Public key input to ECDH calculation. X and Y
                            integers in big-endian format. 64 bytes for P256
                            key. (bytearray or bytes)
        pms                 Computed ECDH premaster secret is returned here
                            (32 bytes). (Expects bytearray of size 32)

    Retuns:
        Status code
    """
    c_pms = create_string_buffer(32)

    if not isinstance(pms, bytearray):
        status = Status.ATCA_BAD_PARAM
    else:
        status = get_cryptoauthlib().atcab_ecdh_tempkey(bytes(public_key), byref(c_pms))
        pms[0:] = bytes(c_pms.raw)
    return status


def atcab_ecdh_tempkey_ioenc(public_key, pms, io_key):
    """
    ECDH command with a private key in TempKey and the premaster secret
    is returned encrypted using the IO protection key.

    Args:
        public_key          Public key input to ECDH calculation. X and Y
                            integers in big-endian format. 64 bytes for P256
                            key. (bytearray or bytes)
        io_key              IO protection key (32 bytes).(bytearray or bytes)
        pms                 Computed ECDH premaster secret is returned here
                            (32 bytes). (Expects bytearray of size 32)

    Returns:
        Status code
    """
    c_pms = create_string_buffer(32)

    if not isinstance(pms, bytearray):
        status = Status.ATCA_BAD_PARAM
    else:
        status = get_cryptoauthlib().atcab_ecdh_tempkey_ioenc(bytes(public_key), byref(c_pms), bytes(io_key))
        pms[0:] = bytes(c_pms.raw)
    return status


# CryptoAuthLib Basic API methods for GenDig command.
#
# The GenDig command uses SHA-256 to combine a stored value with the contents
# of TempKey, which must have been valid prior to the execution of this
# command.


def atcab_gendig(zone, key_id, other_data, other_data_size):
    """
    Issues a GenDig command, which performs a SHA256 hash on the source
    data indicated by zone with the contents of TempKey.  See the
    CryptoAuth datasheet for your chip to see what the values of zone
    correspond to.

    Args:
        zone                Designates the source of the data to hash
                            with TempKey.(int)
        key_id              Indicates the key, OTP block, or message
                            order for shared nonce mode. (int)
        other_data          Four bytes of data for SHA calculation when
                            using a NoMac key, 32 bytes for "Shared Nonce"
                            mode, otherwise ignored (can be NULL).
                            (bytearray or bytes)
        other_data_size     Size of other_data in bytes. (int)

    Returns:
        Status code
    """
    status = get_cryptoauthlib().atcab_gendig(zone, key_id, bytes(other_data), other_data_size)
    return status


# CryptoAuthLib Basic API methods for GenKey command.
#
# The GenKey command is used for creating ECC private keys, generating ECC
# public keys, and for digest calculations involving public keys.

def atcab_genkey_base(mode, key_id, other_data, public_key=None):
    """
    Issues GenKey command, which can generate a private key, compute a
    public key, nd/or compute a digest of a public key.

    Args:
        mode                Mode determines what operations the GenKey
                            command performs. (int)
        key_id              Slot to perform the GenKey command on. (int)
        other_data          OtherData for PubKey digest calculation. Can be set
                            to NULL otherwise. (bytearray or bytes)
        public_key          If the mode indicates a public key will be
                            calculated, it will be returned here. Format will
                            be the X and Y integers in big-endian format.
                            64 bytes for P256 curve. Set to NULL if public key
                            isn't required. (Expects bytearray of size 64 bytes)
    Returns:
        Status code
    """
    if public_key is None:
        status = get_cryptoauthlib().atcab_genkey_base(mode, key_id, bytes(other_data), None)
    elif not isinstance(public_key, bytearray):
        status = Status.ATCA_BAD_PARAM
    else:
        c_public_key = create_string_buffer(64)
        status = get_cryptoauthlib().atcab_genkey_base(mode, key_id, bytes(other_data), byref(c_public_key))
        public_key[0:] = bytes(c_public_key.raw)
    return status


def atcab_genkey(key_id, public_key):
    """
    Issues GenKey command, which generates a new random private key in
    slot and returns the public key.

    Args:
        key_id              Slot number where an ECC private key is configured.
                            Can also be ATCA_TEMPKEY_KEYID to generate a private
                            key in TempKey. (int)
        public_key          Public key will be returned here. Format will be
                            the X and Y integers in big-endian format.
                            64 bytes for P256 curve. Set to NULL if public key
                            isn't required. (Expects bytearray)

    Returns:
        Status code
    """
    c_public_key = create_string_buffer(64)

    if not isinstance(public_key, bytearray):
        status = Status.ATCA_BAD_PARAM
    else:
        status = get_cryptoauthlib().atcab_genkey(key_id, byref(c_public_key))
        public_key[0:] = bytes(c_public_key.raw)
    return status


def atcab_get_pubkey(key_id, public_key):
    """
    Uses GenKey command to calculate the public key from an existing
    private key in a slot.

    Args:
        key_id              Slot number of the private key. (int)
        public_key          Public key will be returned here. Format will be
                            the X and Y integers in big-endian format.
                            64 bytes for P256 curve. Set to NULL if public key
                            isn't required.(Expects bytearray)
    Returns:
        Status code
    """
    c_public_key = create_string_buffer(64)

    if not isinstance(public_key, bytearray):
        status = Status.ATCA_BAD_PARAM
    else:
        status = get_cryptoauthlib().atcab_get_pubkey(key_id, byref(c_public_key))
        public_key[0:] = bytes(c_public_key.raw)
    return status


# CryptoAuthLib Basic API methods for HMAC command.
#
# The HMAC command computes an HMAC/SHA-256 digest using a key stored in the
# device over a challenge stored in the TempKey register, and/or other
# information stored within the device.


def atcab_hmac(mode, key_id, digest):
    """
    Issues a HMAC command, which computes an HMAC/SHA-256 digest of a
    key stored in the device, a challenge, and other information on the
    device.

    Args:
        mode                Controls which fields within the device are used in the
                            message. (int)
        key_id              Which key is to be used to generate the response.
                            Bits 0:3 only are used to select a slot but all 16 bits
                            are used in the HMAC message. (int)
        digest              HMAC digest is returned in this buffer (32 bytes).
                            (Expects bytearray)
    Returns:
        Status code
    """
    c_digest = create_string_buffer(32)

    if not isinstance(digest, bytearray):
        status = Status.ATCA_BAD_PARAM
    else:
        status = get_cryptoauthlib().atcab_hmac(mode, key_id, byref(c_digest))
        digest[0:] = bytes(c_digest.raw)
    return status


# CryptoAuthLib Basic API methods for Info command.
#
# Info command returns a variety of static and dynamic information about the
# device and its state. Also is used to control the GPIO pin and the persistent
# latch.


def atcab_info_base(mode, param2, out_data):
    """
    Issues an Info command, which return internal device information and
    can control GPIO and the persistent latch.

    Args:
        mode                Selects which mode to be used for info command.(int)
        param2              Selects the particular fields for the mode.(int)
        out_data            Response from info command (4 bytes). Can be set to
                            NULL if not required.(Expects bytearray)

    Returns:
        Status
    """
    c_out_data = create_string_buffer(4)

    if not isinstance(out_data, bytearray):
        status = Status.ATCA_BAD_PARAM
    else:
        status = get_cryptoauthlib().atcab_info_base(mode, param2, byref(c_out_data))
        out_data[0:] = bytes(c_out_data.raw)
    return status


def atcab_info(revision):
    """
    Used to get the device revision number. (DevRev)

    Args:
        revision            4-byte bytearray receiving the revision number
                            from the device. (Expects bytearray)

    Returns:
        Status code
    """
    c_revision = create_string_buffer(4)
    if not isinstance(revision, bytearray):
        status = Status.ATCA_BAD_PARAM
    else:
        status = get_cryptoauthlib().atcab_info(byref(c_revision))
        revision[0:] = bytes(c_revision.raw)
    return status


def atcab_info_get_latch(state):
    """
    Using the Info command to get the persistent latch current state for
    an ATECC608 device.

    Args:
        state               The state is returned here. Set (True) or
                            clear (False). Expects AtcaReference.

    Returns:
        Status code
    """
    if not isinstance(state, AtcaReference):
        status = Status.ATCA_BAD_PARAM
    else:
        c_state = c_uint8(state.value)
        status = get_cryptoauthlib().atcab_info_get_latch(byref(c_state))
        state.value = c_state.value
    return status


def atcab_info_set_latch(state):
    """
    Use the Info command to set the persistent latch state for an
    ATECC608 device.

    Args:
        state               Persistent latch state. Set (True) or
                            clear (False).

    Returns:
        Status code
    """
    status = get_cryptoauthlib().atcab_info_set_latch(int(state))
    return status


# CryptoAuthLib Basic API methods for KDF command.
#
# The KDF command implements one of a number of Key Derivation Functions (KDF).
# Generally this function combines a source key with an input string and
# creates a result key/digest/array. Three algorithms are currently supported:
# PRF, HKDF and AES.


def atcab_kdf(mode, key_id, details, message, out_data, out_nonce):
    """
    Executes the KDF command, which derives a new key in PRF, AES, or
    HKDF modes. Generally this function combines a source key with an input
    string and creates a result key/digest/array.

    Args:
        mode            Mode determines KDF algorithm (PRF,AES,HKDF), source
                        key location, and target key locations. (int)
        key_id          Source and target key slots if locations are in the
                        EEPROM. Source key slot is the LSB and target key
                        slot is the MSB. (int)
        details         Further information about the computation, depending
                        on the algorithm. (int)
        message         Input value from system (up to 128 bytes). Actual size
                        of message is 16 bytes for AES algorithm or is encoded
                        in the MSB of the details parameter for other
                        algorithms.(bytearray or bytes)
        out_data        Output of the KDF function is returned here. If the
                        result remains in the device, this can be NULL.
                        (Expects bytearray)
        out_nonce       If the output is encrypted, a 32 byte random nonce
                        generated by the device is returned here. If output
                        encryption is not used, this can be NULL.
                        (Expects bytearray)

    Retuns:
        Status code
    """
    c_out_data = create_string_buffer(64)
    c_out_nonce = create_string_buffer(32)

    if (not isinstance(out_data, bytearray)) or (not isinstance(out_nonce, bytearray)):
        status = Status.ATCA_BAD_PARAM
    else:
        status = get_cryptoauthlib().atcab_kdf(mode, key_id, details, bytes(message),
                                               byref(c_out_data), byref(c_out_nonce))
        out_data[0:] = bytes(c_out_data.raw)
        out_nonce[0:] = bytes(c_out_nonce.raw)
    return status


# CryptoAuthLib Basic API methods for lock command.
#
# The Lock command prevents future modifications of the Configuration zone,
# enables configured policies for Data and OTP zones, and can render
# individual slots read-only regardless of configuration.


def atcab_lock(mode, summary_crc):
    """
    The Lock command prevents future modifications of the Configuration
    and/or Data and OTP zones. If the device is so configured, then
    this command can be used to lock individual data slots. This
    command fails if the designated area is already locked.

    Args:
        mode                Zone, and/or slot, and summary check (bit 7).(int)
        summary_crc         CRC of the config or data zones. Ignored for
                            slot locks or when mode bit 7 is set. (int)

    Returns:
        Status code
    """
    status = get_cryptoauthlib().atcab_lock(mode, summary_crc)
    return status


def atcab_lock_config_zone():
    """
    Unconditionally (no CRC required) lock the config zone.

    Args:
        None

    Returns:
        Status code
    """
    status = get_cryptoauthlib().atcab_lock_config_zone()
    return status


def atcab_lock_config_zone_crc(summary_crc):
    """
    Lock the config zone with summary CRC.

    The CRC is calculated over the entire config zone contents. 88 bytes for
    ATSHA devices, 128 bytes for ATECC devices. Lock will fail if the provided
    CRC doesn't match the internally calculated one.

    Args:
        summary_crc         Expected CRC over the config zone. (int)

    Returns:
        Status code
    """
    status = get_cryptoauthlib().atcab_lock_config_zone_crc(summary_crc)
    return status


def atcab_lock_data_zone():
    """
    Unconditionally (no CRC required) lock the data zone (slots and OTP).

    ConfigZone must be locked and DataZone must be unlocked for the
    zone to be successfully locked.

    Args:
        None

    Returns:
        Status code
    """
    status = get_cryptoauthlib().atcab_lock_data_zone()
    return status


def atcab_lock_data_zone_crc(summary_crc):
    """
    Lock the data zone (slots and OTP) with summary CRC.

    The CRC is calculated over the concatenated contents of all the slots and
    OTP at the end. Private keys (KeyConfig.Private=1) are skipped. Lock will
    fail if the provided CRC doesn't match the internally calculated one.

    Args:
        summary_crc         Expected CRC over the config zone. (int)

    Returns:
        Status code
    """
    status = get_cryptoauthlib().atcab_lock_data_zone_crc(summary_crc)
    return status


def atcab_lock_data_slot(slot):
    """
    Lock an individual slot in the data zone on an ATECC device. Not
    available for ATSHA devices. Slot must be configured to be slot
    lockable (KeyConfig.Lockable=1).

    Args:
        slot                Slot to be locked in data zone. (int)

    Returns:
        Status code
    """
    status = get_cryptoauthlib().atcab_lock_data_slot(slot)
    return status


# CryptoAuthLib Basic API methods for MAC command.
#
# The MAC command computes a SHA-256 digest of a key stored in the device, a
# challenge, and other information on the device. The output of this command
# is the digest of this message.


def atcab_mac(mode, key_id, challenge, digest):
    """
    Executes MAC command, which computes a SHA-256 digest of a key
    stored in the device, a challenge, and other information on the
    device.

    Args:
        mode                Controls which fields within the device are used in
                            the message (int)
        key_id              Key in the CryptoAuth device to use for the MAC (int)
        challenge           Challenge message (32 bytes). May be NULL if mode
                            indicates a challenge isn't required. (bytearray or bytes)
        digest              MAC response is returned here (32 bytes). (Expects bytearray)

    Returns:
        Status code
    """
    c_digest = create_string_buffer(32)

    if not isinstance(digest, bytearray):
        status = Status.ATCA_BAD_PARAM
    else:
        status = get_cryptoauthlib().atcab_mac(mode, key_id, bytes(challenge), byref(c_digest))
        digest[0:] = bytes(c_digest.raw)
    return status


# CryptoAuthLib Basic API methods for Nonce command.
#
# The Nonce command generates a nonce for use by a subsequent commands of the
# device by combining an internally generated random number with an input value
# from the system.


def atcab_nonce_base(mode, zero, num_in, rand_out):
    """
    Executes Nonce command, which loads a random or fixed nonce/data
    into the device for use by subsequent commands.

    Args:
        mode                Controls the mechanism of the internal RNG or fixed
                            write. (int)
        zero                Param2, normally 0, but can be used to indicate a
                            nonce calculation mode (bit 15). (int)
        num_in              Input value to either be included in the nonce
                            calculation in random modes (20 bytes) or to be
                            written directly (32 bytes or 64 bytes(ATECC608))
                            in pass-through mode. (bytearray or bytes)
        rand_out            If using a random mode, the internally generated
                            32-byte random number that was used in the nonce
                            calculation is returned here. Can be NULL if not
                            needed. (Expects bytearray)

    Returns:
        Status code
    """
    c_rand_out = create_string_buffer(32)
    if not isinstance(rand_out, bytearray):
        status = Status.ATCA_BAD_PARAM
    else:
        status = get_cryptoauthlib().atcab_nonce_base(mode, zero, bytes(num_in), byref(c_rand_out))
        rand_out[0:] = bytes(c_rand_out.raw)
    return status


def atcab_nonce(num_in):
    """
    Execute a Nonce command in pass-through mode to initialize TempKey
    to a specified value.

    Args:
        num_in              Data to be loaded into TempKey (32 bytes).
                            (bytearray or bytes)

    Returns:
        None
    """
    status = get_cryptoauthlib().atcab_nonce(bytes(num_in))
    return status


def atcab_nonce_load(target, num_in, num_in_size):
    """
    Execute a Nonce command in pass-through mode to load one of the
    device's internal buffers with a fixed value.

    For the ATECC608, available targets are TempKey (32 or 64 bytes), Message
    Digest Buffer (32 or 64 bytes), or the Alternate Key Buffer (32 bytes). For
    all other devices, only TempKey (32 bytes) is available.

    Args:
        target              Target device buffer to load. Can be
                            NONCE_MODE_TARGET_TEMPKEY,
                            NONCE_MODE_TARGET_MSGDIGBUF, or
                            NONCE_MODE_TARGET_ALTKEYBUF.(int)
        num_in              Data to load into the buffer.(bytearray or bytes)
        num_in_size         Size of num_in in bytes. Can be 32 or 64 bytes
                            depending on device and target. (int)

    Returns:
        Status code
    """
    status = get_cryptoauthlib().atcab_nonce_load(target, bytes(num_in), num_in_size)
    return status


def atcab_nonce_rand(num_in, rand_out):
    """
    Execute a Nonce command to generate a random nonce combining a host
    nonce (num_in) and a device random number.

    Args:
        num_in              Host nonce to be combined with the device random
                            number (20 bytes). (bytearray or bytes)
        rand_out            Internally generated 32-byte random number that was
                            used in the nonce/challenge calculation is returned
                            here. Can be NULL if not needed.(Expects bytearray)

    Returns:
        Status code
    """
    c_rand_out = create_string_buffer(32)
    if not isinstance(rand_out, bytearray):
        status = Status.ATCA_BAD_PARAM
    else:
        status = get_cryptoauthlib().atcab_nonce_rand(bytes(num_in), byref(c_rand_out))
        rand_out[0:] = bytes(c_rand_out.raw)
    return status


def atcab_challenge(num_in):
    """
    Execute a Nonce command in pass-through mode to initialize TempKey
    to a specified value.

    Args:
        num_in              Data to be loaded into TempKey (32 bytes).
                            (bytearray or bytes)

    Returns:
        Status Code
    """
    status = get_cryptoauthlib().atcab_challenge(bytes(num_in))
    return status


def atcab_challenge_seed_update(num_in, rand_out):
    """
    Execute a Nonce command to generate a random challenge combining
    a host nonce (num_in) and a device random number.

    Args:
        num_in              Host nonce to be combined with the device random
                            number (20 bytes). (bytearray or bytes)
        rand_out            Internally generated 32-byte random number that was
                            used in the nonce/challenge calculation is returned
                            here. Can be NULL if not needed. (Expects bytearray)

    Returns:
        Status code
    """
    c_rand_out = create_string_buffer(32)
    if not isinstance(rand_out, bytearray):
        status = Status.ATCA_BAD_PARAM
    else:
        status = get_cryptoauthlib().atcab_challenge_seed_update(bytes(num_in), byref(c_rand_out))
        rand_out[0:] = bytes(c_rand_out.raw)
    return status


# CryptoAuthLib Basic API methods for PrivWrite command.
#
# The PrivWrite command is used to write externally generated ECC private keys
# into the device.


def atcab_priv_write(key_id, priv_key, write_key_id, write_key, num_in=None):
    """
    Executes PrivWrite command, to write externally generated ECC
    private keys into the device.

    Args:
        key_id              Slot to write the external private key into. (int)
        priv_key            External private key (36 bytes) to be written.
                            The first 4 bytes should be zero for P256 curve.
                            (bytearray or bytes)
        write_key_id        Write key slot. Ignored if write_key is NULL.(int)
        write_key           Write key (32 bytes). If NULL, perform an
                            unencrypted PrivWrite, which is only available when
                            the data zone is unlocked. (bytearray or bytes)
        num_in              Bytearray - Host nonce used to calculate nonce (20 bytes)
    Returns:
        Status code
    """
    if num_in is None:
        num_in = bytearray(20)

    status = get_cryptoauthlib().atcab_priv_write(key_id, bytes(priv_key), write_key_id, bytes(write_key),
                                                  bytes(num_in))
    return status


# CryptoAuthLib Basic API methods for Random command.
#
# The Random command generates a random number for use by the system.


def atcab_random(random_number):
    """
    Generates a 32 byte random number. Note that if the configuration zone
    isn't locked yet (LockConfig) then it will return a 0xFFFF0000 repeating
    pattern instead.

    Args:
        random_number       Random number is returned here (expects bytearray)

    Returns:
        Status code
    """
    c_random_number = create_string_buffer(32)
    if not isinstance(random_number, bytearray):
        status = Status.ATCA_BAD_PARAM
    else:
        status = get_cryptoauthlib().atcab_random(byref(c_random_number))
        random_number[0:] = bytes(c_random_number.raw)
    return status


# CryptoAuthLib Basic API methods for read command.
#
# The Read command reads words either 4-byte words or 32-byte blocks from one
# of the memory zones of the device. The data may optionally be encrypted
# before being returned to the system.


def atcab_read_zone(zone, slot, block, offset, data, length):
    """
    Executes Read command, which reads either 4 or 32 bytes of data from
    a given slot, configuration zone, or the OTP zone.

    When reading a slot or OTP, data zone must be locked and the slot
    configuration must not be secret for a slot to be successfully read.

    Args:
        zone                Zone to be read from device. Options are
                            ATCA_ZONE_CONFIG, ATCA_ZONE_OTP, or ATCA_ZONE_DATA.(int)
        slot                Slot number for data zone and ignored for other zones. (int)
        block               32 byte block index within the zone. (int)
        offset              4 byte work index within the block. Ignored for 32 byte
                            reads. (Expects bytearray)
        length              Length of the data to be read. Must be either 4 or 32.
        data                Read data is returned here. (Expects bytearray)

    Returns:
        Status code
    """
    c_data = create_string_buffer(32)
    if not isinstance(data, bytearray):
        status = Status.ATCA_BAD_PARAM
    else:
        status = get_cryptoauthlib().atcab_read_zone(zone, slot, block, offset, byref(c_data), length)
        data[0:] = bytes(c_data.raw)
    return status


def atcab_read_serial_number(serial_number):
    """
    Executes Read command, which reads the 9 byte serial number of the
    device from the config zone.

    Args:
        serial_number       9 byte serial number is returned here.
                            (Expects bytearray)

    Returns:
        Status code
    """
    c_serial_number = create_string_buffer(9)
    if not isinstance(serial_number, bytearray):
        status = Status.ATCA_BAD_PARAM
    else:
        status = get_cryptoauthlib().atcab_read_serial_number(byref(c_serial_number))
        serial_number[0:] = bytes(c_serial_number.raw)
    return status


def atcab_is_slot_locked(slot, is_locked):
    """
    Executes Read command, which reads the configuration zone to see if
    the specified slot is locked.

    Args:
        slot                Slot to query for locked (slot 0-15) (int)
        is_locked           Lock state returned here. True if locked.
                            (Expects AtcaReference)

    Returns:
        Status code
    """
    if not isinstance(is_locked, AtcaReference):
        status = Status.ATCA_BAD_PARAM
    else:
        c_is_locked = c_uint8(is_locked.value)
        status = get_cryptoauthlib().atcab_is_slot_locked(slot, byref(c_is_locked))
        is_locked.value = c_is_locked.value
    return status


def atcab_is_locked(zone, is_locked):
    """
    Executes Read command, which reads the configuration zone to see if
    the specified slot is locked.

    Args:
        zone                The zone to query for locked (use LOCK_ZONE_CONFIG(0x00) or
                            LOCK_ZONE_DATA(0x01) ). (int)
        is_locked           Lock state returned here. True if locked.
                            (Expects AtcaReference)

    Returns:
        Status code
    """
    if not isinstance(is_locked, AtcaReference):
        status = Status.ATCA_BAD_PARAM
    else:
        c_is_locked = c_bool(is_locked.value)
        status = get_cryptoauthlib().atcab_is_locked(zone, byref(c_is_locked))
        is_locked.value = c_is_locked.value
    return status


def atcab_read_enc(key_id, block, data, enc_key, enc_key_id, num_in=None):
    """
    Executes Read command on a slot configured for encrypted reads and
    decrypts the data to return it as plaintext.

    Data zone must be locked for this command to succeed. Can only read 32 byte
    blocks.

    Args:
        key_id              The slot ID to read from. (int)
        block               Index of the 32 byte block within the slot to read. (int)
        enc_key             32 byte ReadKey for the slot being read.(bytearray or bytes)
        enc_key_id          KeyID of the ReadKey being used.(int)
        data                Decrypted (plaintext) data from the read is returned
                            here (32 bytes). (Expects bytearray)
        num_in              Bytearray - Host nonce used to calculate nonce (20 byte)
    Returns:
        Status code
    """
    c_data = create_string_buffer(32)
    if num_in is None:
        num_in = bytearray(20)

    if not isinstance(data, bytearray):
        status = Status.ATCA_BAD_PARAM
    else:
        status = get_cryptoauthlib().atcab_read_enc(key_id, block, byref(c_data), bytes(enc_key), enc_key_id,
                                                    bytes(num_in))
        data[0:] = bytes(c_data.raw)
    return status


def atcab_read_config_zone(config_data):
    """
    Executes Read command to read the complete device configuration
    zone.

    Args:
        config_data         Configuration zone data is returned here. 88 bytes
                            for ATSHA devices, 128 bytes for ATECC devices.
                            (Expects bytearray)

    Returns:
        Status code
    """
    c_config_data = create_string_buffer(128)
    if not isinstance(config_data, bytearray):
        status = Status.ATCA_BAD_PARAM
    else:
        status = get_cryptoauthlib().atcab_read_config_zone(byref(c_config_data))
        config_data[0:] = bytes(c_config_data.raw)
    return status


def atcab_cmp_config_zone(config_data, same_config):
    """
    Compares a specified configuration zone with the configuration zone
    currently on the device.

    This only compares the static portions of the configuration zone and skips
    those that are unique per device (first 16 bytes) and areas that can change
    after the configuration zone has been locked (e.g. LastKeyUse).

    Args:
        config_data         Full configuration data to compare the device
                            against. (bytearray or bytes)
        same_config         Result is returned here. True if the static portions
                            on the configuration zones are the same.
                            (Expects AtcaReference)

    Returns:
        Status code
    """
    if not isinstance(same_config, AtcaReference):
        status = Status.ATCA_BAD_PARAM
    else:
        c_same_config = c_uint8(same_config.value)
        status = get_cryptoauthlib().atcab_cmp_config_zone(bytes(config_data), byref(c_same_config))
        same_config.value = c_same_config.value
    return status


def atcab_read_sig(slot, sig):
    """
    Executes Read command to read a 64 byte ECDSA P256 signature from a
    slot configured for clear reads.

    Args:
        slot                Slot number to read from. Only slots 8 to 15 are large
                            enough for a signature. (int)
        sig                 Signature will be returned here (64 bytes). Format will be
                            the 32 byte R and S big-endian integers concatenated.
                            (Expects bytearray)

    Returns:
        Status code
    """
    c_sig = create_string_buffer(64)
    if not isinstance(sig, bytearray):
        status = Status.ATCA_BAD_PARAM
    else:
        status = get_cryptoauthlib().atcab_read_sig(slot, byref(c_sig))
        sig[0:] = bytes(c_sig.raw)
    return status


def atcab_read_pubkey(slot, public_key):
    """
    Executes Read command to read an ECC P256 public key from a slot
    configured for clear reads.

    This function assumes the public key is stored using the ECC public key
    format specified in the datasheet.

    Args:
        slot                Slot number to read from. Only slots 8 to 15 are
                            large enough for a public key. (int)
        public_key          Public key is returned here (64 bytes). Format will
                            be the 32 byte X and Y big-endian integers
                            concatenated. (Expects bytearray)
    Returns:
        Status code
    """
    c_public_key = create_string_buffer(64)
    if not isinstance(public_key, bytearray):
        status = Status.ATCA_BAD_PARAM
    else:
        status = get_cryptoauthlib().atcab_read_pubkey(slot, byref(c_public_key))
        public_key[0:] = bytes(c_public_key.raw)
    return status


def atcab_read_bytes_zone(zone, slot, offset, data, length):
    """
    Used to read an arbitrary number of bytes from any zone configured
    for clear reads.

    This function will issue the Read command as many times as is required to
    read the requested data.

    Args:
        zone                Zone to read data from. Option are ATCA_ZONE_CONFIG(0),
                            ATCA_ZONE_OTP(1), or ATCA_ZONE_DATA(2). (int)
        slot                Slot number to read from if zone is ATCA_ZONE_DATA(2).
                            Ignored for all other zones. (int)
        offset              Byte offset within the zone to read from. (int)
        length              Number of bytes to read starting from the offset.(int)
        data                Read data is returned here. (Expects bytearray)

    Returns:
        Status code
    """
    c_data = create_string_buffer(length)
    if not isinstance(data, bytearray):
        status = Status.ATCA_BAD_PARAM
    else:
        status = get_cryptoauthlib().atcab_read_bytes_zone(zone, slot, offset, byref(c_data), length)
        data[0:] = bytes(c_data.raw)
    return status


# CryptoAuthLib Basic API methods for secureboot command.
#
# The SecureBoot command provides support for secure boot of an external MCU
# or MPU.


def atcab_secureboot(mode, param2, digest, signature, mac):
    """
    Executes Secure Boot command, which provides support for secure
    boot of an external MCU or MPU.

    Args:
        mode                Mode determines what operations the SecureBoot
                            command performs. (int)
        param2              Not used, must be 0. (int)
        digest              Digest of the code to be verified (32 bytes).
                            (bytearray or bytes)
        signature           Signature of the code to be verified (64 bytes). Can
                            be NULL when using the FullStore mode. (bytearray or bytes)
        mac                 Validating MAC will be returned here (32 bytes). Can
                            be NULL if not required. (Expects bytearray)

    Return:
        Status code
    """
    c_mac = create_string_buffer(32)
    if not isinstance(mac, bytearray):
        status = Status.ATCA_BAD_PARAM
    else:
        status = get_cryptoauthlib().atcab_secureboot(mode, param2, bytes(digest), bytes(signature), byref(c_mac))
        mac[0:] = bytes(c_mac.raw)
    return status


def atcab_secureboot_mac(mode, digest, signature, num_in, io_keys, is_verified):
    """
    Executes Secure Boot command with encrypted digest and validated
    MAC response using the IO protection key.

    Args:
        mode                Mode determines what operations the SecureBoot
                            command performs. (int)
        digest              Digest of the code to be verified (32 bytes).
                            This is the plaintext digest (not encrypted).
                            (bytearray or bytes)
        signature           Signature of the code to be verified (64 bytes). Can
                            be NULL when using the FullStore mode.
                            (bytearray or bytes)
        num_in              Host nonce (20 bytes).(bytearray or bytes)
        io_key              IO protection key (32 bytes). (bytearray or bytes)
        is_verified         Verify result is returned here. (Expects
                            AtcaReference)

    Returns:
        Status code
    """
    if not isinstance(is_verified, AtcaReference):
        status = Status.ATCA_BAD_PARAM
    else:
        c_is_verified = c_uint8(is_verified.value)
        status = get_cryptoauthlib().atcab_secureboot_mac(mode, bytes(digest), bytes(signature),
                                                          bytes(num_in), bytes(io_keys), byref(c_is_verified))
        is_verified.value = c_is_verified.value
    return status


# CryptoAuthLib Basic API methods for SelfTest command.
#
# The SelfTest command performs a test of one or more of the cryptographic
# engines within the device.


def atcab_selftest(mode, param2, result):
    """
    Executes the SelfTest command, which performs a test of one or more
    of the cryptographic engines within the ATECC608 chip.

    Args:
        mode                Functions to test. Can be a bit field combining any
                            of the following: SELFTEST_MODE_RNG,
                            SELFTEST_MODE_ECDSA_VERIFY, SELFTEST_MODE_ECDSA_SIGN,
                            SELFTEST_MODE_ECDH, SELFTEST_MODE_AES,
                            SELFTEST_MODE_SHA, SELFTEST_MODE_ALL. (int)
        param2              Currently unused, should be 0. (int)
        result              Results are returned here as a bit field. (Expects
                            AtcaReference)

    Returns:
        Status code
    """
    if not isinstance(result, AtcaReference):
        status = Status.ATCA_BAD_PARAM
    else:
        c_result = c_uint8(result.value)
        status = get_cryptoauthlib().atcab_selftest(mode, param2, byref(c_result))
        result.value = c_result.value
    return status


# CryptoAuthLib Basic API methods for SHA command.
#
# The SHA command Computes a SHA-256 or HMAC/SHA digest for general purpose
# use by the host system.


def atcab_sha_base(mode, length, message, data_out, data_out_size):
    """
    Executes SHA command, which computes a SHA-256 or HMAC/SHA-256
    digest for general purpose use by the host system.

    Only the Start(0) and Compute(1) modes are available for ATSHA devices.

    Args:
        mode                SHA command mode Start(0), Update/Compute(1),
                            End(2), Public(3), HMACstart(4), HMACend(5),
                            Read_Context(6), or Write_Context(7). Also
                            message digest target location for the
                            ATECC608. (int)
        length              Number of bytes in the message parameter or
                            KeySlot for the HMAC key if Mode is
                            HMACstart(4) or Public(3). (int)
        message             Message bytes to be hashed or Write_Context if
                            restoring a context on the ATECC608. Can be
                            NULL if not required by the mode.
                            (bytearray or bytes)
        data_out            Data returned by the command (digest or
                            context).(Expects bytearray)
        data_out_size       As input, the size of the data_out buffer. As
                            output, the number of bytes returned in
                            data_out. (Expects AtcaReference)

    Returns:
        Status code
    """
    if (not isinstance(data_out, bytearray)) or (not isinstance(data_out_size, AtcaReference)):
        status = Status.ATCA_BAD_PARAM
    else:
        c_data_out_size = c_uint8(data_out_size.value)
        c_data_out = create_string_buffer(data_out_size.value)
        status = get_cryptoauthlib().atcab_sha_base(mode, length, bytes(message),
                                                    byref(c_data_out), byref(c_data_out_size))
        data_out[:] = bytes(c_data_out.raw)[0:c_data_out_size.value]
        data_out_size.value = c_data_out_size.value
    return status


def atcab_sha_start():
    """
    Executes SHA command to initialize SHA-256 calculation engine

    Args:
        None

    Returns;
        Status code
    """
    status = get_cryptoauthlib().atcab_sha_start()
    return status


def atcab_sha_update(message):
    """
    Executes SHA command to add 64 bytes of message data to the current
    context.

    Args:
        message             64 bytes of message data to add to add to operation.
                            (Expects bytearray)

    Returns:
        Status code
    """
    status = get_cryptoauthlib().atcab_sha_update(bytes(message))
    return status


def atcab_sha_end(digest, length, message):
    """
    Executes SHA command to complete SHA-256 or HMAC/SHA-256 operation.

    Args:
        length              Length of any remaining data to include in hash. Max 64
                            bytes.(int)
        message             Remaining data to include in hash. NULL if length is 0. (bytearray or bytes)
        digest              Digest from SHA-256 or HMAC/SHA-256 will be returned
                            here (32 bytes). (Expects bytearray)

    Returns:
        Status code
    """
    if not isinstance(digest, bytearray):
        status = Status.ATCA_BAD_PARAM
    else:
        c_digest = create_string_buffer(32)
        status = get_cryptoauthlib().atcab_sha_end(byref(c_digest), length, bytes(message))
        digest[0:] = bytes(c_digest.raw)
    return status


def atcab_sha_read_context(context, context_size):
    """
    Executes SHA command to read the SHA-256 context back. Only for
    ATECC608 with SHA-256 contexts. HMAC not supported.

    Args:
        context             Context data is returned here. (Expects bytearray)
        context_size        As input, the size of the context buffer in
                            bytes. As output, the size of the returned
                            context data. (Expects AtcaReference)

    Retuns:
        Status code
    """
    if (not isinstance(context, bytearray)) or (not isinstance(context_size, AtcaReference)):
        status = Status.ATCA_BAD_PARAM
    else:
        c_context_size = c_uint8(context_size.value)
        c_context = create_string_buffer(context_size.value)
        status = get_cryptoauthlib().atcab_sha_read_context(byref(c_context), byref(c_context_size))
        context[:] = bytes(c_context.raw)[0:c_context_size.value]
        context_size.value = c_context_size.value
    return status


def atcab_sha_write_context(context, context_size):
    """
    Executes SHA command to write (restore) a SHA-256 context into the
    the device. Only supported for ATECC608 with SHA-256 contexts.

    Args:
        context             Context data to be restored. (bytearray or bytes)
        context_size        Size of the context data in bytes. (int)

    Returns:
        Status code
    """
    status = get_cryptoauthlib().atcab_sha_write_context(bytes(context), context_size)
    return status


def atcab_sha(length, message, digest):
    """
    Use the SHA command to compute a SHA-256 digest.

    Args:
        length              Size of message parameter in bytes. (int)
        message             Message data to be hashed. (bytearray or bytes)
        digest              Digest is returned here (32 bytes). (Expects bytearray)

    Returns:
        Status code
    """
    if not isinstance(digest, bytearray):
        status = Status.ATCA_BAD_PARAM
    else:
        c_digest = create_string_buffer(32)
        status = get_cryptoauthlib().atcab_sha(length, bytes(message), byref(c_digest))
        digest[0:] = bytes(c_digest.raw)
    return status


def atcab_hw_sha2_256_init(ctx):
    """
    Initialize a SHA context for performing a hardware SHA-256 operation
    on a device. Note that only one SHA operation can be run at a time.

    Args:
        ctx                     SHA256 context (atca_sha256_ctx)

    Returns:
        Status code
    """
    status = get_cryptoauthlib().atcab_hw_sha2_256_init(byref(ctx))
    return status


def atcab_hw_sha2_256_update(ctx, data, data_size):
    """
    --> Add message data to a SHA context for performing a hardware SHA-256
        operation on a device.

    Args:
        ctx                 SHA256 context (atca_sha256_ctx)
        data                Message data to be added to hash. (bytearray or bytes)
        data_size           Size of data in bytes. (int)

    Returns:
        Status code
    """
    status = get_cryptoauthlib().atcab_hw_sha2_256_update(byref(ctx), bytes(data), data_size)
    return status


def atcab_hw_sha2_256_finish(ctx, digest):
    """
    Finish SHA-256 digest for a SHA context for performing a hardware
    SHA-256 operation on a device.

    Args:
    ctx                     SHA256 context (atca_sha256_ctx)
    digest                  SHA256 digest is returned here (32 bytes)
                            (Expects bytearray)

    Returns:
        Status code
    """
    if not isinstance(digest, bytearray):
        status = Status.ATCA_BAD_PARAM
    else:
        c_digest = create_string_buffer(32)
        status = get_cryptoauthlib().atcab_hw_sha2_256_finish(byref(ctx), byref(c_digest))
        digest[0:] = bytes(c_digest.raw)
    return status


def atcab_hw_sha2_256(data, data_size, digest):
    """
    Use the SHA command to compute a SHA-256 digest.

    Args:
        data                Message data to be hashed. (bytearray or bytes)
        data_size           Size of data in bytes. (int)
        digest              Digest is returned here (32 bytes).
                            (Expects bytearray)

    Returns:
        Status code
    """
    if not isinstance(digest, bytearray):
        status = Status.ATCA_BAD_PARAM
    else:
        c_digest = create_string_buffer(32)
        status = get_cryptoauthlib().atcab_hw_sha2_256(bytes(data), data_size, byref(c_digest))
        digest[0:] = bytes(c_digest.raw)
    return status


def atcab_sha_hmac_init(ctx, key_slot):
    """
    Executes SHA command to start an HMAC/SHA-256 operation

    Args:
        ctx                 HMAC/SHA-256 context (atca_hmac_sha256_ctx_t)
        key_slot            Slot key id to use for the HMAC calculation (int)

    Returns:
        Status code
    """
    status = get_cryptoauthlib().atcab_sha_hmac_init(bytes(ctx), key_slot)
    return status


def atcab_sha_hmac_update(ctx, data, data_size):
    """
    Executes SHA command to add an arbitrary amount of message data to
    a HMAC/SHA-256 operation.

    Args:
        ctx                 HMAC/SHA-256 context (atca_hmac_sha256_ctx_t)
        data                Message data to add (bytearray or bytes)
        data_size           Size of message data in bytes (int)

    Returns:
        Status code
    """
    status = get_cryptoauthlib().atcab_sha_hmac_update(byref(ctx), bytes(data), data_size)
    return status


def atcab_sha_hmac_finish(ctx, digest, target):
    """
    Executes SHA command to complete a HMAC/SHA-256 operation.

    Args:
        ctx                 HMAC/SHA-256 context (atca_hmac_sha256_ctx_t)
        target              Where to save the digest internal to the device.
                            For ATECC608, can be SHA_MODE_TARGET_TEMPKEY,
                            SHA_MODE_TARGET_MSGDIGBUF, or SHA_MODE_TARGET_OUT_ONLY.
                            For all other devices, SHA_MODE_TARGET_TEMPKEY is the
                            only option. (int)
        digest              HMAC/SHA-256 result is returned here (32 bytes).
                            (Expects bytearray)

    Returns:
        Status code
    """
    if not isinstance(digest, bytearray):
        status = Status.ATCA_BAD_PARAM
    else:
        c_digest = create_string_buffer(32)
        status = get_cryptoauthlib().atcab_sha_hmac_finish(byref(ctx), byref(c_digest), target)
        digest[0:] = bytes(c_digest.raw)
    return status


def atcab_sha_hmac(data, data_size, key_slot, digest, target):
    """
    Use the SHA command to compute an HMAC/SHA-256 operation.

    Args:
        data                Message data to be hashed. (bytearray or bytes)
        data_size           Size of data in bytes. (int)
        key_slot            Slot key id to use for the HMAC calculation (int)
        target              Where to save the digest internal to the device.
                            For ATECC608, can be SHA_MODE_TARGET_TEMPKEY,
                            SHA_MODE_TARGET_MSGDIGBUF, or
                            SHA_MODE_TARGET_OUT_ONLY. For all other devices,
                            SHA_MODE_TARGET_TEMPKEY is the only option. (int)
        digest              Digest is returned here (32 bytes).
                            (Expects bytearray)

    Return:
        Status code
    """
    if not isinstance(digest, bytearray):
        status = Status.ATCA_BAD_PARAM
    else:
        c_digest = create_string_buffer(32)
        status = get_cryptoauthlib().atcab_sha_hmac(bytes(data), data_size, key_slot, byref(c_digest), target)
        digest[0:] = bytes(c_digest.raw)
    return status


# CryptoAuthLib Basic API methods for Sign command.
#
# The Sign command generates a signature using the private key in slot with
# ECDSA algorithm.


def atcab_sign_base(mode, key_id, signature):
    """
    Executes the Sign command, which generates a signature using the ECDSA algorithm.

    Args:
        mode            Mode determines what the source of the message to be signed (int)
        key_id          Private key slot used to sign the message. (int)
        signature       Signature is returned here. Format is R and S integers in
                        big-endian format. 64 bytes for P256 curve (Expects bytearray)

    Returns:
        Stauts code
    """
    if not isinstance(signature, bytearray):
        status = Status.ATCA_BAD_PARAM
    else:
        c_signature = create_string_buffer(64)
        status = get_cryptoauthlib().atcab_sign_base(mode, key_id, byref(c_signature))
        signature[0:] = bytes(c_signature.raw)
    return status


def atcab_sign(key_id, msg, signature):
    """
    Executes Sign command, to sign a 32-byte external message using the private key
    in the specified slot. The message to be signed will be loaded into the Message
    Digest Buffer to the ATECC608 device or TempKey for other devices.

    Args:
        key_id          Slot of the private key to be used to sign the message (int)
        msg             32-byte message to be signed. Typically the SHA256 hash
                        of the full message. (bytearray or bytes)
        signature       Signature will be returned here. Format is R and S integers in
                        big-endian format. 64 bytes for P256 curve. (Expects bytearray)

    Returns:
        Status code
    """
    c_signature = create_string_buffer(64)
    if not isinstance(signature, bytearray):
        status = Status.ATCA_BAD_PARAM
    else:
        status = get_cryptoauthlib().atcab_sign(key_id, bytes(msg), byref(c_signature))
        signature[0:] = bytes(c_signature.raw)
    return status


def atcab_sign_internal(key_id, is_invalidate, is_full_sn, signature):
    """
    Executes Sign command to sign an internally generated message.

    Args:
        key_id              Slot of the private key to be used to sign the message (int)
        is_invalidate       Set to true if the signature will be used with the Verify(Invalidate)
                            command. false for all other cases.
        is_full_sn          Set to true if the message should incorporate the device's
                            full serial number.
        signature           Signature is returned here. Format is R and S integers in
                            big-endian format. 64 bytes for P256 curve (Expects bytearray)

    Returns:
        Status code
    """
    c_signature = create_string_buffer(64)
    if not isinstance(signature, bytearray):
        status = Status.ATCA_BAD_PARAM
    else:
        status = get_cryptoauthlib().atcab_sign_internal(key_id, int(is_invalidate), int(is_full_sn),
                                                         byref(c_signature))
        signature[0:] = bytes(c_signature.raw)
    return status


# Executes UpdateExtra command to update the values of the two
# extra bytes within the Configuration zone (bytes 84 and 85).
#
# Can also be used to decrement the limited use counter associated with the
# key in slot NewValue.


def atcab_updateextra(mode, new_value):
    """
    Executes UpdateExtra command to update the values of the two extra bytes within
    the Configuration zone (bytes 84 and 85). an also be used to decrement the limited
    use counter associated with the key in slot NewValue.

    Args:
        mode        Mode determines what operations the UpdateExtra command performs. (int)
        new_value   Value to be written. (int)

    Returns:
        Status code
    """
    status = get_cryptoauthlib().atcab_updateextra(mode, new_value)
    return status


# CryptoAuthLib Basic API methods for Verify command.
#
# The Verify command takes an ECDSA [R,S] signature and verifies that it is
# correctly generated given an input message digest and public key.


def atcab_verify(mode, key_id, signature, public_key, other_data, mac):
    """
    Executes the Verify command, which takes an ECDSA [R,S] signature and verifies that
    it is correctly generated from a given message and public key. In all cases, the
    signature is an input to the command. For the Stored, External, and ValidateExternal
    Modes, the contents of TempKey (or Message Digest Buffer in some cases for the
    ATECC608) should contain the 32 byte message.

    Args:
        mode                Verify command mode and options (int)
        key_id              Stored mode, the slot containing the public key to be
                            used for the verification. ValidateExternal mode, the
                            slot containing the public key to be validated. External
                            mode, KeyID contains the curve type to be used to Verify
                            the signature. Validate or Invalidate mode, the slot
                            containing the public key to be (in)validated.(int)
        signature           Signature to be verified. R and S integers in
                            big-endian format. 64 bytes for P256 curve.
                            (bytearray or bytes)
        public_key          If mode is External, the public key to be used for
                            verification. X and Y integers in big-endian format.
                            64 bytes for P256 curve. NULL for all other modes.
                            (bytearray or bytes)
        other_data          If mode is Validate, the bytes used to generate the
                            message for the validation (19 bytes). NULL for all other modes.
                            (bytearray or bytes)
        mac                 If mode indicates a validating MAC, then the MAC will
                            be returned here. Can be NULL otherwise.
                            (Expects bytearray)

    Returns:
        Status code
    """
    if not isinstance(mac, bytearray):
        status = Status.ATCA_BAD_PARAM
    else:
        c_mac = create_string_buffer(64)
        status = get_cryptoauthlib().atcab_verify(mode, key_id, bytes(signature), bytes(public_key),
                                                  bytes(other_data), byref(c_mac))
        mac[0:] = bytes(c_mac.raw)
    return status


def atcab_verify_extern_stored_mac(mode, key_id, message, signature, public_key, num_in, io_key, is_verified):
    """
    Executes the Verify command with verification MAC for the External or Stored Verify modes..

    Args:
        mode                Verify command mode. Can be VERIFY_MODE_EXTERNAL or
                            VERIFY_MODE_STORED. (int)
        key_id              For VERIFY_MODE_STORED mode, the slot containing the public key
                            to be used for the verification. For VERIFY_MODE_EXTERNAL mode,
                            KeyID contains the curve type to be used to Verify the signature.
                            Only VERIFY_KEY_P256 supported. (int)
        message             32 byte message to be verified. Typically the SHA256 hash of the
                            full message. (bytearray or bytes)
        signature           Signature to be verified. R and S integers in big-endian format.
                            64 bytes for P256 curve. (bytearray or bytes)
        public_key          For VERIFY_MODE_EXTERNAL mode, the public key to be used for
                            verification. X and Y integers in big-endian format. 64 bytes
                            for P256 curve. Null for VERIFY_MODE_STORED mode. (bytearray or bytes)
        num_in              System nonce (32 byte) used for the verification MAC. (bytearray or bytes)
        io_key              IO protection key for verifying the validation MAC. (bytearray or bytes)
        is_verified         Boolean whether or not the message, signature, public key verified.
                            (Expects AtcaReference)

    Returns:
        Status code
    """
    if not isinstance(is_verified, AtcaReference):
        status = Status.ATCA_BAD_PARAM
    else:
        c_is_verified = c_uint8(is_verified.value)
        status = get_cryptoauthlib().atcab_verify_extern_stored_mac(mode, key_id, bytes(message), bytes(signature),
                                                                    bytes(public_key), bytes(num_in), bytes(io_key),
                                                                    byref(c_is_verified))
        is_verified.value = c_is_verified.value
    return status


def atcab_verify_extern(message, signature, public_key, is_verified):
    """
    Executes the Verify command, which verifies a signature (ECDSA verify operation) with
    all components (message, signature, and public key) supplied. The message to be signed
    will be loaded into the Message Digest Buffer to the ATECC608 device or TempKey for
    other devices.

    Args:
        message             32 byte message to be verified. Typically the SHA256 hash of
                            the full message. (Expects bytes)
        signature           Signature to be verified. R and S integers in big-endian format.
                            64 bytes for P256 curve. (Expects bytes)
        public_key          The public key to be used for verification. X and Y integers
                            in big-endian format. 64 bytes for P256 curve. (Expects bytes)
        is_verified         Boolean whether or not the message, signature, public key verified.
                            (Expects AtcaReference)


    Returns:
        Status code
    """
    if not isinstance(is_verified, AtcaReference):
        status = Status.ATCA_BAD_PARAM
    else:
        c_is_verified = c_uint8(is_verified.value)
        status = get_cryptoauthlib().atcab_verify_extern(bytes(message), bytes(signature), bytes(public_key),
                                                         byref(c_is_verified))
        is_verified.value = c_is_verified.value
    return status


def atcab_verify_extern_mac(message, signature, public_key, num_in, io_key, is_verified):
    """
    Executes the Verify command with verification MAC, which verifies a signature
    (ECDSA verify operation) with all components (message,  signature, and public key)
    supplied. This function is only available on the ATECC608.

    Args:
        message             32 byte message to be verified. Typically the SHA256 hash of
                            the full message. (bytearray or bytes)
        signature           Signature to be verified. R and S integers in big-endian format.
                            64 bytes for P256 curve. (bytearray or bytes)
        public_key          The public key to be used for verification. X and Y integers in
                            big-endian format. 64 bytes for P256 curve. (bytearray or bytes)
        num_in              System nonce (32 byte) used for the verification MAC. (bytearray or bytes)
        io_key              IO protection key for verifying the validation MAC. (bytearray or bytes)
        is_verified         Boolean whether or not the message, signature, public key verified.
                            (Expects AtcaReference)

    Returns:
        Stats code
    """
    if not isinstance(is_verified, AtcaReference):
        status = Status.ATCA_BAD_PARAM
    else:
        c_is_verified = c_uint8(is_verified.value)
        status = get_cryptoauthlib().atcab_verify_extern_mac(bytes(message), bytes(signature), bytes(public_key),
                                                             bytes(num_in), bytes(io_key), byref(c_is_verified))
        is_verified.value = c_is_verified.value
    return status


def atcab_verify_stored(message, signature, key_id, is_verified):
    """
    Executes the Verify command, which verifies a signature (ECDSA verify operation)
    with a public key stored in the device. The message to be signed will be loaded
    into the Message Digest Buffer to the ATECC608 device or TempKey for other devices.

    Args:
        message             32 byte message to be verified. Typically the SHA256 hash of
                            the full message. (bytearray or bytes)
        signature           Signature to be verified. R and S integers in big-endian format.
                            64 bytes for P256 curve. (bytearray or bytes)
        key_id              Slot containing the public key to be used in the verification.(int)
        is_verified         Boolean whether or not the message, signature, public key verified.
                            (Expects AtcaReference)

    Returns:
        Status code
    """
    if not isinstance(is_verified, AtcaReference):
        status = Status.ATCA_BAD_PARAM
    else:
        c_is_verified = c_uint8(is_verified.value)
        status = get_cryptoauthlib().atcab_verify_stored(bytes(message), bytes(signature), key_id, byref(c_is_verified))
        is_verified.value = c_is_verified.value
    return status


def atcab_verify_stored_mac(message, signature, key_id, num_in, io_key, is_verified):
    """
    Executes the Verify command with verification MAC, which verifies a  signature
    (ECDSA verify operation) with a public key stored in the device. This function
    is only available on the ATECC608.

    Args:
        message             32 byte message to be verified. Typically the SHA256 hash of
                            the full message. (bytearray or bytes)
        signature           Signature to be verified. R and S integers in big-endian format.
                            64 bytes for P256 curve. (bytearray or bytes)
        key_id              Slot containing the public key to be used in the verification.
                            (int)
        num_in              System nonce (32 byte) used for the verification MAC.
                            (bytearray or bytes)
        io_key              IO protection key for verifying the validation MAC.
                            (bytearray or bytes)
        is_verified         Boolean whether or not the message, signature, public key verified.
                            (Expects AtcaReference)

    Retuns:
        Status code
    """
    if not isinstance(is_verified, AtcaReference):
        status = Status.ATCA_BAD_PARAM
    else:
        c_is_verified = c_uint8(is_verified.value)
        status = get_cryptoauthlib().atcab_verify_stored_mac(bytes(message), bytes(signature), key_id, bytes(num_in),
                                                             bytes(io_key), byref(c_is_verified))
        is_verified.value = c_is_verified.value
    return status


def atcab_verify_validate(key_id, signature, other_data, is_verified):
    """
    Executes the Verify command in Validate mode to validate a public key stored
    in a slot. This command can only be run after GenKey has been used to create
    a PubKey digest of the public key to be validated in TempKey (mode=0x10).

    Args:
        key_id              Slot containing the public key to be validated.(int)
        signature           Signature to be verified. R and S integers in big-endian format.
                            64 bytes for P256 curve. (bytearray or bytes)
        other_data          19 bytes of data used to build the verification message (bytearray or bytes)
        is_verified         Boolean whether or not the message, signature, public key verified.
                            (Expects AtcaReference)

    Returns:
        Status code
    """
    if not isinstance(is_verified, AtcaReference):
        status = Status.ATCA_BAD_PARAM
    else:
        c_is_verified = c_uint8(is_verified.value)
        status = get_cryptoauthlib().atcab_verify_validate(key_id, bytes(signature), bytes(other_data),
                                                           byref(c_is_verified))
        is_verified.value = c_is_verified.value
    return status


def atcab_verify_invalidate(key_id, signature, other_data, is_verified):
    """
    Executes the Verify command in Invalidate mode which invalidates a previously
    validated public key stored in a slot. This command can only be run after
    GenKey has been used to create a PubKey digest of the public key to be
    invalidated in TempKey (mode=0x10).

    Args:
        key_id              Slot containing the public key to be invalidated. (int)
        signature           Signature to be verified. R and S integers in big-endian format.
                            64 bytes for P256 curve. (bytearray or bytes)
        other_data          19 bytes of data used to build the verification message (bytearray or bytes)
        is_verified         Boolean whether or not the message, signature, public key verified.
                            (Expects AtcaReference)

    Returns:
        Status code
    """
    if not isinstance(is_verified, AtcaReference):
        status = Status.ATCA_BAD_PARAM
    else:
        c_is_verified = c_uint8(is_verified.value)
        status = get_cryptoauthlib().atcab_verify_invalidate(key_id, bytes(signature), bytes(other_data),
                                                             byref(c_is_verified))
        is_verified.value = c_is_verified.value
    return status


# CryptoAuthLib Basic API methods for Write command.
#
# The Write command writes either one 4-byte word or a 32-byte block to one of
# the EEPROM zones on the device. Depending upon the value of the WriteConfig
# byte for a slot, the data may be required to be encrypted by the system prior
# to being sent to the device


def atcab_write(zone, address, value, mac):
    """
    Executes the Write command, which writes either one four byte word or a 32-byte
    block to one of the EEPROM zones on the device. Depending upon the value of the
    WriteConfig byte for this slot, the data may be required to be encrypted by the
    system prior to being sent to the device. This command cannot be used to write
    slots configured as ECC private keys.

    Args:
        zone                Zone/Param1 for the write command. (int)
        address             Address/Param2 for the write command. (int)
        value               Plain-text data to be written or cipher-text for encrypted writes.
                            32 or 4 bytes depending on bit 7 in the zone. (bytearray or bytes)
        data                Data to be written. (bytearray or bytes)
        mac                 MAC required for encrypted writes (32 bytes).
                            (bytearray or bytes)

    Returns:
        Status code
    """
    status = get_cryptoauthlib().atcab_write(zone, address, bytes(value), bytes(mac))
    return status


def atcab_write_zone(zone, slot, block, offset, data, length):
    """
    Executes the Write command, which writes either 4 or 32 bytes of data into a device zone.

    Args:
        zone                Device zone to write to (0=config, 1=OTP, 2=data). (int)
        slot                If writing to the data zone, it is the slot to write to, otherwise
                            it should be 0. (int)
        block               32-byte block to write to. (int)
        offset              4-byte word within the specified block to write to. If performing a
                            32-byte write, this should be 0. (int)
        data                Data to be written. (bytearray or bytes)
        len                 Number of bytes to be written. Must be either 4 or 32. (int)

    Returns:
        Status code
    """
    status = get_cryptoauthlib().atcab_write_zone(zone, slot, block, offset, bytes(data), length)
    return status


def atcab_write_enc(key_id, block, data, enc_key, enc_key_id, num_in=None):
    """
    Executes the Write command, which performs an encrypted write of a 32 byte block into
    given slot. The function takes clear text bytes and encrypts them for writing over the
    wire. Data zone must be locked and the slot configuration must be set to encrypted
    write for the block to be successfully written.

    Args:
        key_id              Slot ID to write to. (int)
        block               Index of the 32 byte block to write in the slot. (int)
        data                32 bytes of clear text data to be written to the slot.
                            (bytearray or bytes)
        enc_key             WriteKey to encrypt with for writing
                            (bytearray or bytes)
        enc_key_id          The KeyID of the WriteKey (int)
        num_in              Bytearray - Host nonce used to calculate nonce (20 bytes)
    Returns:
        Status code
    """
    if num_in is None:
        num_in = bytearray(20)

    status = get_cryptoauthlib().atcab_write_enc(key_id, block, bytes(data), bytes(enc_key), enc_key_id, bytes(num_in))
    return status


def atcab_write_config_zone(conf):
    """
    Executes the Write command, which writes the configuration zone. First 16 bytes are
    skipped as they are not writable. LockValue and LockConfig are also skipped and can
    only be changed via the Lock command.

    This command may fail if UserExtra and/or Selector bytes have
    already been set to non-zero values.

    Args:
        conf                Data to the config zone data. This should be a 88
                            byte bytearray for SHA devices and 128 byte bytearray for ECC
                            devices. (bytearray or bytes)

    Returns:
        Status code
    """
    status = get_cryptoauthlib().atcab_write_config_zone(bytes(conf))
    return status


def atcab_write_pubkey(slot, public_key):
    """
    Executes the Write command, which writes a public key to a data slot in the device format.

    Args:
        slot                Slot number to write. Only slots 8 to 15 are large enough to
                            store a public key. (int)
        public_key          Public key to write into the slot specified. X and Y integers
                            in big-endian format. 64 bytes for P256 curve. (bytearray or bytes)

    Returns:
        Status code
    """
    status = get_cryptoauthlib().atcab_write_pubkey(slot, bytes(public_key))
    return status


def atcab_write_bytes_zone(zone, slot, offset_bytes, data, length):
    """
    Executes the Write command, which writes data into config, otp, or data zone with a given
    byte offset and length. Offset and length must be multiples of a word (4 bytes).

    Config zone must be unlocked for writes to that zone. If data zone is
    unlocked, only 32-byte writes are allowed to slots and OTP and the offset
    and length must be multiples of 32 or the write will fail.

    Args:
        zone                Zone to write data to: Zones.ATCA_ZONE_CONFIG, Zones.ATCA_ZONE_OTP,
                            or Zones.ATCA_ZONE_DATA. (int)
        slot                If zone is Zones.ATCA_ZONE_DATA, the slot number to write to.
                            Ignored for all other zones. (int)
        offset_bytes        Byte offset within the zone to write to. Must be a multiple of
                            a word (4 bytes). (int)
        data                bytearray containing Data to be written. (bytearray or bytes)
        length              Number of bytes to be written. Must be a multiple of a word (4 bytes).
                            (int)

    Returns:
        None
    """
    status = get_cryptoauthlib().atcab_write_bytes_zone(zone, slot, offset_bytes, bytes(data), length)
    return status


def atcab_write_config_counter(counter_id, counter_value):
    """
    Initialize one of the monotonic counters in device with a specific value. The monotonic
    counters are stored in the configuration zone using a special format. This encodes a
    binary count value into the 8 byte encoded value required. This can only be set while
    the configuration zone is unlocked.

    Args:
        counter_id          Counter to be written (int)
        counter_value       Counter value to set (int)
    """
    status = get_cryptoauthlib().atcab_write_config_counter(counter_id, counter_value)
    return status


# Make module import * safe - keep at the end of the file
__all__ = ['atca_aes_cbc_ctx', 'atca_aes_cmac_ctx', 'atca_aes_ctr_ctx',
           'atca_aes_gcm_ctx', 'atca_sha256_ctx', 'atca_hmac_sha256_ctx']
__all__ += [x for x in dir() if x.startswith(__name__.split('.')[-1])]
