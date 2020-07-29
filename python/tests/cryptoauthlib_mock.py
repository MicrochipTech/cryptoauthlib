from ctypes import c_uint8, create_string_buffer, memmove, byref, cast, c_void_p, c_uint32, POINTER, c_size_t, sizeof
from cryptoauthlib import *

c_ptr = type(byref(create_string_buffer(1)))

class atcab_mock(object):
    def atcab_init(self):
        return Status.ATCA_SUCCESS

    def atcab_release(self):
        return Status.ATCA_SUCCESS

    r_devtype = 3
    def atcab_get_device_type(self):
        return self.r_devtype

    #--------------------------------------------------------------------#
    # atcab_aes(self, mode, key_id, aes_in, aes_out)
    r_aes_out = create_string_buffer(16)
    r_aes_out.value = bytes(bytearray([0x00, 0x01, 0x02, 0x04,
                                       0x00, 0x01, 0x02, 0x04,
                                       0x00, 0x01, 0x02, 0x04,
                                       0x00, 0x01, 0x02, 0x04]))

    def atcab_aes(self, mode, key_id, aes_in, aes_out):

        if not isinstance(mode, int):
            raise TypeError

        if not isinstance(key_id, int):
            raise TypeError

        if not isinstance(aes_in, bytes):
            raise TypeError

        if not isinstance(aes_out, c_ptr):
            raise TypeError

        memmove(cast(aes_out, c_void_p).value, cast(byref(self.r_aes_out), c_void_p).value, len(self.r_aes_out))

        return Status.ATCA_SUCCESS


    #--------------------------------------------------------------------#
    # atcab_aes_encrypt(key_id, key_block, plaintext, ciphertext)
    r_ciphertext = create_string_buffer(16)
    r_ciphertext.value = bytes(bytearray([0x00, 0x01, 0x02, 0x04,
                                          0x00, 0x01, 0x02, 0x04,
                                          0x00, 0x01, 0x02, 0x04,
                                          0x00, 0x01, 0x02, 0x04]))

    def atcab_aes_encrypt(self, key_id, key_block, plaintext, ciphertext):

        if not isinstance(key_id, int):
            raise TypeError

        if not isinstance(key_block, int):
            raise TypeError

        if not isinstance(plaintext, bytes):
            raise TypeError

        if not isinstance(ciphertext, c_ptr):
            raise TypeError

        memmove(cast(ciphertext, c_void_p).value, cast(byref(self.r_ciphertext), c_void_p).value, len(self.r_aes_out))

        return Status.ATCA_SUCCESS


    #--------------------------------------------------------------------#
    # atcab_aes_decrypt(key_id, key_block, ciphertext, plaintext):
    r_plaintext = create_string_buffer(16)
    r_plaintext.value = bytes(bytearray([0x00, 0x01, 0x02, 0x04,
                                         0x00, 0x01, 0x02, 0x04,
                                         0x00, 0x01, 0x02, 0x04,
                                         0x00, 0x01, 0x02, 0x04]))

    def atcab_aes_decrypt(self, key_id, key_block, ciphertext, plaintext):

        if not isinstance(key_id, int):
            raise TypeError

        if not isinstance(key_block, int):
            raise TypeError

        if not isinstance(ciphertext, bytes):
            raise TypeError

        if not isinstance(plaintext, c_ptr):
            raise TypeError

        memmove(cast(plaintext, c_void_p).value, cast(byref(self.r_plaintext), c_void_p).value, len(self.r_plaintext))

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # atcab_aes_gfm(hash_key, inp, output):
    r_aes_gfm_output = create_string_buffer(16)
    r_aes_gfm_output.value = bytes(bytearray([0x00, 0x01, 0x02, 0x04,
                                              0x00, 0x01, 0x02, 0x04,
                                              0x00, 0x01, 0x02, 0x04,
                                              0x00, 0x01, 0x02, 0x04]))

    def atcab_aes_gfm(self, hash_key, inp, output):

        if not isinstance(hash_key, bytes):
            raise TypeError

        if not isinstance(inp, bytes):
            raise TypeError

        if not isinstance(output, c_ptr):
            raise TypeError

        memmove(cast(output, c_void_p).value, cast(byref(self.r_aes_gfm_output), c_void_p).value, len(self.r_plaintext))

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # atcab_aes_cbc_init(ctx, key_id, key_block, iv):

    def atcab_aes_cbc_init(self, ctx, key_id, key_block, iv):

        if not isinstance(key_id, int):
            raise TypeError

        if not isinstance(key_block, int):
            raise TypeError

        if not isinstance(iv, bytes):
            raise TypeError

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # atcab_aes_cbc_encrypt_block(ctx, plaintext, ciphertext):

    def atcab_aes_cbc_encrypt_block(self, ctx, plaintext, ciphertext):

        if not isinstance(plaintext, bytes):
            raise TypeError

        if not isinstance(ciphertext, c_ptr):
            raise TypeError

        memmove(cast(ciphertext, c_void_p).value, cast(byref(self.r_ciphertext), c_void_p).value, len(self.r_aes_out))

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # atcab_aes_cbc_decrypt_block(ctx, ciphertext, plaintext):

    def atcab_aes_cbc_decrypt_block(self, ctx, ciphertext, plaintext):

        if not isinstance(plaintext, c_ptr):
            raise TypeError

        if not isinstance(ciphertext, bytes):
            raise TypeError

        memmove(cast(plaintext, c_void_p).value, cast(byref(self.r_plaintext), c_void_p).value, len(self.r_plaintext))

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    #atcab_aes_cmac_init(ctx, key_id, key_block):

    def atcab_aes_cmac_init(self, ctx, key_id, key_block):

        if not isinstance(key_id, int):
            raise TypeError

        if not isinstance(key_block, int):
            raise TypeError

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # atcab_aes_cmac_update(ctx, data, data_size):

    def atcab_aes_cmac_update(self, ctx, data, data_size):

        if not isinstance(data, bytes):
            raise TypeError

        if not isinstance(data_size, int):
            raise TypeError

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    #atcab_aes_cmac_finish(ctx, cmac, size):

    r_aes_cmac_output = create_string_buffer(16)
    r_aes_cmac_output.value = bytes(bytearray([0x00, 0x01, 0x02, 0x04,
                                               0x00, 0x01, 0x02, 0x04,
                                               0x00, 0x01, 0x02, 0x04,
                                               0x00, 0x01, 0x02, 0x04]))

    def atcab_aes_cmac_finish(self, ctx, cmac, size):

        if not isinstance(cmac, c_ptr):
            raise TypeError

        if not isinstance(size, int):
            raise TypeError

        memmove(cast(cmac, c_void_p).value, cast(byref(self.r_aes_cmac_output), c_void_p).value, len(self.r_aes_cmac_output))

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    #atcab_aes_ctr_init(ctx, key_id, key_block, counter_size, iv):

    def atcab_aes_ctr_init(self, ctx, key_id, key_block, counter_size, iv):

        if not isinstance(key_id, int):
            raise TypeError

        if not isinstance(key_block, int):
            raise TypeError

        if not isinstance(counter_size, int):
            raise TypeError

        if not isinstance(iv, bytes):
            raise TypeError

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    #atcab_aes_ctr_init_rand(ctx, key_id, key_block, counter_size, iv):

    def atcab_aes_ctr_init_rand(self, ctx, key_id, key_block, counter_size, iv):

        if not isinstance(key_id, int):
            raise TypeError

        if not isinstance(key_block, int):
            raise TypeError

        if not isinstance(counter_size, int):
            raise TypeError

        if not isinstance(iv, c_ptr):
            raise TypeError

        memmove(cast(iv, c_void_p).value, cast(byref(self.r_aes_ctr_output), c_void_p).value, len(self.r_aes_ctr_output))

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    #atcab_aes_ctr_encrypt_block(ctx, plaintext, ciphertext):

    r_aes_ctr_output = create_string_buffer(16)
    r_aes_ctr_output.value = bytes(bytearray([0x00, 0x01, 0x02, 0x04,
                                              0x00, 0x01, 0x02, 0x04,
                                              0x00, 0x01, 0x02, 0x04,
                                              0x00, 0x01, 0x02, 0x04]))

    def atcab_aes_ctr_encrypt_block(self, ctx, plaintext, ciphertext):

        if not isinstance(plaintext, bytes):
            raise TypeError

        if not isinstance(ciphertext, c_ptr):
            raise TypeError

        memmove(cast(ciphertext, c_void_p).value, cast(byref(self.r_aes_ctr_output), c_void_p).value, len(self.r_aes_ctr_output))

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    #atcab_aes_ctr_encrypt_block(ctx, plaintext, ciphertext):

    def atcab_aes_ctr_decrypt_block(self, ctx, ciphertext, plaintext):

        if not isinstance(ciphertext, bytes):
            raise TypeError

        if not isinstance(plaintext, c_ptr):
            raise TypeError

        memmove(cast(plaintext, c_void_p).value, cast(byref(self.r_aes_ctr_output), c_void_p).value, len(self.r_aes_ctr_output))

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # atcab_aes_gcm_init(ctx, key_id, key_block, iv, iv_size):

    def atcab_aes_gcm_init(self, ctx, key_id, key_block, iv, iv_size):

        if not isinstance(key_id, int):
            raise TypeError

        if not isinstance(key_block, int):
            raise TypeError

        if not isinstance(iv, bytes):
            raise TypeError

        if not isinstance(iv_size, int):
            raise TypeError

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # atcab_aes_gcm_init_rand(ctx, key_id, key_block, rand_size, free_field, free_field_size, iv):
    r_iv = create_string_buffer(16)
    r_iv.value = bytes(bytearray([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                              0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]))

    def atcab_aes_gcm_init_rand(self, ctx, key_id, key_block, rand_size, free_field, free_field_size, iv):

        if not isinstance(key_id, int):
            raise TypeError

        if not isinstance(key_block, int):
            raise TypeError

        if not isinstance(rand_size, int):
            raise TypeError

        if not isinstance(free_field, bytes):
            raise TypeError

        if not isinstance(free_field_size, int):
            raise TypeError

        if not isinstance(iv, c_ptr):
            raise TypeError

        memmove(cast(iv, c_void_p).value, cast(byref(self.r_iv), c_void_p).value, len(self.r_iv))

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # atcab_aes_gcm_aad_update(ctx, aad, aad_size):

    def atcab_aes_gcm_aad_update(self, ctx, aad, aad_size):

        if not isinstance(aad, bytes):
            raise TypeError

        if not isinstance(aad_size, int):
            raise TypeError

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # atcab_aes_gcm_encrypt_update(ctx, plaintext, plaintext_size, ciphertext):
    r_ciphertext = create_string_buffer(16)
    r_ciphertext.value = bytes(bytearray([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                              0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]))

    def atcab_aes_gcm_encrypt_update(self, ctx, plaintext, plaintext_size, ciphertext):

        if not isinstance(plaintext, bytes):
            raise TypeError

        if not isinstance(plaintext_size, int):
            raise TypeError

        if not isinstance(ciphertext, c_ptr):
            raise TypeError

        memmove(cast(ciphertext, c_void_p).value, cast(byref(self.r_ciphertext), c_void_p).value, len(self.r_ciphertext))

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # atcab_aes_gcm_encrypt_finish(ctx, tag, tag_size):
    r_tag = create_string_buffer(16)
    r_tag.value = bytes(bytearray([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                              0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]))

    def atcab_aes_gcm_encrypt_finish(self, ctx, tag, tag_size):

        if not isinstance(tag_size, int):
            raise TypeError

        if not isinstance(tag, c_ptr):
            raise TypeError

        memmove(cast(tag, c_void_p).value, cast(byref(self.r_tag), c_void_p).value, tag_size)

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # atcab_aes_gcm_decrypt_update(ctx, ciphertext, ciphertext_size, plaintext):

    def atcab_aes_gcm_decrypt_update(self, ctx, ciphertext, ciphertext_size, plaintext):

        r_plaintext= create_string_buffer(16)
        r_plaintext.value = bytes(bytearray([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                              0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]))

        if not isinstance(ciphertext_size, int):
            raise TypeError

        if not isinstance(ciphertext, bytes):
            raise TypeError

        if not isinstance(plaintext, c_ptr):
            raise TypeError

        memmove(cast(plaintext, c_void_p).value, cast(byref(self.r_plaintext), c_void_p).value, len(self.r_plaintext))

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # atcab_aes_gcm_decrypt_finish(ctx, tag, tag_size, is_verified):
    r_is_verified = c_uint8()
    r_is_verified.value = 1
    def atcab_aes_gcm_decrypt_finish(self, ctx, tag, tag_size, is_verified):

        if not isinstance(tag, bytes):
            raise TypeError

        if not isinstance(tag_size, int):
            raise TypeError

        if not isinstance(is_verified, c_ptr):
            raise TypeError

        memmove(cast(is_verified, c_void_p).value, cast(byref(self.r_is_verified), c_void_p).value, 1)

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # atcab_checkmac(mode, key_id, challenge, response, other_data):

    def atcab_checkmac(self, mode, key_id, challenge, response, other_data):

        if not isinstance(mode, int):
            raise TypeError

        if not isinstance(key_id, int):
            raise TypeError

        if not isinstance(challenge, bytes):
            raise TypeError

        if not isinstance(response, bytes):
            raise TypeError

        if not isinstance(other_data, bytes):
            raise TypeError

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # atcab_counter(mode, counter_id, counter_value):
    r_counter_value = c_uint32()
    r_counter_value.value = 0x12345678

    def atcab_counter(self, mode, counter_id, counter_value):

        if not isinstance(mode, int):
            raise TypeError

        if not isinstance(counter_id, int):
            raise TypeError

        if not isinstance(counter_value, c_ptr):
            raise TypeError

        memmove(cast(counter_value, c_void_p).value, cast(byref(self.r_counter_value), c_void_p).value, 4)

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # atcab_counter_increment(counter_id, counter_value):

    def atcab_counter_increment(self, counter_id, counter_value):

        if not isinstance(counter_id, int):
            raise TypeError

        if not isinstance(counter_value, c_ptr):
            raise TypeError

        memmove(cast(counter_value, c_void_p).value, cast(byref(self.r_counter_value), c_void_p).value, 4)

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # atcab_counter_read(counter_id, counter_value):

    def atcab_counter_read(self, counter_id, counter_value):

        if not isinstance(counter_id, int):
            raise TypeError

        if not isinstance(counter_value, c_ptr):
            raise TypeError

        memmove(cast(counter_value, c_void_p).value, cast(byref(self.r_counter_value), c_void_p).value, 4)

        return Status.ATCA_SUCCESS

   #--------------------------------------------------------------------#
   # atcab_derivekey(mode, target_key, mac):

    def atcab_derivekey(self, mode, target_key, mac):

        if not isinstance(mode, int):
            raise TypeError

        if not isinstance(target_key, int):
            raise TypeError

        if not isinstance(mac, bytes):
            raise TypeError

        return Status.ATCA_SUCCESS


    #--------------------------------------------------------------------#
    # atcab_ecdh_base(mode, key_id, public_key, pms, out_nonce):

    r_ecdh_pms = create_string_buffer(32)
    r_ecdh_pms.value = bytes(bytearray([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]))

    r_ecdh_out_nonce = create_string_buffer(32)
    r_ecdh_out_nonce.value = bytes(bytearray([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                              0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                              0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                              0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]))

    def atcab_ecdh_base(self, mode, key_id, public_key, pms, out_nonce):

        if not isinstance(mode, int):
            raise TypeError

        if not isinstance(key_id, int):
            raise TypeError

        if not isinstance(public_key, bytes):
            raise TypeError

        if not isinstance(pms, c_ptr):
            raise TypeError

        if not isinstance(out_nonce, c_ptr):
            raise TypeError

        memmove(cast(pms, c_void_p).value, cast(byref(self.r_ecdh_pms), c_void_p).value, len(self.r_ecdh_pms))
        memmove(cast(out_nonce, c_void_p).value, cast(byref(self.r_ecdh_out_nonce), c_void_p).value, len(self.r_ecdh_out_nonce))

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # atcab_ecdh(key_id, public_key, pms):

    def atcab_ecdh(self, key_id, public_key, pms):

        if not isinstance(key_id, int):
            raise TypeError

        if not isinstance(public_key, bytes):
            raise TypeError

        if not isinstance(pms, c_ptr):
            raise TypeError

        memmove(cast(pms, c_void_p).value, cast(byref(self.r_ecdh_pms), c_void_p).value, len(self.r_ecdh_pms))

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # atcab_ecdh_enc(key_id, public_key, pms, read_key, read_key_id, num_in):

    def atcab_ecdh_enc(self, key_id, public_key, pms, read_key, read_key_id, num_in):

        if not isinstance(key_id, int):
            raise TypeError

        if not isinstance(public_key, bytes):
            raise TypeError

        if not isinstance(pms, c_ptr):
            raise TypeError

        if not isinstance(read_key, bytes):
            raise TypeError

        if not isinstance(read_key_id, int):
            raise TypeError

        if not isinstance(num_in, bytes):
            raise TypeError

        memmove(cast(pms, c_void_p).value, cast(byref(self.r_ecdh_pms), c_void_p).value, len(self.r_ecdh_pms))

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # atcab_ecdh_ioenc(key_id, public_key, pms, io_key):

    def atcab_ecdh_ioenc(self, key_id, public_key, pms, io_key):

        if not isinstance(key_id, int):
            raise TypeError

        if not isinstance(public_key, bytes):
            raise TypeError

        if not isinstance(pms, c_ptr):
            raise TypeError

        if not isinstance(io_key, bytes):
            raise TypeError

        memmove(cast(pms, c_void_p).value, cast(byref(self.r_ecdh_pms), c_void_p).value, len(self.r_ecdh_pms))

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # atcab_ecdh_tempkey(public_key, pms):

    def atcab_ecdh_tempkey(self, public_key, pms):

        if not isinstance(public_key, bytes):
            raise TypeError

        if not isinstance(pms, c_ptr):
            raise TypeError

        memmove(cast(pms, c_void_p).value, cast(byref(self.r_ecdh_pms), c_void_p).value, len(self.r_ecdh_pms))

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # atcab_ecdh_tempkey_ioenc(public_key, pms):

    def atcab_ecdh_tempkey_ioenc(self, public_key, pms, io_key):

        if not isinstance(public_key, bytes):
            raise TypeError

        if not isinstance(pms, c_ptr):
            raise TypeError

        if not isinstance(io_key, bytes):
            raise TypeError

        memmove(cast(pms, c_void_p).value, cast(byref(self.r_ecdh_pms), c_void_p).value, len(self.r_ecdh_pms))

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # atcab_gendig(zone, key_id, other_data, other_data_size):

    def atcab_gendig(self, zone, key_id, other_data, other_data_size):

        if not isinstance(zone, int):
            raise TypeError

        if not isinstance(key_id, int):
            raise TypeError

        if not isinstance(other_data, bytes):
            raise TypeError

        if not isinstance(other_data_size, int):
            raise TypeError

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # atcab_genkey_base(mode, key_id, other_data, public_key):
    r_genkey_pubkey = create_string_buffer(64)
    r_genkey_pubkey.value = bytes(bytearray([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                             0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                             0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                             0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]))

    def atcab_genkey_base(self, mode, key_id, other_data, public_key):

        if not isinstance(mode, int):
            raise TypeError

        if not isinstance(key_id, int):
            raise TypeError

        if not isinstance(other_data, bytes):
            raise TypeError

        if not isinstance(public_key, c_ptr):
            raise TypeError

        memmove(cast(public_key, c_void_p).value, cast(byref(self.r_genkey_pubkey), c_void_p).value, len(self.r_genkey_pubkey))

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # atcab_genkey(key_id, public_key):
    def atcab_genkey(self, key_id, public_key):

        if not isinstance(key_id, int):
            raise TypeError

        if not isinstance(public_key, c_ptr):
            raise TypeError

        memmove(cast(public_key, c_void_p).value, cast(byref(self.r_genkey_pubkey), c_void_p).value, len(self.r_genkey_pubkey))

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # atcab_get_pubkey(key_id, public_key):

    def atcab_get_pubkey(self, key_id, public_key):

        if not isinstance(key_id, int):
            raise TypeError

        if not isinstance(public_key, c_ptr):
            raise TypeError

        memmove(cast(public_key, c_void_p).value, cast(byref(self.r_genkey_pubkey), c_void_p).value, len(self.r_genkey_pubkey))

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # atcab_hmac(mode, key_id, digest):
    r_hmac_digest = create_string_buffer(32)
    r_hmac_digest.value = bytes(bytearray([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                           0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                           0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                           0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]))

    def atcab_hmac(self, mode, key_id, digest):

        if not isinstance(mode, int):
            raise TypeError

        if not isinstance(key_id, int):
            raise TypeError

        if not isinstance(digest, c_ptr):
            raise TypeError

        memmove(cast(digest, c_void_p).value, cast(byref(self.r_hmac_digest), c_void_p).value, len(self.r_hmac_digest))

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # atcab_info_base(mode, param2, out_data):

    r_revision = create_string_buffer(4)
    r_revision.value = bytes(bytearray([0, 1, 2, 3]))

    def atcab_info_base(self, mode, param2, out_data):

        if not isinstance(mode, int):
            raise TypeError

        if not isinstance(param2, int):
            raise TypeError

        if not isinstance(out_data, c_ptr):
            raise TypeError

        memmove(cast(out_data, c_void_p).value, cast(byref(self.r_revision), c_void_p).value, len(self.r_revision))

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # atcab_info(revision):

    def atcab_info(self, revision):

        if not isinstance(revision, c_ptr):
            raise TypeError

        memmove(cast(revision, c_void_p).value, cast(byref(self.r_revision), c_void_p).value, len(self.r_revision))

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # atcab_info_get_latch(state):

    r_latch_state = c_uint8()
    r_latch_state.value = 0x01

    def atcab_info_get_latch(self, state):

        if not isinstance(state, c_ptr):
            raise TypeError

        memmove(cast(state, c_void_p).value, cast(byref(self.r_latch_state), c_void_p).value, 1)

        return Status.ATCA_SUCCESS


    #--------------------------------------------------------------------#
    # atcab_info_set_latch(self, state):

    def atcab_info_set_latch(self, state):

        if not isinstance(state, int):
            raise TypeError

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # atcab_kdf(mode, key_id, details, message, out_data, out_nonce):

    r_kdf_out_data = create_string_buffer(64)
    r_kdf_out_data.value = bytes(bytearray([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]))


    r_kdf_out_nonce = create_string_buffer(32)
    r_kdf_out_nonce.value = bytes(bytearray([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                             0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                             0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                             0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]))

    def atcab_kdf(self, mode, key_id, details, message, out_data, out_nonce):

        if not isinstance(mode, int):
            raise TypeError

        if not isinstance(key_id, int):
            raise TypeError

        if not isinstance(details, int):
            raise TypeError

        if not isinstance(message, bytes):
            raise TypeError

        if not isinstance(out_data, c_ptr):
            raise TypeError

        if not isinstance(out_nonce, c_ptr):
            raise TypeError

        memmove(cast(out_data, c_void_p).value, cast(byref(self.r_kdf_out_data), c_void_p).value, len(self.r_kdf_out_data))
        memmove(cast(out_nonce, c_void_p).value, cast(byref(self.r_kdf_out_nonce), c_void_p).value, len(self.r_kdf_out_nonce))

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # atcab_lock(mode, summary_crc):

    def atcab_lock(self, mode, summary_crc):

        if not isinstance(mode, int):
            raise TypeError

        if not isinstance(summary_crc, int):
            raise TypeError

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # atcab_lock_config_zone():

    def atcab_lock_config_zone(self):
        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # atcab_lock_config_zone_crc(summary_crc):

    def atcab_lock_config_zone_crc(self, summary_crc):

        if not isinstance(summary_crc, int):
            raise TypeError

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # atcab_lock_data_zone():

    def atcab_lock_data_zone(self):
        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # atcab_lock_data_zone_crc(summary_crc):

    def atcab_lock_data_zone_crc(self, summary_crc):

        if not isinstance(summary_crc, int):
            raise TypeError

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # atcab_lock_data_slot(slot):
    def atcab_lock_data_slot(self, slot):

        if not isinstance(slot, int):
            raise TypeError

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # atcab_mac(mode, key_id, challenge, digest):

    r_mac_digest = create_string_buffer(32)
    r_mac_digest.value = bytes(bytearray([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                          0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                          0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                          0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]))


    def atcab_mac(self, mode, key_id, challenge, digest):

        if not isinstance(mode, int):
            raise TypeError

        if not isinstance(key_id, int):
            raise TypeError

        if not isinstance(challenge, bytes):
            raise TypeError

        if not isinstance(digest, c_ptr):
            raise TypeError

        memmove(cast(digest, c_void_p).value, cast(byref(self.r_mac_digest), c_void_p).value, len(self.r_mac_digest))

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # atcab_nonce_base(mode, zero, num_in, rand_out):

    r_nonce_rand_out = create_string_buffer(32)
    r_nonce_rand_out.value = bytes(bytearray([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                              0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                              0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                              0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]))

    def atcab_nonce_base(self, mode, zero, num_in, rand_out):

        if not isinstance(mode, int):
            raise TypeError

        if not isinstance(zero, int):
            raise TypeError

        if not isinstance(num_in, bytes):
            raise TypeError

        if not isinstance(rand_out, c_ptr):
            raise TypeError

        memmove(cast(rand_out, c_void_p).value, cast(byref(self.r_nonce_rand_out), c_void_p).value, len(self.r_nonce_rand_out))

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # atcab_nonce(num_in):
    def atcab_nonce(self, num_in):

        if not isinstance(num_in, bytes):
            raise TypeError

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # atcab_nonce_load(target, num_in, num_in_size):

    def atcab_nonce_load(self, target, num_in, num_in_size):

        if not isinstance(target, int):
            raise TypeError

        if not isinstance(num_in, bytes):
            raise TypeError

        if not isinstance(num_in_size, int):
            raise TypeError

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # atcab_nonce_rand(num_in, rand_out):

    def atcab_nonce_rand(self, num_in, rand_out):

        if not isinstance(num_in, bytes):
            raise TypeError

        if not isinstance(rand_out, c_ptr):
            raise TypeError

        memmove(cast(rand_out, c_void_p).value, cast(byref(self.r_nonce_rand_out), c_void_p).value, len(self.r_nonce_rand_out))

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # atcab_challenge(num_in):
    def atcab_challenge(self, num_in):

        if not isinstance(num_in, bytes):
            raise TypeError

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # atcab_challenge_seed_update(num_in, rand_out):
    def atcab_challenge_seed_update(self, num_in, rand_out):

        if not isinstance(num_in, bytes):
            raise TypeError

        if not isinstance(rand_out, c_ptr):
            raise TypeError

        memmove(cast(rand_out, c_void_p).value, cast(byref(self.r_nonce_rand_out), c_void_p).value, len(self.r_nonce_rand_out))

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # atcab_priv_write(key_id, priv_key, write_key_id, write_key, num_in):

    def atcab_priv_write(self, key_id, priv_key, write_key_id, write_key, num_in):

        if not isinstance(key_id, int):
            raise TypeError

        if not isinstance(priv_key, bytes):
            raise TypeError

        if not isinstance(write_key_id, int):
            raise TypeError

        if not isinstance(write_key, bytes):
            raise TypeError

        if not isinstance(num_in, bytes):
            raise TypeError

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # atcab_random(random_number):

    r_rand_out = create_string_buffer(32)
    r_rand_out.value = bytes(bytearray([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]))

    def atcab_random(self, random_number):

        if not isinstance(random_number, c_ptr):
            raise TypeError

        memmove(cast(random_number, c_void_p).value, cast(byref(self.r_rand_out), c_void_p).value, len(self.r_rand_out))
        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # atcab_read_zone(zone, slot, block, offset, data, length):

    r_read_zone_data = create_string_buffer(32)
    r_read_zone_data.value = bytes(bytearray([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                              0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                              0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                              0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]))

    def atcab_read_zone(self, zone, slot, block, offset, data, length):

        if not isinstance(zone, int):
            raise TypeError

        if not isinstance(slot, int):
            raise TypeError

        if not isinstance(block, int):
            raise TypeError

        if not isinstance(offset, int):
            raise TypeError

        if not isinstance(data, c_ptr):
            raise TypeError

        if not isinstance(length, int):
            raise TypeError

        memmove(cast(data, c_void_p).value, cast(byref(self.r_read_zone_data), c_void_p).value, len(self.r_read_zone_data))

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # atcab_read_serial_number(serial_number):

    r_ser_num = create_string_buffer(9)
    r_ser_num.value = bytes(bytearray([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]))

    def atcab_read_serial_number(self, serial_number):

        if not isinstance(serial_number, c_ptr):
            raise TypeError

        memmove(cast(serial_number, c_void_p).value, cast(byref(self.r_ser_num), c_void_p).value, len(self.r_ser_num))

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # atcab_is_slot_locked(slot, is_locked):

    r_is_locked = c_uint8()
    r_is_locked.value = 0x01

    def atcab_is_slot_locked(self, slot, is_locked):

        if not isinstance(slot, int):
            raise TypeError

        if not isinstance(is_locked, c_ptr):
            raise TypeError

        memmove(cast(is_locked, c_void_p).value, cast(byref(self.r_is_locked), c_void_p).value, 1)

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # atcab_is_locked(zone, is_locked):

    r_is_locked = c_uint8()
    r_is_locked.value = 0x01

    def atcab_is_locked(self, zone, is_locked):

        if not isinstance(zone, int):
            raise TypeError

        if not isinstance(is_locked, c_ptr):
            raise TypeError

        memmove(cast(is_locked, c_void_p).value, cast(byref(self.r_is_locked), c_void_p).value, 1)

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # atcab_read_enc(key_id, block, data, enc_key, enc_key_id, num_in):

    r_read_enc_data = create_string_buffer(32)
    r_read_enc_data.value = bytes(bytearray([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                             0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                             0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                             0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]))

    def atcab_read_enc(self, key_id, block, data, enc_key, enc_key_id, num_in):

        if not isinstance(key_id, int):
            raise TypeError

        if not isinstance(block, int):
            raise TypeError

        if not isinstance(data, c_ptr):
            raise TypeError

        if not isinstance(enc_key, bytes):
            raise TypeError

        if not isinstance(enc_key_id, int):
            raise TypeError

        if not isinstance(num_in, bytes):
            raise TypeError

        memmove(cast(data, c_void_p).value, cast(byref(self.r_read_enc_data), c_void_p).value, len(self.r_read_enc_data))

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # atcab_read_config_zone(config_data):

    r_read_config_data = create_string_buffer(128)
    r_read_config_data.value = bytes(bytearray(range(0, 128)))

    def atcab_read_config_zone(self, config_data):

        if not isinstance(config_data, c_ptr):
            raise TypeError

        memmove(cast(config_data, c_void_p).value, cast(byref(self.r_read_config_data), c_void_p).value, len(self.r_read_config_data))

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # atcab_cmp_config_zone(config_data, same_config):

    r_same_config = c_uint8()
    r_same_config.value = 1

    def atcab_cmp_config_zone(self, config_data, same_config):

        if not isinstance(config_data, bytes):
            raise TypeError

        if not isinstance(same_config, c_ptr):
            raise TypeError

        memmove(cast(same_config, c_void_p).value, cast(byref(self.r_same_config), c_void_p).value, 1)

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # atcab_read_sig(slot, sig):

    r_read_sig = create_string_buffer(64)
    r_read_sig.value = bytes(bytearray([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]))

    def atcab_read_sig(self, slot, sig):

        if not isinstance(slot, int):
            raise TypeError

        if not isinstance(sig, c_ptr):
            raise TypeError

        memmove(cast(sig, c_void_p).value, cast(byref(self.r_read_sig), c_void_p).value, len(self.r_read_sig))

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # atcab_read_pubkey(slot, publick_key):

    r_read_pubkey = create_string_buffer(64)
    r_read_pubkey.value = bytes(bytearray([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                           0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                           0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                           0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]))

    def atcab_read_pubkey(self, slot, public_key):

        if not isinstance(slot, int):
            raise TypeError

        if not isinstance(public_key, c_ptr):
            raise TypeError

        memmove(cast(public_key, c_void_p).value, cast(byref(self.r_read_pubkey), c_void_p).value, len(self.r_read_pubkey))

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # atcab_read_bytes_zone(zone, slot, offset, data, length):

    r_read_bytes_zone_data = create_string_buffer(64)
    r_read_bytes_zone_data.value = bytes(bytearray([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]))

    def atcab_read_bytes_zone(self, zone, slot, offset, data, length):

        if not isinstance(zone, int):
            raise TypeError

        if not isinstance(slot, int):
            raise TypeError

        if not isinstance(offset, int):
            raise TypeError

        if not isinstance(data, c_ptr):
            raise TypeError

        if not isinstance(length, int):
            raise TypeError

        memmove(cast(data, c_void_p).value, cast(byref(self.r_read_bytes_zone_data), c_void_p).value, len(self.r_read_bytes_zone_data))

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # atcab_secureboot(self, mode, param2, digest, signature, mac):

    r_sboot_mac = create_string_buffer(32)
    r_sboot_mac.value = bytes(bytearray([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                         0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                         0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                         0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]))

    def atcab_secureboot(self, mode, param2, digest, signature, mac):

        if not isinstance(mode, int):
            raise TypeError

        if not isinstance(param2, int):
            raise TypeError

        if not isinstance(digest, bytes):
            raise TypeError

        if not isinstance(signature, bytes):
            raise TypeError

        if not isinstance(mac, c_ptr):
            raise TypeError

        memmove(cast(mac, c_void_p).value, cast(byref(self.r_sboot_mac), c_void_p).value, len(self.r_sboot_mac))

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # atcab_secureboot_mac(self, mode, digest, signature, num_in, io_keys, is_verified):

    r_sboot_is_verified = c_uint8()
    r_sboot_is_verified.value = 1

    def atcab_secureboot_mac(self, mode, digest, signature, num_in, io_keys, is_verified):

        if not isinstance(mode, int):
            raise TypeError

        if not isinstance(digest, bytes):
            raise TypeError

        if not isinstance(signature, bytes):
            raise TypeError

        if not isinstance(num_in, bytes):
            raise TypeError

        if not isinstance(io_keys, bytes):
            raise TypeError

        if not isinstance(is_verified, c_ptr):
            raise TypeError

        memmove(cast(is_verified, c_void_p).value, cast(byref(self.r_sboot_is_verified), c_void_p).value, 1)

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # atcab_selftest(mode, param2, result):

    r_stest_res = c_uint8()
    r_stest_res.value = 0x29

    def atcab_selftest(self, mode, param2, result):

        if not isinstance(mode, int):
            raise TypeError

        if not isinstance(param2, int):
            raise TypeError

        if not isinstance(result, c_ptr):
            raise TypeError

        memmove(cast(result, c_void_p).value, cast(byref(self.r_stest_res), c_void_p).value, 1)

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # atcab_sha_base(mode, length, message, data_out, data_out_size):

    r_sha_base_data = create_string_buffer(130)
    r_sha_base_data.value = bytes(bytearray(range(0, 130)))

    r_sha_base_data_size = c_uint8()
    r_sha_base_data_size.value = 130

    def atcab_sha_base(self, mode, length, message, data_out, data_out_size):

        if not isinstance(mode, int):
            raise TypeError

        if not isinstance(length, int):
            raise TypeError

        if not isinstance(message, bytes):
            raise TypeError

        if not isinstance(data_out, c_ptr):
            raise TypeError

        if not isinstance(data_out_size, c_ptr):
            raise TypeError

        memmove(cast(data_out, c_void_p).value, cast(byref(self.r_sha_base_data), c_void_p).value, len(self.r_sha_base_data))
        memmove(cast(data_out_size, c_void_p).value, cast(byref(self.r_sha_base_data_size), c_void_p).value, 1)

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # atcab_sha_start():

    def atcab_sha_start(self):
        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # atcab_sha_update(message):

    def atcab_sha_update(self, message):
        if not isinstance(message, bytes):
            raise TypeError
        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # atcab_sha_end(digest, length, message):

    r_sha_digest = create_string_buffer(32)
    r_sha_digest.value = bytes(bytearray([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                          0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                          0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                          0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]))

    def atcab_sha_end(self, digest, length, message):

        if not isinstance(digest, c_ptr):
            raise TypeError

        if not isinstance(length, int):
            raise TypeError

        if not isinstance(message, bytes):
            raise TypeError

        memmove(cast(digest, c_void_p).value, cast(byref(self.r_sha_digest), c_void_p).value, len(self.r_sha_digest))

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # atcab_sha_read_context(context, context_size):

    r_sha_context_data = create_string_buffer(130)
    r_sha_context_data.value = bytes(bytearray(range(0, 130)))

    r_sha_context_size = c_uint8()
    r_sha_context_size.value = 130

    def atcab_sha_read_context(self, context, context_size):

        if not isinstance(context, c_ptr):
            raise TypeError

        if not isinstance(context_size, c_ptr):
            raise TypeError

        memmove(cast(context, c_void_p).value, cast(byref(self.r_sha_context_data), c_void_p).value, len(self.r_sha_context_data))
        memmove(cast(context_size, c_void_p).value, cast(byref(self.r_sha_context_size), c_void_p).value, 1)

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # atcab_sha_write_context(self, context, context_size):

    def atcab_sha_write_context(self, context, context_size):

        if not isinstance(context, bytes):
            raise TypeError

        if not isinstance(context_size, int):
            raise TypeError

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # atcab_sha(length, message, digest):

    def atcab_sha(self, length, message, digest):

        if not isinstance(digest, c_ptr):
            raise TypeError

        if not isinstance(length, int):
            raise TypeError

        if not isinstance(message, bytes):
            raise TypeError

        memmove(cast(digest, c_void_p).value, cast(byref(self.r_sha_digest), c_void_p).value, len(self.r_sha_digest))

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # atcab_hw_sha2_256_init(ctx):

    def atcab_hw_sha2_256_init(self, ctx):

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # atcab_hw_sha2_256_update(ctx, data, data_size):

    def atcab_hw_sha2_256_update(self, ctx, data, data_size):

        if not isinstance(data, bytes):
            raise TypeError

        if not isinstance(data_size, int):
            raise TypeError

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # atcab_hw_sha2_256_finish(ctx, digest):

    def atcab_hw_sha2_256_finish(self, ctx, digest):

        if not isinstance(digest, c_ptr):
            raise TypeError

        memmove(cast(digest, c_void_p).value, cast(byref(self.r_sha_digest), c_void_p).value, len(self.r_sha_digest))

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # atcab_hw_sha2_256(data, data_size, digest):

    def atcab_hw_sha2_256(self, data, data_size, digest):

        if not isinstance(data, bytes):
            raise TypeError

        if not isinstance(data_size, int):
            raise TypeError

        if not isinstance(digest, c_ptr):
            raise TypeError

        memmove(cast(digest, c_void_p).value, cast(byref(self.r_sha_digest), c_void_p).value, len(self.r_sha_digest))

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # atcab_sha_hmac_init(ctx, key_slot):

    def atcab_sha_hmac_init(self, ctx, key_slot):

        if not isinstance(key_slot, int):
            raise TypeError

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # atcab_sha_hmac_update(ctx, data, data_size):

    def atcab_sha_hmac_update(self, ctx, data, data_size):

        if not isinstance(data, bytes):
            raise TypeError

        if not isinstance(data_size, int):
            raise TypeError

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # atcab_sha_hmac_finish(ctx, digest, target):

    def atcab_sha_hmac_finish(self, ctx, digest, target):

        if not isinstance(digest, c_ptr):
            raise TypeError

        if not isinstance(target, int):
            raise TypeError

        memmove(cast(digest, c_void_p).value, cast(byref(self.r_sha_digest), c_void_p).value, len(self.r_sha_digest))

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # atcab_sha_hmac(data, data_size, key_slot, digest, target):

    def atcab_sha_hmac(self, data, data_size, key_slot, digest, target):

        if not isinstance(data, bytes):
            raise TypeError

        if not isinstance(data_size, int):
            raise TypeError

        if not isinstance(key_slot, int):
            raise TypeError

        if not isinstance(digest, c_ptr):
            raise TypeError

        if not isinstance(target, int):
            raise TypeError

        memmove(cast(digest, c_void_p).value, cast(byref(self.r_sha_digest), c_void_p).value, len(self.r_sha_digest))

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # atcab_sign_base(mode, key_id, signature):

    r_signature = create_string_buffer(64)
    r_signature.value = bytes(bytearray([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                         0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                         0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                         0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]))

    def atcab_sign_base(self, mode, key_id, signature):

        if not isinstance(mode, int):
            raise TypeError

        if not isinstance(key_id, int):
            raise TypeError

        if not isinstance(signature, c_ptr):
            raise TypeError

        memmove(cast(signature, c_void_p).value, cast(byref(self.r_signature), c_void_p).value, len(self.r_signature))

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # atcab_sign(key_id, msg, signature):

    def atcab_sign(self, key_id, msg, signature):

        if not isinstance(key_id, int):
            raise TypeError

        if not isinstance(msg, bytes):
            raise TypeError

        if not isinstance(signature, c_ptr):
            raise TypeError

        memmove(cast(signature, c_void_p).value, cast(byref(self.r_signature), c_void_p).value, len(self.r_signature))

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # atcab_sign_internal(key_id, is_invalidate, is_full_sn, signature):

    def atcab_sign_internal(self, key_id, is_invalidate, is_full_sn, signature):

        if not isinstance(key_id, int):
            raise TypeError

        if not isinstance(is_invalidate, int):
            raise TypeError

        if not isinstance(is_full_sn, int):
            raise TypeError

        if not isinstance(signature, c_ptr):
            raise TypeError

        memmove(cast(signature, c_void_p).value, cast(byref(self.r_signature), c_void_p).value, len(self.r_signature))

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # atcab_updateextra(mode, new_value):

    def atcab_updateextra(self, mode, new_value):

        if not isinstance(mode, int):
            raise TypeError

        if not isinstance(new_value, int):
            raise TypeError

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # atcab_verify(mode, key_id, signature, public_key, other_data, mac):

    r_mac = create_string_buffer(64)
    r_mac.value = bytes(bytearray([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                   0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                   0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                   0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]))

    def atcab_verify(self, mode, key_id, signature, public_key, other_data, mac):

        if not isinstance(mode, int):
            raise TypeError

        if not isinstance(key_id, int):
            raise TypeError

        if not isinstance(signature, bytes):
            raise TypeError

        if not isinstance(public_key, bytes):
            raise TypeError

        if not isinstance(other_data, bytes):
            raise TypeError

        if not isinstance(mac, c_ptr):
            raise TypeError

        memmove(cast(mac, c_void_p).value, cast(byref(self.r_mac), c_void_p).value, len(self.r_mac))

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # atcab_verify_extern_stored_mac(mode, key_id, message, signature, public_key, num_in, io_key, is_verified):

    r_verify_is_verified = c_uint8()
    r_verify_is_verified.value = 1

    def atcab_verify_extern_stored_mac(self, mode, key_id, message, signature, public_key, num_in, io_key, is_verified):

        if not isinstance(mode, int):
            raise TypeError

        if not isinstance(key_id, int):
            raise TypeError

        if not isinstance(message, bytes):
            raise TypeError

        if not isinstance(signature, bytes):
            raise TypeError

        if not isinstance(public_key, bytes):
            raise TypeError

        if not isinstance(num_in, bytes):
            raise TypeError

        if not isinstance(io_key, bytes):
            raise TypeError

        if not isinstance(is_verified, c_ptr):
            raise TypeError

        memmove(cast(is_verified, c_void_p).value, cast(byref(self.r_verify_is_verified), c_void_p).value, 1)

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # atcab_verify_extern(message, signature, public_key, is_verified):

    def atcab_verify_extern(self, message, signature, public_key, is_verified):

        if not isinstance(message, bytes):
            raise TypeError

        if not isinstance(signature, bytes):
            raise TypeError

        if not isinstance(public_key, bytes):
            raise TypeError

        if not isinstance(is_verified, c_ptr):
            raise TypeError

        memmove(cast(is_verified, c_void_p).value, cast(byref(self.r_verify_is_verified), c_void_p).value, 1)

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # atcab_verify_extern_mac(message, signature, public_key, num_in, io_key, is_verified):

    def atcab_verify_extern_mac(self, message, signature, public_key, num_in, io_key, is_verified):

        if not isinstance(message, bytes):
            raise TypeError

        if not isinstance(signature, bytes):
            raise TypeError

        if not isinstance(public_key, bytes):
            raise TypeError

        if not isinstance(num_in, bytes):
            raise TypeError

        if not isinstance(io_key, bytes):
            raise TypeError

        if not isinstance(is_verified, c_ptr):
            raise TypeError

        memmove(cast(is_verified, c_void_p).value, cast(byref(self.r_verify_is_verified), c_void_p).value, 1)

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # atcab_verify_stored(message, signature, key_id, is_verified):

    def atcab_verify_stored(self, message, signature, key_id, is_verified):

        if not isinstance(message, bytes):
            raise TypeError

        if not isinstance(signature, bytes):
            raise TypeError

        if not isinstance(key_id, int):
            raise TypeError

        if not isinstance(is_verified, c_ptr):
            raise TypeError

        memmove(cast(is_verified, c_void_p).value, cast(byref(self.r_verify_is_verified), c_void_p).value, 1)

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # atcab_verify_stored_mac(message, signature, key_id, num_in, io_key, is_verified):

    def atcab_verify_stored_mac(self, message, signature, key_id, num_in, io_key, is_verified):

        if not isinstance(message, bytes):
            raise TypeError

        if not isinstance(signature, bytes):
            raise TypeError

        if not isinstance(key_id, int):
            raise TypeError

        if not isinstance(num_in, bytes):
            raise TypeError

        if not isinstance(io_key, bytes):
            raise TypeError

        if not isinstance(is_verified, c_ptr):
            raise TypeError

        memmove(cast(is_verified, c_void_p).value, cast(byref(self.r_verify_is_verified), c_void_p).value, 1)

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # atcab_verify_validate(key_id, signature, other_data, is_verified):

    def atcab_verify_validate(self, key_id, signature, other_data, is_verified):

        if not isinstance(key_id, int):
            raise TypeError

        if not isinstance(signature, bytes):
            raise TypeError

        if not isinstance(other_data, bytes):
            raise TypeError

        if not isinstance(is_verified, c_ptr):
            raise TypeError

        memmove(cast(is_verified, c_void_p).value, cast(byref(self.r_verify_is_verified), c_void_p).value, 1)

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # atcab_verify_invalidate(key_id, signature, other_data, is_verified):

    def atcab_verify_invalidate(self, key_id, signature, other_data, is_verified):

        if not isinstance(key_id, int):
            raise TypeError

        if not isinstance(signature, bytes):
            raise TypeError

        if not isinstance(other_data, bytes):
            raise TypeError

        if not isinstance(is_verified, c_ptr):
            raise TypeError

        memmove(cast(is_verified, c_void_p).value, cast(byref(self.r_verify_is_verified), c_void_p).value, 1)

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # atcab_write(zone, address, value, mac):

    def atcab_write(self, zone, address, value, mac):

        if not isinstance(zone, int):
            raise TypeError

        if not isinstance(address, int):
            raise TypeError

        if not isinstance(value, bytes):
            raise TypeError

        if not isinstance(mac, bytes):
            raise TypeError

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # atcab_write_zone(zone, slot, block, offset, data, length):

    def atcab_write_zone(self, zone, slot, block, offset, data, length):

        if not isinstance(zone, int):
            raise TypeError

        if not isinstance(slot, int):
            raise TypeError

        if not isinstance(block, int):
            raise TypeError

        if not isinstance(offset, int):
            raise TypeError

        if not isinstance(data, bytes):
            raise TypeError

        if not isinstance(length, int):
            raise TypeError

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # atcab_write_enc(key_id, block, data, enc_key, enc_key_id, num_in):

    def atcab_write_enc(self, key_id, block, data, enc_key, enc_key_id, num_in):

        if not isinstance(key_id, int):
            raise TypeError

        if not isinstance(block, int):
            raise TypeError

        if not isinstance(data, bytes):
            raise TypeError

        if not isinstance(enc_key, bytes):
            raise TypeError

        if not isinstance(enc_key_id, int):
            raise TypeError

        if not isinstance(num_in, bytes):
            raise TypeError

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # atcab_write_config_zone(conf):

    def atcab_write_config_zone(self, conf):

        if not isinstance(conf, bytes):
            raise TypeError

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # def atcab_write_pubkey(slot, public_key):

    def atcab_write_pubkey(self, slot, public_key):

        if not isinstance(slot, int):
            raise TypeError

        if not isinstance(public_key, bytes):
            raise TypeError

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # def atcab_write_bytes_zone(zone, slot, offset_bytes, data, length):

    def atcab_write_bytes_zone(self, zone, slot, offset_bytes, data, length):

        if not isinstance(zone, int):
            raise TypeError

        if not isinstance(slot, int):
            raise TypeError

        if not isinstance(offset_bytes, int):
            raise TypeError

        if not isinstance(data, bytes):
            raise TypeError

        if not isinstance(length, int):
            raise TypeError

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # atcab_write_config_counter(counter_id, counter_value):

    def atcab_write_config_counter(self, counter_id, counter_value):

        if not isinstance(counter_id, int):
            raise TypeError

        if not isinstance(counter_value, int):
            raise TypeError

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # atcacert_get_response(device_private_key_slot, challenge, response):

    r_response = create_string_buffer(64)
    r_response.value = bytes(bytearray([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]))

    def atcacert_get_response(self, device_private_key_slot, challenge, response):

        if not isinstance(device_private_key_slot, int):
            raise TypeError

        if not isinstance(challenge, bytes):
            raise TypeError

        if not isinstance(response, c_ptr):
            raise TypeError

        memmove(cast(response, c_void_p).value, cast(byref(self.r_response), c_void_p).value, len(self.r_response))

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # atcacert_read_cert(cert_def, ca_public_key, cert, cert_size):

    r_cert_size = c_size_t(64)

    r_cert = create_string_buffer(r_cert_size.value)
    r_cert.value = bytes(bytearray([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]))

    def atcacert_read_cert(self, cert_def, ca_public_key, cert, cert_size):

        if not isinstance(ca_public_key, bytes):
            raise TypeError

        if not isinstance(cert, c_ptr):
            raise TypeError

        if not isinstance(cert_size, c_ptr):
            raise TypeError

        if cast(cert_size, POINTER(c_uint32)).contents.value < len(self.r_cert):
            raise ValueError

        memmove(cast(cert, c_void_p).value, cast(byref(self.r_cert), c_void_p).value, len(self.r_cert))
        memmove(cert_size, byref(self.r_cert_size), sizeof(self.r_cert_size))

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # atcacert_write_cert(self, cert_def, cert, cert_size):

    def atcacert_write_cert(self, cert_def, cert, cert_size):

        if not isinstance(cert, bytes):
            raise TypeError

        if not isinstance(cert_size, int):
            raise TypeError

        return Status.ATCA_SUCCESS


    #--------------------------------------------------------------------#
    # atcacert_create_csr(self, csr_def, csr, csr_size):

    r_csr_size = c_uint8()
    r_csr_size.value = 64

    r_csr = create_string_buffer(64)
    r_csr.value = bytes(bytearray([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                   0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                   0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                   0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]))

    def atcacert_create_csr(self, csr_def, csr, csr_size):

        if not isinstance(csr, c_ptr):
            raise TypeError

        if not isinstance(csr_size, c_ptr):
            raise TypeError

        memmove(cast(csr, c_void_p).value, cast(byref(self.r_csr), c_void_p).value, len(self.r_csr))
        memmove(cast(csr_size, c_void_p).value, cast(byref(self.r_csr_size), c_void_p).value, 1)

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # atcacert_create_csr_pem(self, csr_def, csr, csr_size):

    def atcacert_create_csr_pem(self, csr_def, csr, csr_size):

        if not isinstance(csr, c_ptr):
            raise TypeError

        if not isinstance(csr_size, c_ptr):
            raise TypeError

        memmove(cast(csr, c_void_p).value, cast(byref(self.r_csr), c_void_p).value, len(self.r_csr))
        memmove(cast(csr_size, c_void_p).value, cast(byref(self.r_csr_size), c_void_p).value, 1)

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # atcacert_date_enc(format, timestamp, formatted_date, formatted_date_size):

    r_formatted_date = create_string_buffer(3)
    r_formatted_date.value = bytes(bytearray([0x00, 0x01, 0x02]))

    r_formatted_date_size = c_uint8()
    r_formatted_date_size.value = 3

    def atcacert_date_enc(self, format, timestamp, formatted_date, formatted_date_size):

        if not isinstance(formatted_date, c_ptr):
            raise TypeError

        if not isinstance(formatted_date_size, c_ptr):
            raise TypeError

        memmove(cast(formatted_date, c_void_p).value, cast(byref(self.r_formatted_date), c_void_p).value, len(self.r_formatted_date))
        memmove(cast(formatted_date_size, c_void_p).value, cast(byref(self.r_formatted_date_size), c_void_p).value, 1)

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # atcacert_date_dec( format, formatted_date, formatted_date_size, timestamp):

    def atcacert_date_dec(self, format, formatted_date, formatted_date_size, timestamp):

        if not isinstance(formatted_date, bytes):
            raise TypeError

        if not isinstance(formatted_date_size, int):
            raise TypeError

        timestamp.tm_sec = 12
        timestamp.tm_min = 2
        timestamp.tm_hour = 3
        timestamp.tm_mday = 4
        timestamp.tm_mon = 5
        timestamp.tm_year = 2018

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # atcacert_date_enc_compcert(issue_date, expire_years, enc_dates):

    r_enc_dates = create_string_buffer(3)
    r_enc_dates.value = bytes(bytearray([0x00, 0x01, 0x02]))

    def atcacert_date_enc_compcert(self, issue_date, expire_years, enc_dates):

        if not isinstance(expire_years, int):
            raise TypeError

        if not isinstance(enc_dates, c_ptr):
            raise TypeError

        memmove(cast(enc_dates, c_void_p).value, cast(byref(self.r_enc_dates), c_void_p).value, len(self.r_enc_dates))

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # atcacert_date_dec_compcert(enc_dates, expire_date_format, issue_date, expire_date):

    def atcacert_date_dec_compcert(self, enc_dates, expire_date_format, issue_date, expire_date):

        if not isinstance(enc_dates, bytes):
            raise TypeError

        issue_date.tm_sec = 12
        expire_date.tm_sec = 12

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # atcacert_date_get_max_date(date_format, timestamp):

    def atcacert_date_get_max_date(self, date_format, timestamp):

        timestamp.tm_sec = 12

        return Status.ATCA_SUCCESS


    r_max_cert_size = c_size_t(123)

    def atcacert_max_cert_size(self, cert_def, max_cert_size):

        if not isinstance(cert_def, c_ptr):
            raise TypeError

        if not isinstance(max_cert_size, c_ptr):
            raise TypeError

        memmove(max_cert_size, byref(self.r_max_cert_size), sizeof(self.r_max_cert_size))

        return Status.ATCA_SUCCESS


    r_tng_type = c_int(1)


    def tng_get_device_pubkey(self, public_key):

        if not isinstance(public_key, c_ptr):
            raise TypeError

        memmove(public_key, byref(self.r_genkey_pubkey), sizeof(self.r_genkey_pubkey))

        return Status.ATCA_SUCCESS


    def tng_atcacert_max_device_cert_size(self, max_cert_size):

        if not isinstance(max_cert_size, c_ptr):
            raise TypeError

        memmove(max_cert_size, byref(self.r_max_cert_size), sizeof(self.r_max_cert_size))

        return CertStatus.ATCACERT_E_SUCCESS


    def tng_atcacert_read_device_cert(self, cert, cert_size, signer_cert):

        if not isinstance(cert, c_ptr):
            raise TypeError

        if not isinstance(cert_size, c_ptr):
            raise TypeError

        if signer_cert is not None and not isinstance(signer_cert, bytes):
            raise TypeError

        memmove(cert, byref(self.r_cert), sizeof(self.r_cert))
        memmove(cert_size, byref(self.r_cert_size), sizeof(self.r_cert_size))

        return CertStatus.ATCACERT_E_SUCCESS


    def tng_atcacert_device_public_key(self, public_key, cert):

        if not isinstance(public_key, c_ptr):
            raise TypeError

        if cert is not None and not isinstance(cert, bytes):
            raise TypeError

        memmove(public_key, byref(self.r_genkey_pubkey), sizeof(self.r_genkey_pubkey))

        return CertStatus.ATCACERT_E_SUCCESS


    def tng_atcacert_max_signer_cert_size(self, max_cert_size):

        if not isinstance(max_cert_size, c_ptr):
            raise TypeError

        memmove(max_cert_size, byref(self.r_max_cert_size), sizeof(self.r_max_cert_size))

        return CertStatus.ATCACERT_E_SUCCESS


    def tng_atcacert_read_signer_cert(self, cert, cert_size):

        if not isinstance(cert, c_ptr):
            raise TypeError

        if not isinstance(cert_size, c_ptr):
            raise TypeError

        memmove(cert, byref(self.r_cert), sizeof(self.r_cert))
        memmove(cert_size, byref(self.r_cert_size), sizeof(self.r_cert_size))

        return CertStatus.ATCACERT_E_SUCCESS


    def tng_atcacert_signer_public_key(self, public_key, cert):

        if not isinstance(public_key, c_ptr):
            raise TypeError

        if cert is not None and not isinstance(cert, bytes):
            raise TypeError

        memmove(public_key, byref(self.r_genkey_pubkey), sizeof(self.r_genkey_pubkey))

        return CertStatus.ATCACERT_E_SUCCESS


    def tng_atcacert_root_cert_size(self, cert_size):

        if not isinstance(cert_size, c_ptr):
            raise TypeError

        memmove(cert_size, byref(self.r_cert_size), sizeof(self.r_cert_size))

        return CertStatus.ATCACERT_E_SUCCESS


    def tng_atcacert_root_cert(self, cert, cert_size):

        if not isinstance(cert, c_ptr):
            raise TypeError

        if not isinstance(cert_size, c_ptr):
            raise TypeError

        memmove(cert, byref(self.r_cert), sizeof(self.r_cert))
        memmove(cert_size, byref(self.r_cert_size), sizeof(self.r_cert_size))

        return CertStatus.ATCACERT_E_SUCCESS


    def tng_atcacert_root_public_key(self, public_key):

        if not isinstance(public_key, c_ptr):
            raise TypeError

        memmove(public_key, byref(self.r_genkey_pubkey), sizeof(self.r_genkey_pubkey))

        return CertStatus.ATCACERT_E_SUCCESS

    #--------------------------------------------------------------------#
    # sha206a_generate_derive_key(parent_key, derived_key, param1, param2):

    r_derived_key = create_string_buffer(32)
    r_derived_key.value = bytes(bytearray([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                           0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                           0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                           0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]))

    def sha206a_generate_derive_key(self, parent_key, derived_key, param1, param2):

        if not isinstance(parent_key, bytes):
            raise TypeError

        if not isinstance(derived_key, c_ptr):
            raise TypeError

        if not isinstance(param1, int):
            raise TypeError

        if not isinstance(param2, int):
            raise TypeError

        memmove(cast(derived_key, c_void_p).value, cast(byref(self.r_derived_key), c_void_p).value, len(self.r_derived_key))

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # sha206a_diversify_parent_key(parent_key, diversified_key):

    r_diversified_key = create_string_buffer(32)
    r_diversified_key.value = bytes(bytearray([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                               0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                               0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                               0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]))

    def sha206a_diversify_parent_key(self, parent_key, diversified_key):

        if not isinstance (parent_key, bytes):
            raise TypeError

        if not isinstance (diversified_key, c_ptr):
            raise TypeError

        memmove(cast(diversified_key, c_void_p).value, cast(byref(self.r_diversified_key), c_void_p).value, len(self.r_diversified_key))

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # sha206a_generate_challenge_response_pair(key, challenge, response):

    r_challenge_response = create_string_buffer(32)
    r_challenge_response.value = bytes(bytearray([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                                  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                                  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                                  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]))

    def sha206a_generate_challenge_response_pair(self, key, challenge, response):

        if not isinstance(key, bytes):
            raise TypeError

        if not isinstance(challenge, bytes):
            raise TypeError

        if not isinstance(response, c_ptr):
            raise TypeError

        memmove(cast(response, c_void_p).value, cast(byref(self.r_challenge_response), c_void_p).value, len(self.r_challenge_response))

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # sha206a_authenticate(challenge, expected_response, is_verified):

    def sha206a_authenticate(self, challenge, expected_response, is_verified):

        if not isinstance(challenge, bytes):
            raise TypeError

        if not isinstance(expected_response, bytes):
            raise TypeError

        if not isinstance(is_verified, c_ptr):
            raise TypeError

        memmove(cast(is_verified, c_void_p).value, cast(byref(self.r_verify_is_verified), c_void_p).value, 1)

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # sha206a_write_data_store(slot, data, block, offset, length, lock_after_write):

    def sha206a_write_data_store(self, slot, data, block, offset, length, lock_after_write):

        if not isinstance(slot, int):
            raise TypeError

        if not isinstance(data, bytes):
            raise TypeError

        if not isinstance(block, int):
            raise TypeError

        if not isinstance(offset, int):
            raise TypeError

        if not isinstance(length, int):
            raise TypeError

        if not isinstance(lock_after_write, int):
            raise TypeError

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # sha206a_read_data_store(slot, data, block, offset, length):

    def sha206a_read_data_store(self, slot, data, offset, length):

        if not isinstance(slot, int):
            raise TypeError

        if not isinstance(data, c_ptr):
            raise TypeError

        if not isinstance(offset, int):
            raise TypeError

        if not isinstance(length, int):
            raise TypeError

        memmove(cast(data, c_void_p).value, cast(byref(self.r_read_zone_data), c_void_p).value, len(self.r_read_zone_data))

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # sha206a_get_data_store_lock_status(slot, is_locked):

    r_verify_is_locked = c_uint8()
    r_verify_is_locked.value = 1

    def sha206a_get_data_store_lock_status(self, slot, is_locked):

        if not isinstance(slot, int):
            raise TypeError

        if not isinstance(is_locked, c_ptr):
            raise TypeError

        memmove(cast(is_locked, c_void_p).value, cast(byref(self.r_verify_is_locked), c_void_p).value, 1)

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # sha206a_get_dk_update_count(dk_update_count):

    r_dk_update_count = c_uint8()
    r_dk_update_count.value = 1

    def sha206a_get_dk_update_count(self, dk_update_count):

        if not isinstance(dk_update_count, c_ptr):
            raise TypeError

        memmove(cast(dk_update_count, c_void_p).value, cast(byref(self.r_dk_update_count), c_void_p).value, 1)

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # sha206a_get_pk_useflag_count(pk_avail_count):

    r_pk_avail_count = c_uint8()
    r_pk_avail_count.value = 1

    def sha206a_get_pk_useflag_count(self, pk_avail_count):

        if not isinstance(pk_avail_count, c_ptr):
            raise TypeError

        memmove(cast(pk_avail_count, c_void_p).value, cast(byref(self.r_pk_avail_count), c_void_p).value, 1)

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # sha206a_get_dk_useflag_count(dk_avail_count):

    r_dk_avail_count = c_uint8()
    r_dk_avail_count.value = 1

    def sha206a_get_dk_useflag_count(self, dk_avail_count):

        if not isinstance(dk_avail_count, c_ptr):
            raise TypeError

        memmove(cast(dk_avail_count, c_void_p).value, cast(byref(self.r_dk_avail_count), c_void_p).value, 1)
        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # sha206a_check_pk_useflag_validity(is_consumed):

    r_verify_is_consumed = c_uint8()
    r_verify_is_consumed.value = 1

    def sha206a_check_pk_useflag_validity(self, is_consumed):

        if not isinstance(is_consumed, c_ptr):
            raise TypeError

        memmove(cast(is_consumed, c_void_p).value, cast(byref(self.r_verify_is_consumed), c_void_p).value, 1)

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # sha206a_check_dk_useflag_validity(is_consumed):

    def sha206a_check_dk_useflag_validity(self, is_consumed):

        if not isinstance(is_consumed, c_ptr):
            raise TypeError

        memmove(cast(is_consumed, c_void_p).value, cast(byref(self.r_verify_is_consumed), c_void_p).value, 1)

        return Status.ATCA_SUCCESS

    #--------------------------------------------------------------------#
    # sha206a_verify_device_consumption(is_consumed):

    def sha206a_verify_device_consumption(self, is_consumed):

        if not isinstance(is_consumed, c_ptr):
            raise TypeError

        memmove(cast(is_consumed, c_void_p).value, cast(byref(self.r_verify_is_consumed), c_void_p).value, 1)

        return Status.ATCA_SUCCESS



