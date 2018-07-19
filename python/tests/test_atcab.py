from cryptoauthlib import *
from cryptoauthlib_mock import atcab_mock
import pytest
import binascii

@pytest.fixture(scope="module")
def test_init():
    load_cryptoauthlib(atcab_mock())

#---------------ATCA_BASIC_AES--------------#

def test_atcab_aes(test_init):
    mode = 23
    key_id = 10
    aes_in = bytearray(16)
    aes_out = bytearray(16)
    assert atcab_aes(mode, key_id, aes_in, aes_out) == Status.ATCA_SUCCESS
    assert aes_out == bytearray(atcab_mock.r_aes_out)

def test_atcab_aes_encrypt(test_init):
    key_id = 10
    key_block = 3
    plaintext = bytearray(16)
    ciphertext = bytearray(16)
    assert atcab_aes_encrypt(key_id, key_block, plaintext, ciphertext) == Status.ATCA_SUCCESS
    assert ciphertext == bytearray(atcab_mock.r_ciphertext)

def test_atcab_aes_decrypt(test_init):
    key_id = 10
    key_block = 3
    plaintext = bytearray(16)
    ciphertext = bytearray(16)
    assert atcab_aes_encrypt(key_id, key_block, ciphertext, plaintext) == Status.ATCA_SUCCESS
    assert plaintext == bytearray(atcab_mock.r_plaintext)

def test_atcab_aes_gfm(test_init):
    hash_key = bytearray(16)
    inp = bytearray(16)
    output = bytearray(16)
    assert atcab_aes_gfm(hash_key, inp, output) == Status.ATCA_SUCCESS
    assert output == bytearray(atcab_mock.r_aes_gfm_output)

#---------------ATCA_BASIC_CHECKMAC--------------#

def test_atcab_checkmac(test_init):
    mode = 2
    key_id = 3
    challenge = bytearray(32)
    response = bytearray(32)
    other_data = bytearray(13)
    assert atcab_checkmac(mode, key_id, challenge, response, other_data) == Status.ATCA_SUCCESS

#---------------ATCA_BASIC_COUNTER--------------#

def test_atcab_counter(test_init):
    mode = 2
    counter_id = 3
    counter_value = []
    assert atcab_counter(mode, counter_id, counter_value) == Status.ATCA_SUCCESS
    assert counter_value[0] == (atcab_mock.r_counter_value).value

def test_atcab_counter_increment(test_init):
    counter_id = 3
    counter_value = []
    assert atcab_counter_increment(counter_id, counter_value) == Status.ATCA_SUCCESS
    assert counter_value[0] == (atcab_mock.r_counter_value).value

def test_atcab_counter_read(test_init):
    counter_id = 3
    counter_value = []
    assert atcab_counter_read(counter_id, counter_value) == Status.ATCA_SUCCESS
    assert counter_value[0] == (atcab_mock.r_counter_value).value

#---------------ATCA_BASIC_DERIVEKKEY--------------#
def test_atcab_derivekey(test_init):
    mode = 3
    target_key = 5
    mac = bytearray(32)
    assert atcab_derivekey(mode, target_key, mac) == Status.ATCA_SUCCESS

#-----------------ATCA_BASIC_ECDH-------------------#
def test_atcab_ecdh_base(test_init):
    mode =3
    key_id = 5
    public_key = bytearray(64)
    pms = bytearray(32)
    out_nonce = bytearray(32)
    assert atcab_ecdh_base(mode, key_id, public_key, pms, out_nonce) == Status.ATCA_SUCCESS
    assert pms == bytearray(atcab_mock.r_ecdh_pms)
    assert out_nonce == bytearray(atcab_mock.r_ecdh_out_nonce)

def test_atcab_ecdh(test_init):
    key_id = 5
    public_key = bytearray(64)
    pms = bytearray(32)
    assert atcab_ecdh(key_id, public_key, pms) == Status.ATCA_SUCCESS
    assert pms == bytearray(atcab_mock.r_ecdh_pms)

def test_atcab_ecdh_enc(test_init):
    key_id = 5
    public_key = bytearray(64)
    pms = bytearray(32)
    readkey= bytearray(32)
    readkey_id =7
    assert atcab_ecdh_enc(key_id, public_key, pms, readkey, readkey_id) == Status.ATCA_SUCCESS
    assert pms == bytearray(atcab_mock.r_ecdh_pms)

def test_atcab_ecdh_ioenc(test_init):
    key_id = 5
    public_key = bytearray(64)
    pms = bytearray(32)
    io_key = bytearray(32)
    assert atcab_ecdh_ioenc(key_id, public_key, pms, io_key) == Status.ATCA_SUCCESS
    assert pms == bytearray(atcab_mock.r_ecdh_pms)


def test_atcab_ecdh_tempkey(test_init):
    public_key = bytearray(64)
    pms = bytearray(32)
    assert atcab_ecdh_tempkey(public_key, pms) == Status.ATCA_SUCCESS

def test_atcab_ecdh_tempkey_ioenc(test_init):
    public_key = bytearray(64)
    pms = bytearray(32)
    io_key = bytearray(32)
    assert atcab_ecdh_tempkey_ioenc(public_key, pms, io_key) == Status.ATCA_SUCCESS
    assert pms == bytearray(atcab_mock.r_ecdh_pms)


#-----------------ATCA_BASIC_GENDIG-------------------#
def test_atcab_gendig(test_init):
    zone = 2
    key_id = 4
    other_data = bytearray(32)
    other_data_size = 32
    assert atcab_gendig(zone, key_id, other_data, other_data_size) == Status.ATCA_SUCCESS

#-----------------ATCA_BASIC_GENKEY-------------------#

def test_atcab_genkey_base(test_init):
    mode = 4
    key_id = 3
    other_data = bytearray(32)
    public_key = bytearray(64)
    assert atcab_genkey_base(mode, key_id, other_data, public_key) == Status.ATCA_SUCCESS
    assert public_key == bytearray(atcab_mock.r_genkey_pubkey)

def test_atcab_genkey(test_init):
    key_id = 3
    public_key = bytearray(64)
    assert atcab_genkey(key_id, public_key) == Status.ATCA_SUCCESS
    assert public_key == bytearray(atcab_mock.r_genkey_pubkey)

def test_atcab_get_publickey(test_init):
    key_id = 3
    public_key = bytearray(64)
    assert atcab_get_pubkey(key_id, public_key) == Status.ATCA_SUCCESS
    assert public_key == bytearray(atcab_mock.r_genkey_pubkey)

#-----------------ATCA_BASIC_HMAC-------------------#

def test_atcab_hmac(test_init):
    mode = 3
    key_id = 4
    digest = bytearray(32)
    assert atcab_hmac(mode, key_id, digest) == Status.ATCA_SUCCESS
    assert digest == bytearray(atcab_mock.r_hmac_digest)

#-----------------ATCA_BASIC_INFO-------------------#

def test_atcab_info_base(test_init):
    mode = 2
    param2 = 0
    out_data = bytearray(4)
    assert atcab_info_base(mode, param2, out_data) == Status.ATCA_SUCCESS
    assert out_data == bytearray(atcab_mock.r_revision)

def test_atcab_info(test_init):
    revision = bytearray(4)
    assert atcab_info(revision) == Status.ATCA_SUCCESS
    assert revision == bytearray(atcab_mock.r_revision)

def test_atcab_info_get_latch(test_init):
    state = bytearray(1)
    assert atcab_info_get_latch(state) == Status.ATCA_SUCCESS
    assert state[0] == atcab_mock.r_latch_state.value

def test_atcab_info_set_latch(test_init):
    state = 1
    assert atcab_info_set_latch(state) == Status.ATCA_SUCCESS

#-----------------ATCA_BASIC_KDF-------------------#

def test_atcab_kdf(test_init):
    mode = 2
    key_id = 4
    details = bytearray(4)
    message = bytearray(128)
    out_data = bytearray(64)
    out_nonce = bytearray(32)
    assert atcab_kdf(mode, key_id, details, message, out_data, out_nonce) == Status.ATCA_SUCCESS
    assert out_data == bytearray(atcab_mock.r_kdf_out_data)
    assert out_nonce == bytearray(atcab_mock.r_kdf_out_nonce)

#-----------------ATCA_BASIC_LOCK-------------------#

def test_atcab_lock(test_init):
    mode = 2
    summary_crc = 0x2345
    assert atcab_lock(mode, summary_crc) == Status.ATCA_SUCCESS

def test_atcab_lock_config_zone(test_init):
    assert atcab_lock_config_zone() == Status.ATCA_SUCCESS

def test_atcab_lock_config_zone_crc(test_init):
    summary_crc = 0x2343
    assert atcab_lock_config_zone_crc(summary_crc) == Status.ATCA_SUCCESS

def test_atcab_lock_data_zone(test_init):
    assert atcab_lock_data_zone() == Status.ATCA_SUCCESS

def test_atcab_lock_data_zone_crc(test_init):
    summary_crc = 0x2343
    assert atcab_lock_data_zone_crc(summary_crc) == Status.ATCA_SUCCESS

def test_atcab_lock_data_slot(test_init):
    slot = 11
    assert atcab_lock_data_slot(slot) == Status.ATCA_SUCCESS

#-----------------ATCA_BASIC_MAC-------------------#

def test_atcab_mac(test_init):
    mode = 2
    key_id = 4
    challenge = bytearray(32)
    digest = bytearray(32)
    assert atcab_mac(mode, key_id, challenge, digest) == Status.ATCA_SUCCESS
    assert digest == bytearray(atcab_mock.r_mac_digest)

#-----------------ATCA_BASIC_NONCE-------------------#

def test_atcab_nonce_base(test_init):
    mode = 2
    zero = 0
    num_in = bytearray(32)
    rand_out = bytearray(32)
    assert atcab_nonce_base(mode, zero, num_in, rand_out) == Status.ATCA_SUCCESS
    assert rand_out == bytearray(atcab_mock.r_nonce_rand_out)

def test_atcab_nonce(test_init):
    num_in = bytearray(32)
    assert atcab_nonce(num_in) == Status.ATCA_SUCCESS

def test_atcab_nonce_load(test_init):
    target = 8
    num_in = bytearray(64)
    num_in_size = len(num_in)
    assert atcab_nonce_load(target, num_in, num_in_size) == Status.ATCA_SUCCESS

def test_atcab_nonce_rand(test_init):
    num_in = bytearray(32)
    rand_out = bytearray(32)
    assert atcab_nonce_rand(num_in, rand_out) == Status.ATCA_SUCCESS
    assert rand_out == bytearray(atcab_mock.r_nonce_rand_out)

def test_atcab_challenge(test_init):
    num_in = bytearray(32)
    assert atcab_challenge(num_in) == Status.ATCA_SUCCESS

def test_atcab_challenge_seed_update(test_init):
    num_in = bytearray(32)
    rand_out = bytearray(32)
    assert atcab_challenge_seed_update(num_in, rand_out) == Status.ATCA_SUCCESS
    assert rand_out == bytearray(atcab_mock.r_nonce_rand_out)

#-----------------ATCA_BASIC_PRIV_WRITE-------------------#

def test_atcab_priv_write(test_init):
    key_id= 4
    priv_key = bytearray(36)
    write_key_id = 5
    write_key = bytearray(32)
    assert atcab_priv_write(key_id, priv_key, write_key_id, write_key) == Status.ATCA_SUCCESS

#-----------------ATCA_BASIC_RANDOM-------------------#

def test_atcab_random(test_init):
    random_number = bytearray(32)
    assert atcab_random(random_number) == Status.ATCA_SUCCESS
    assert random_number == bytearray(atcab_mock.r_rand_out)

#-----------------ATCA_BASIC_READ-------------------#

def test_atcab_read_zone(test_init):
    zone = 2
    slot = 2
    block = 0
    offset = 0
    data = bytearray(32)
    length = 32
    assert atcab_read_zone(zone, slot, block, offset, data, length) == Status.ATCA_SUCCESS
    assert data == bytearray(atcab_mock.r_read_zone_data)

def test_atcab_read_serial_number(test_init):
    serial_number = bytearray(9)
    assert atcab_read_serial_number(serial_number) == Status.ATCA_SUCCESS
    assert serial_number == bytearray(atcab_mock.r_ser_num)

def test_atcab_is_slot_locked(test_init):
    slot = 2
    is_locked = bytearray(1)
    assert atcab_is_slot_locked(slot, is_locked) == Status.ATCA_SUCCESS
    assert is_locked[0] == atcab_mock.r_is_locked.value

def test_atcab_is_locked(test_init):
    zone = 3
    is_locked = bytearray(1)
    assert atcab_is_locked(zone, is_locked) == Status.ATCA_SUCCESS
    assert is_locked[0] == atcab_mock.r_is_locked.value

def test_atcab_read_enc(test_init):
    key_id = 2
    block = 0
    data = bytearray(32)
    enc_key = bytearray(32)
    enc_key_id = 4
    assert atcab_read_enc(key_id, block, data, enc_key, enc_key_id) == Status.ATCA_SUCCESS
    assert data == bytearray(atcab_mock.r_read_enc_data)

def test_atcab_read_config_zone(test_init):
    config_data = bytearray(128)
    assert atcab_read_config_zone(config_data) == Status.ATCA_SUCCESS
    assert config_data == bytearray(atcab_mock.r_read_config_data)

def test_atcab_cmp_config_zone(test_init):
    same_config = bytearray(1)
    config_data = bytearray(128)
    assert atcab_cmp_config_zone(config_data, same_config) == Status.ATCA_SUCCESS
    assert same_config[0] == atcab_mock.r_same_config.value

def test_atcab_read_sig(test_init):
    slot = 2
    sig = bytearray(64)
    assert atcab_read_sig(slot, sig) == Status.ATCA_SUCCESS
    assert sig == bytearray(atcab_mock.r_read_sig)

def test_atcab_read_pubkey(test_init):
    slot = 3
    public_key = bytearray(64)
    assert atcab_read_pubkey(slot, public_key) == Status.ATCA_SUCCESS
    assert public_key == bytearray(atcab_mock.r_read_pubkey)

def test_atcab_read_bytes_zone(test_init):
    zone = 2
    slot = 4
    offset = 3
    data = bytearray(64)
    length = 64
    assert atcab_read_bytes_zone(zone, slot, offset, data, length) == Status.ATCA_SUCCESS
    assert data == bytearray(atcab_mock.r_read_bytes_zone_data)

#-----------------ATCA_BASIC_SECUREBOOT-------------------#

def test_atcab_secureboot(test_init):
    mode = 2
    param2= 34
    digest = bytearray(32)
    signature = bytearray(64)
    mac = bytearray(32)
    assert atcab_secureboot(mode, param2, digest, signature, mac) == Status.ATCA_SUCCESS
    assert mac == bytearray(atcab_mock.r_sboot_mac)

def test_atcab_secureboot_mac(test_init):
    mode = 2
    digest = bytearray(32)
    signature = bytearray(64)
    num_in = bytearray(20)
    io_key = bytearray(32)
    is_verified = bytearray(1)
    assert atcab_secureboot_mac(mode, digest, signature, num_in, io_key, is_verified) == Status.ATCA_SUCCESS
    assert is_verified[0] == atcab_mock.r_sboot_is_verified.value

#-----------------ATCA_BASIC_SELFTEST-------------------#

def test_atcab_selftest(test_init):
    mode = 2
    param2 = 3
    result = bytearray(1)
    assert atcab_selftest(mode, param2, result) == Status.ATCA_SUCCESS
    assert result[0] == atcab_mock.r_stest_res.value

#-----------------ATCA_BASIC_SHA-------------------#

def test_atcab_sha_base(test_init):
    mode = 2
    length = 130
    message = bytearray(64)
    data_out = bytearray(130)
    data_out_size = bytearray(1)
    assert atcab_sha_base(mode, length, message, data_out, data_out_size) == Status.ATCA_SUCCESS
    assert data_out == bytearray(atcab_mock.r_sha_base_data)

def test_atcab_sha_start(test_init):
    assert atcab_sha_start() == Status.ATCA_SUCCESS

def test_atcab_sha_update(test_init):
    message = bytearray(64)
    assert atcab_sha_update(message) == Status.ATCA_SUCCESS

def test_atcab_sha_end(test_init):
    digest = bytearray(32)
    length = 32
    message = bytearray(32)
    assert atcab_sha_end(digest, length, message) == Status.ATCA_SUCCESS
    assert digest == bytearray(atcab_mock.r_sha_digest)

def test_atcab_sha_read_context(test_init):
    context = bytearray(130)
    context_size = bytearray(1)
    context_size[0] = 130
    assert atcab_sha_read_context(context, context_size) == Status.ATCA_SUCCESS
    assert context == bytearray(atcab_mock.r_sha_context_data)

def test_atcab_write_context(test_init):
    context = bytearray(130)
    context_size = 130
    assert atcab_sha_write_context(context, context_size) == Status.ATCA_SUCCESS

def test_atcab_sha(test_init):
    length = 32
    message = bytearray(32)
    digest = bytearray(32)
    assert atcab_sha(length, message, digest) == Status.ATCA_SUCCESS
    assert digest == bytearray(atcab_mock.r_sha_digest)

def test_atcab_hw_sha2_256_init(test_init):
    ctx = bytearray(130)
    assert atcab_hw_sha2_256_init(ctx) == Status.ATCA_SUCCESS

def test_atcab_hw_sha2_256_update(test_init):
    ctx = bytearray(130)
    data = bytearray(32)
    data_size = 32
    assert atcab_hw_sha2_256_update(ctx, data, data_size) == Status.ATCA_SUCCESS

def test_atcab_hw_sha2_256_finish(test_init):
    ctx = bytearray(130)
    digest = bytearray(32)
    assert atcab_hw_sha2_256_finish(ctx, digest) == Status.ATCA_SUCCESS
    assert digest == bytearray(atcab_mock.r_sha_digest)

def test_atcab_hw_sha2_256(test_init):
    data = bytearray(32)
    data_size = 32
    digest = bytearray(32)
    assert atcab_hw_sha2_256(data, data_size, digest) == Status.ATCA_SUCCESS
    assert digest == bytearray(atcab_mock.r_sha_digest)

def test_atcab_sha_hmac_init(test_init):
    ctx = bytearray(32)
    key_slot = 5
    assert atcab_sha_hmac_init(ctx, key_slot) == Status.ATCA_SUCCESS

def test_atcab_sha_hmac_update(test_init):
    ctx = bytearray(32)
    data = bytearray(32)
    data_size = 32
    assert atcab_sha_hmac_update(ctx, data, data_size) == Status.ATCA_SUCCESS

def test_atcab_sha_hmac_finish(test_init):
    ctx = bytearray(32)
    digest = bytearray(32)
    target = 4
    assert atcab_sha_hmac_finish(ctx, digest, target) == Status.ATCA_SUCCESS
    assert digest == bytearray(atcab_mock.r_sha_digest)

def test_atcab_sha_hmac(test_init):
    data = bytearray(32)
    data_size = 32
    key_slot = 8
    digest = bytearray(32)
    target = 5
    assert atcab_sha_hmac(data, data_size, key_slot, digest, target) == Status.ATCA_SUCCESS
    assert digest == bytearray(atcab_mock.r_sha_digest)

#-----------------ATCA_BASIC_SIGN-------------------#

def test_atcab_sign_base(test_init):
    mode = 2
    key_id = 4
    signature = bytearray(64)
    assert atcab_sign_base(mode, key_id, signature) == Status.ATCA_SUCCESS
    assert signature == bytearray(atcab_mock.r_signature)

def test_atcab_sign(test_init):
    key_id = 3
    msg = bytearray(32)
    signature = bytearray(64)
    assert atcab_sign(key_id, msg, signature) == Status.ATCA_SUCCESS
    assert signature == bytearray(atcab_mock.r_signature)

def test_sign_internal(test_init):
    key_id = 4
    is_invalidate = 1
    is_full_sn = 1
    signature = bytearray(64)
    assert atcab_sign_internal(key_id, is_invalidate, is_full_sn, signature) == Status.ATCA_SUCCESS
    assert signature == bytearray(atcab_mock.r_signature)

#-----------------ATCA_BASIC_UPDATEEXTRA-------------------#

def test_atcab_updateextra(test_init):
    mode = 4
    new_value = 0x39
    assert atcab_updateextra(mode, new_value) == Status.ATCA_SUCCESS


#--------------------ATCA_BASIC_VERIFY----------------------#

def test_atcab_verify(test_init):
    mode = 2
    key_id = 3
    signature = bytearray(64)
    public_key = bytearray(64)
    other_data = bytearray(19)
    mac = bytearray(64)
    assert atcab_verify(mode, key_id, signature, public_key, other_data, mac) == Status.ATCA_SUCCESS
    assert mac == bytearray(atcab_mock.r_mac)

def test_atcab_verify_extern_stored_mac(test_init):
    mode = 2
    key_id = 3
    message = bytearray(32)
    signature = bytearray(64)
    public_key = bytearray(64)
    num_in = bytearray(32)
    io_key = bytearray(32)
    is_verified = bytearray(1)
    assert atcab_verify_extern_stored_mac(mode, key_id, message, signature, public_key, num_in, io_key, is_verified) == Status.ATCA_SUCCESS
    assert is_verified[0] == atcab_mock.r_verify_is_verified.value

def test_atcab_verify_extern(test_init):
    message = bytearray(32)
    signature = bytearray(64)
    public_key = bytearray(64)
    is_verified = bytearray(1)
    assert atcab_verify_extern(message, signature, public_key, is_verified) == Status.ATCA_SUCCESS
    assert is_verified[0] == atcab_mock.r_verify_is_verified.value

def test_atcab_verify_extern_mac(test_init):
    message = bytearray(32)
    signature = bytearray(64)
    public_key = bytearray(64)
    num_in = bytearray(32)
    io_key = bytearray(32)
    is_verified = bytearray(1)
    assert atcab_verify_extern_mac(message, signature, public_key, num_in, io_key, is_verified) == Status.ATCA_SUCCESS
    assert is_verified[0] == atcab_mock.r_verify_is_verified.value

def test_atcab_verify_stored(test_init):
    message = bytearray(32)
    signature = bytearray(64)
    key_id = 3
    is_verified = bytearray(1)
    assert atcab_verify_stored(message, signature, key_id, is_verified) == Status.ATCA_SUCCESS
    assert is_verified[0] == atcab_mock.r_verify_is_verified.value

def test_atcab_verify_stored_mac(test_init):
    message = bytearray(32)
    signature = bytearray(64)
    key_id = 3
    num_in = bytearray(32)
    io_key = bytearray(32)
    is_verified = bytearray(1)
    assert atcab_verify_stored_mac(message, signature, key_id, num_in, io_key, is_verified) == Status.ATCA_SUCCESS
    assert is_verified[0] == atcab_mock.r_verify_is_verified.value

def test_atcab_verify_validate(test_init):
    key_id = 3
    signature = bytearray(64)
    other_data = bytearray(19)
    is_verified = bytearray(1)
    assert atcab_verify_validate(key_id, signature, other_data, is_verified) == Status.ATCA_SUCCESS
    assert is_verified[0] == atcab_mock.r_verify_is_verified.value

def test_atcab_verify_invalidate(test_init):
    key_id = 3
    signature = bytearray(64)
    other_data = bytearray(19)
    is_verified = bytearray(1)
    assert atcab_verify_invalidate(key_id, signature, other_data, is_verified) == Status.ATCA_SUCCESS
    assert is_verified[0] == atcab_mock.r_verify_is_verified.value

#--------------------ATCA_BASIC_WRITE----------------------#

def test_atcab_write(test_init):
    zone = 2
    address = 54
    value = bytearray(32)
    mac = bytearray(32)
    assert atcab_write(zone, address, value, mac) == Status.ATCA_SUCCESS

def test_atcab_write_zone(test_init):
    zone = 2
    slot = 3
    block = 5
    offset = 0
    data = bytearray(32)
    length = 32
    assert atcab_write_zone(zone, slot, block, offset, data, length) == Status.ATCA_SUCCESS

def test_atcab_write_enc(test_init):
    key_id = 1
    block = 3
    data = bytearray(32)
    enc_key = bytearray(32)
    enc_key_id = 4
    assert atcab_write_enc(key_id, block, data, enc_key, enc_key_id) == Status.ATCA_SUCCESS

def test_atcab_write_config_zone(test_init):
    conf = bytearray(128)
    assert atcab_write_config_zone(conf) == Status.ATCA_SUCCESS

def test_atcab_write_pubkey(test_init):
    slot = 2
    public_key = bytearray(32)
    assert atcab_write_pubkey(slot, public_key) == Status.ATCA_SUCCESS

def test_atcab_write_bytes_zone(test_init):
    zone = 2
    slot = 3
    offset = 4
    data = bytearray(32)
    length = 32
    assert atcab_write_bytes_zone(zone, slot, offset, data, length) == Status.ATCA_SUCCESS

def test_atcab_write_config_counter(test_init):
    counter_id = 1
    counter_value = 453
    assert atcab_write_config_counter(counter_id, counter_value) == Status.ATCA_SUCCESS
