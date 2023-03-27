#ifndef _CALIB_H
#define _CALIB_H

/* Library Configuration */
#include "calib_config_check.h"

#include "calib_command.h"
#include "calib_execution.h"

/** \defgroup calib_ Basic Crypto API methods for CryptoAuth Devices (calib_)
 *
 * \brief
 * These methods provide a simple API to CryptoAuth chips
 *
   @{ */

#ifdef __cplusplus
extern "C" {
#endif

ATCA_STATUS calib_wakeup(ATCADevice device);
ATCA_STATUS calib_idle(ATCADevice device);
ATCA_STATUS calib_sleep(ATCADevice device);
ATCA_STATUS _calib_exit(ATCADevice device);
ATCA_STATUS calib_get_addr(uint8_t zone, uint16_t slot, uint8_t block, uint8_t offset, uint16_t* addr);
ATCA_STATUS calib_get_zone_size(ATCADevice device, uint8_t zone, uint16_t slot, size_t* size);
ATCA_STATUS calib_ca2_get_addr(uint8_t zone, uint16_t slot, uint8_t block, uint8_t offset, uint16_t* addr);

/* Helper Functions */
ATCA_STATUS calib_is_locked(ATCADevice device, uint8_t zone, bool* is_locked);
ATCA_STATUS calib_is_slot_locked(ATCADevice device, uint16_t slot, bool* is_locked);
ATCA_STATUS calib_ca2_is_locked(ATCADevice device, uint8_t zone, bool* is_locked);
ATCA_STATUS calib_ca2_is_data_locked(ATCADevice device, bool* is_locked);
ATCA_STATUS calib_ca2_is_config_locked(ATCADevice device, bool* is_locked);
ATCADeviceType calib_get_devicetype(uint8_t revision[4]);

#if CALIB_READ_EN || CALIB_READ_CA2_EN
ATCA_STATUS calib_is_locked_ext(ATCADevice device, uint8_t zone, bool* is_locked);
ATCA_STATUS calib_is_private(ATCADevice device, uint16_t slot, bool* is_private);
#endif

#if ATCA_CA2_SUPPORT
ATCADeviceType calib_get_devicetype_with_device_id(uint8_t device_id,uint8_t device_revision);
#endif

//AES command functions
#if CALIB_AES_EN
ATCA_STATUS calib_aes(ATCADevice device, uint8_t mode, uint16_t key_id, const uint8_t* aes_in, uint8_t* aes_out);
ATCA_STATUS calib_aes_encrypt(ATCADevice device, uint16_t key_id, uint8_t key_block, const uint8_t* plaintext, uint8_t* ciphertext);
ATCA_STATUS calib_aes_decrypt(ATCADevice device, uint16_t key_id, uint8_t key_block, const uint8_t* ciphertext, uint8_t* plaintext);
#endif
#if CALIB_AES_GCM_EN
ATCA_STATUS calib_aes_gfm(ATCADevice device, const uint8_t* h, const uint8_t* input, uint8_t* output);
#endif

//CheckMAC command functions
#if CALIB_CHECKMAC_EN
ATCA_STATUS calib_checkmac_base(ATCADevice device, uint8_t mode, uint16_t key_id, const uint8_t *challenge, const uint8_t *response, const uint8_t *other_data, uint8_t *resp_mac);
ATCA_STATUS calib_checkmac(ATCADevice device, uint8_t mode, uint16_t key_id, const uint8_t *challenge, const uint8_t *response, const uint8_t *other_data);
ATCA_STATUS calib_checkmac_with_response_mac(ATCADevice device, uint8_t mode, const uint8_t *challenge, const uint8_t *response, const uint8_t *other_data, uint8_t *mac);
#endif

// Counter command functions
#if CALIB_COUNTER_EN
ATCA_STATUS calib_counter(ATCADevice device, uint8_t mode, uint16_t counter_id, uint32_t* counter_value);
ATCA_STATUS calib_counter_increment(ATCADevice device, uint16_t counter_id, uint32_t* counter_value);
ATCA_STATUS calib_counter_read(ATCADevice device, uint16_t counter_id, uint32_t* counter_value);
#endif

// Delete command functions
#if CALIB_DELETE_EN
ATCA_STATUS calib_delete_base(ATCADevice device, uint8_t mode, uint16_t key_id, const uint8_t* mac);
ATCA_STATUS calib_delete(ATCADevice device, uint8_t num_in[NONCE_NUMIN_SIZE], const uint8_t *key);
#endif

// DeriveKey command functions
#if CALIB_DERIVEKEY_EN
ATCA_STATUS calib_derivekey(ATCADevice device, uint8_t mode, uint16_t key_id, const uint8_t* mac);
#endif

// ECDH command functions
#if CALIB_ECDH_EN
ATCA_STATUS calib_ecdh_base(ATCADevice device, uint8_t mode, uint16_t key_id, const uint8_t* public_key, uint8_t* pms, uint8_t* out_nonce);
ATCA_STATUS calib_ecdh(ATCADevice device, uint16_t key_id, const uint8_t* public_key, uint8_t* pms);
ATCA_STATUS calib_ecdh_tempkey(ATCADevice device, const uint8_t* public_key, uint8_t* pms);
#endif

#if CALIB_ECDH_ENC_EN
#if defined(ATCA_USE_CONSTANT_HOST_NONCE)
ATCA_STATUS calib_ecdh_enc(ATCADevice device, uint16_t key_id, const uint8_t* public_key, uint8_t* pms, const uint8_t* read_key, uint16_t read_key_id);
#else
ATCA_STATUS calib_ecdh_enc(ATCADevice device, uint16_t key_id, const uint8_t* public_key, uint8_t* pms, const uint8_t* read_key, uint16_t read_key_id, const uint8_t num_in[NONCE_NUMIN_SIZE]);
#endif /* ATCA_USE_CONSTANT_HOST_NONCE */
ATCA_STATUS calib_ecdh_ioenc(ATCADevice device, uint16_t key_id, const uint8_t* public_key, uint8_t* pms, const uint8_t* io_key);
ATCA_STATUS calib_ecdh_tempkey_ioenc(ATCADevice device, const uint8_t* public_key, uint8_t* pms, const uint8_t* io_key);
#endif /* CALIB_ECDH_ENC_EN */

// GenDig command functions
#if CALIB_GENDIG_EN
ATCA_STATUS calib_gendig(ATCADevice device, uint8_t zone, uint16_t key_id, const uint8_t *other_data, uint8_t other_data_size);
#endif

// GenDivKey command functions
#if CALIB_GENDIVKEY_EN
ATCA_STATUS calib_sha105_gendivkey(ATCADevice device, const uint8_t *other_data);
#endif

// GenKey command functions
#if CALIB_GENKEY_EN
ATCA_STATUS calib_genkey_base(ATCADevice device, uint8_t mode, uint16_t key_id, const uint8_t* other_data, uint8_t* public_key);
ATCA_STATUS calib_genkey(ATCADevice device, uint16_t key_id, uint8_t* public_key);
ATCA_STATUS calib_get_pubkey(ATCADevice device, uint16_t key_id, uint8_t* public_key);
#endif
#if CALIB_GENKEY_MAC_EN
ATCA_STATUS calib_genkey_mac(ATCADevice device, uint8_t* public_key, uint8_t* mac);
#endif

// HMAC command functions
#if CALIB_HMAC_EN
ATCA_STATUS calib_hmac(ATCADevice device, uint8_t mode, uint16_t key_id, uint8_t* digest);
#endif

// Info command functions
ATCA_STATUS calib_info_base(ATCADevice device, uint8_t mode, uint16_t param2, uint8_t* out_data);
ATCA_STATUS calib_info(ATCADevice device, uint8_t* revision);
ATCA_STATUS calib_info_privkey_valid(ATCADevice device, uint16_t key_id, uint8_t* is_valid);
#if ATCA_CA2_SUPPORT
ATCA_STATUS calib_info_lock_status(ATCADevice device, uint16_t param2, uint8_t* is_locked);
ATCA_STATUS calib_info_chip_status(ATCADevice device, uint8_t* chip_status);
#endif
#if CALIB_INFO_LATCH_EN
ATCA_STATUS calib_info_set_latch(ATCADevice device, bool state);
ATCA_STATUS calib_info_get_latch(ATCADevice device, bool* state);
#endif

// KDF command functions
#if CALIB_KDF_EN
ATCA_STATUS calib_kdf(ATCADevice device, uint8_t mode, uint16_t key_id, const uint32_t details, const uint8_t* message, uint8_t* out_data, uint8_t* out_nonce);
#endif

// Lock command functions
#if CALIB_LOCK_EN || CALIB_LOCK_CA2_EN
ATCA_STATUS calib_lock(ATCADevice device, uint8_t mode, uint16_t summary_crc);
ATCA_STATUS calib_lock_config_zone(ATCADevice device);
ATCA_STATUS calib_lock_config_zone_crc(ATCADevice device, uint16_t summary_crc);
ATCA_STATUS calib_lock_data_zone(ATCADevice device);
ATCA_STATUS calib_lock_data_zone_crc(ATCADevice device, uint16_t summary_crc);
ATCA_STATUS calib_lock_data_slot(ATCADevice device, uint16_t slot);
#endif
// Lock CA2 command functions
#if CALIB_LOCK_CA2_EN
ATCA_STATUS calib_ca2_lock_config_slot(ATCADevice device, uint16_t slot, uint16_t summary_crc);
ATCA_STATUS calib_ca2_lock_config_zone(ATCADevice device);
ATCA_STATUS calib_ca2_lock_data_slot(ATCADevice device, uint16_t slot);
ATCA_STATUS calib_ca2_lock_data_zone(ATCADevice device);
#endif

// MAC command functions
#if CALIB_MAC_EN
ATCA_STATUS calib_mac(ATCADevice device, uint8_t mode, uint16_t key_id, const uint8_t* challenge, uint8_t* digest);
#endif

// Nonce command functions
#if CALIB_NONCE_EN
ATCA_STATUS calib_nonce_base(ATCADevice device, uint8_t mode, uint16_t zero, const uint8_t *num_in, uint8_t* rand_out);
ATCA_STATUS calib_nonce(ATCADevice device, const uint8_t *num_in);
ATCA_STATUS calib_nonce_load(ATCADevice device, uint8_t target, const uint8_t *num_in, uint16_t num_in_size);
ATCA_STATUS calib_nonce_rand(ATCADevice device, const uint8_t *num_in, uint8_t* rand_out);
ATCA_STATUS calib_challenge(ATCADevice device, const uint8_t *num_in);
ATCA_STATUS calib_challenge_seed_update(ATCADevice device, const uint8_t *num_in, uint8_t* rand_out);
ATCA_STATUS calib_nonce_gen_session_key(ATCADevice device, uint16_t param2, uint8_t* num_in,
                                        uint8_t* rand_out);
#endif

// PrivWrite command functions
#if CALIB_PRIVWRITE_EN
#if defined(ATCA_USE_CONSTANT_HOST_NONCE)
ATCA_STATUS calib_priv_write(ATCADevice device, uint16_t key_id, const uint8_t priv_key[36], uint16_t write_key_id, const uint8_t write_key[32]);
#else
ATCA_STATUS calib_priv_write(ATCADevice device, uint16_t key_id, const uint8_t priv_key[36], uint16_t write_key_id, const uint8_t write_key[32], const uint8_t num_in[NONCE_NUMIN_SIZE]);
#endif
#endif /* CALIB_PRIVWRITE_EN */

// Random command functions
#if CALIB_RANDOM_EN
ATCA_STATUS calib_random(ATCADevice device, uint8_t* rand_out);
#endif

// Read command functions
#if CALIB_READ_EN
ATCA_STATUS calib_read_zone(ATCADevice device, uint8_t zone, uint16_t slot, uint8_t block, uint8_t offset, uint8_t *data, uint8_t len);
ATCA_STATUS calib_read_bytes_zone(ATCADevice device, uint8_t zone, uint16_t slot, size_t offset, uint8_t *data, size_t length);
ATCA_STATUS calib_read_serial_number(ATCADevice device, uint8_t* serial_number);
bool calib_sha_compare_config(uint8_t* expected, uint8_t* other);
bool calib_ecc_compare_config(uint8_t* expected, uint8_t* other);
bool calib_ecc608_compare_config(uint8_t* expected, uint8_t* other);
ATCA_STATUS calib_read_sig(ATCADevice device, uint16_t slot, uint8_t *sig);
#endif
// CA2 Read command functions
#if CALIB_READ_CA2_EN
ATCA_STATUS calib_ca2_read_zone(ATCADevice device, uint8_t zone, uint16_t slot, uint8_t block, size_t offset,
                                   uint8_t* data, uint8_t len);
ATCA_STATUS calib_ca2_read_bytes_zone(ATCADevice device, uint8_t zone, uint16_t slot,
                                         size_t block, uint8_t* data, size_t length);
ATCA_STATUS calib_ca2_read_serial_number(ATCADevice device, uint8_t* serial_number);
ATCA_STATUS calib_ca2_read_config_zone(ATCADevice device, uint8_t* config_data);
bool calib_ca2_compare_config(uint8_t* expected, uint8_t* other);
#endif
#if CALIB_READ_EN || CALIB_READ_CA2_EN
ATCA_STATUS calib_read_config_zone(ATCADevice device, uint8_t* config_data);
ATCA_STATUS calib_cmp_config_zone(ATCADevice device, uint8_t* config_data, bool* same_config);
ATCA_STATUS calib_read_zone_ext(ATCADevice device, uint8_t zone, uint16_t slot, uint8_t block, uint8_t offset, uint8_t *data, uint8_t len);
ATCA_STATUS calib_read_bytes_zone_ext(ATCADevice device, uint8_t zone, uint16_t slot, size_t offset, uint8_t *data, size_t length);
ATCA_STATUS calib_read_pubkey(ATCADevice device, uint16_t slot, uint8_t *public_key);
ATCA_STATUS calib_read_serial_number_ext(ATCADevice device, uint8_t* serial_number);
#endif


#if CALIB_READ_ENC_EN
#if defined(ATCA_USE_CONSTANT_HOST_NONCE)
ATCA_STATUS calib_read_enc(ATCADevice device, uint16_t key_id, uint8_t block, uint8_t *data, const uint8_t* enc_key, const uint16_t enc_key_id);
#else
ATCA_STATUS calib_read_enc(ATCADevice device, uint16_t key_id, uint8_t block, uint8_t *data, const uint8_t* enc_key, const uint16_t enc_key_id, const uint8_t num_in[NONCE_NUMIN_SIZE]);
#endif
#endif /* CALIB_READ_ENC_EN */

// SecureBoot command functions
#if CALIB_SECUREBOOT_EN
ATCA_STATUS calib_secureboot(ATCADevice device, uint8_t mode, uint16_t param2, const uint8_t* digest, const uint8_t* signature, uint8_t* mac);
#endif
#if CALIB_SECUREBOOT_MAC_EN
ATCA_STATUS calib_secureboot_mac(ATCADevice device, uint8_t mode, const uint8_t* digest, const uint8_t* signature, const uint8_t* num_in, const uint8_t* io_key, bool* is_verified);
#endif

// SelfTest command functions
#if CALIB_SELFTEST_EN
ATCA_STATUS calib_selftest(ATCADevice device, uint8_t mode, uint16_t param2, uint8_t* result);
#endif

// SHA command functions
typedef struct atca_sha256_ctx
{
    uint32_t total_msg_size;                    //!< Total number of message bytes processed
    uint32_t block_size;                        //!< Number of bytes in current block
    uint8_t  block[ATCA_SHA256_BLOCK_SIZE * 2]; //!< Unprocessed message storage
} atca_sha256_ctx_t;

typedef atca_sha256_ctx_t atca_hmac_sha256_ctx_t;

#if CALIB_SHA_EN
ATCA_STATUS calib_sha_base(ATCADevice device, uint8_t mode, uint16_t length, const uint8_t* data_in, uint8_t* data_out, uint16_t* data_out_size);
ATCA_STATUS calib_sha_start(ATCADevice device);
ATCA_STATUS calib_sha_update(ATCADevice device, const uint8_t* message);
ATCA_STATUS calib_sha_end(ATCADevice device, uint8_t *digest, uint16_t length, const uint8_t *message);
ATCA_STATUS calib_sha_read_context(ATCADevice device, uint8_t* context, uint16_t* context_size);
ATCA_STATUS calib_sha_write_context(ATCADevice device, const uint8_t* context, uint16_t context_size);
ATCA_STATUS calib_sha(ATCADevice device, uint16_t length, const uint8_t *message, uint8_t *digest);
ATCA_STATUS calib_hw_sha2_256(ATCADevice device, const uint8_t * data, size_t data_size, uint8_t* digest);
ATCA_STATUS calib_hw_sha2_256_init(ATCADevice device, atca_sha256_ctx_t* ctx);
ATCA_STATUS calib_hw_sha2_256_update(ATCADevice device, atca_sha256_ctx_t* ctx, const uint8_t* data, size_t data_size);
ATCA_STATUS calib_hw_sha2_256_finish(ATCADevice device, atca_sha256_ctx_t* ctx, uint8_t* digest);
#endif
#if CALIB_SHA_HMAC_EN
ATCA_STATUS calib_sha_hmac_init(ATCADevice device, atca_hmac_sha256_ctx_t* ctx, uint16_t key_slot);
ATCA_STATUS calib_sha_hmac_update(ATCADevice device, atca_hmac_sha256_ctx_t* ctx, const uint8_t* data, size_t data_size);
ATCA_STATUS calib_sha_hmac_finish(ATCADevice device, atca_hmac_sha256_ctx_t* ctx, uint8_t* digest, uint8_t target);
ATCA_STATUS calib_sha_hmac(ATCADevice device, const uint8_t * data, size_t data_size, uint16_t key_slot, uint8_t* digest, uint8_t target);
#endif

// Sign command functions
#if CALIB_SIGN_EN
ATCA_STATUS calib_sign_base(ATCADevice device, uint8_t mode, uint16_t key_id, uint8_t *signature);
ATCA_STATUS calib_sign(ATCADevice device, uint16_t key_id, const uint8_t *msg, uint8_t *signature);
#endif
#if CALIB_SIGN_EN || CALIB_SIGN_CA2_EN
ATCA_STATUS calib_sign_ext(ATCADevice device, uint16_t key_id, const uint8_t *msg, uint8_t *signature);
#endif
#if CALIB_SIGN_INTERNAL_EN
ATCA_STATUS calib_sign_internal(ATCADevice device, uint16_t key_id, bool is_invalidate, bool is_full_sn, uint8_t *signature);
#endif
// CA2 Sign command functions
#if CALIB_SIGN_CA2_EN
ATCA_STATUS calib_ca2_sign(ATCADevice device, uint16_t key_id, const uint8_t* msg, uint8_t* signature);
#endif

// UpdateExtra command functions
#if CALIB_UPDATEEXTRA_EN
ATCA_STATUS calib_updateextra(ATCADevice device, uint8_t mode, uint16_t new_value);
#endif

// Verify command functions
#if CALIB_VERIFY_EXTERN_EN || CALIB_VERIFY_STORED_EN
ATCA_STATUS calib_verify(ATCADevice device, uint8_t mode, uint16_t key_id, const uint8_t* signature, const uint8_t* public_key, const uint8_t* other_data, uint8_t* mac);
#endif

#if CALIB_VERIFY_EXTERN_EN
ATCA_STATUS calib_verify_extern(ATCADevice device, const uint8_t *message, const uint8_t *signature, const uint8_t *public_key, bool *is_verified);
#if CALIB_VERIFY_MAC_EN
ATCA_STATUS calib_verify_extern_mac(ATCADevice device, const uint8_t *message, const uint8_t* signature, const uint8_t* public_key, const uint8_t* num_in, const uint8_t* io_key, bool* is_verified);
#endif
#endif

#if CALIB_VERIFY_STORED_EN
ATCA_STATUS calib_verify_stored(ATCADevice device, const uint8_t *message, const uint8_t *signature, uint16_t key_id, bool *is_verified);
ATCA_STATUS calib_verify_stored_with_tempkey(ATCADevice device, const uint8_t* signature, uint16_t key_id, bool* is_verified);
#if CALIB_VERIFY_MAC_EN
ATCA_STATUS calib_verify_stored_mac(ATCADevice device, const uint8_t *message, const uint8_t *signature, uint16_t key_id, const uint8_t* num_in, const uint8_t* io_key, bool* is_verified);
#endif
#endif

#if CALIB_VERIFY_VALIDATE_EN
ATCA_STATUS calib_verify_validate(ATCADevice device, uint16_t key_id, const uint8_t *signature, const uint8_t *other_data, bool *is_verified);
ATCA_STATUS calib_verify_invalidate(ATCADevice device, uint16_t key_id, const uint8_t *signature, const uint8_t *other_data, bool *is_verified);
#endif

// Write command functions
#if CALIB_WRITE_EN
ATCA_STATUS calib_write(ATCADevice device, uint8_t zone, uint16_t address, const uint8_t *value, const uint8_t *mac);
ATCA_STATUS calib_write_zone(ATCADevice device, uint8_t zone, uint16_t slot, uint8_t block, uint8_t offset, const uint8_t *data, uint8_t len);
ATCA_STATUS calib_write_bytes_zone(ATCADevice device, uint8_t zone, uint16_t slot, size_t offset_bytes, const uint8_t *data, size_t length);
ATCA_STATUS calib_write_config_zone(ATCADevice device, const uint8_t* config_data);
ATCA_STATUS calib_write_config_counter(ATCADevice device, uint16_t counter_id, uint32_t counter_value);
#endif
#if CALIB_WRITE_EN || CALIB_WRITE_CA2_EN
ATCA_STATUS calib_write_ext(ATCADevice device, uint8_t zone, uint16_t address, const uint8_t *value, const uint8_t *mac);
ATCA_STATUS calib_write_zone_ext(ATCADevice device, uint8_t zone, uint16_t slot, uint8_t block, uint8_t offset, const uint8_t *data, uint8_t len);
ATCA_STATUS calib_write_bytes_zone_ext(ATCADevice device, uint8_t zone, uint16_t slot, size_t offset_bytes, const uint8_t *data, size_t length);
ATCA_STATUS calib_write_config_zone_ext(ATCADevice device, const uint8_t* config_data);
ATCA_STATUS calib_write_config_counter_ext(ATCADevice device, uint16_t counter_id, uint32_t counter_value);
ATCA_STATUS calib_write_pubkey(ATCADevice device, uint16_t slot, const uint8_t *public_key);
#endif

#if CALIB_WRITE_ENC_EN
#if defined(ATCA_USE_CONSTANT_HOST_NONCE)
ATCA_STATUS calib_write_enc(ATCADevice device, uint16_t key_id, uint8_t block, const uint8_t *data, const uint8_t* enc_key, const uint16_t enc_key_id);
#else
ATCA_STATUS calib_write_enc(ATCADevice device, uint16_t key_id, uint8_t block, const uint8_t *data, const uint8_t* enc_key, const uint16_t enc_key_id, const uint8_t num_in[NONCE_NUMIN_SIZE]);
#endif
#endif /* CALIB_WRITE_ENC_EN */

// CA2 Write command functions
#if CALIB_WRITE_CA2_EN
ATCA_STATUS calib_ca2_write(ATCADevice device, uint8_t zone, uint16_t address, const uint8_t *value,
                               const uint8_t *mac);
ATCA_STATUS calib_ca2_write_zone(ATCADevice device, uint8_t zone, uint16_t slot, uint8_t block,
                                    uint8_t offset, const uint8_t *data, uint8_t len);
ATCA_STATUS calib_ca2_write_config_zone(ATCADevice device, const uint8_t* config_data);
ATCA_STATUS calib_ca2_write_config_counter(ATCADevice device, uint8_t counter_id, uint16_t counter_value);
ATCA_STATUS calib_ca2_write_bytes_zone(ATCADevice device, uint8_t zone, uint16_t slot, size_t block,
                                          const uint8_t *data, size_t length);
#endif /* CALIB_WRITE_CA2_EN */
#if CALIB_WRITE_ENC_CA2_EN
ATCA_STATUS calib_ca2_write_enc(ATCADevice device, uint16_t slot, uint8_t* data, uint8_t* transport_key,
                                   uint8_t key_id, uint8_t num_in[NONCE_NUMIN_SIZE]);
#endif /* CALIB_WRITE_ENC_CA2_EN */

/* Map calib functions to atcab names for api compatibility without abstraction overhead */
#if !ATCA_TA_SUPPORT && !defined(ATCA_USE_ATCAB_FUNCTIONS)

#define atcab_wakeup()                          calib_wakeup(_gDevice)
#define atcab_idle()                            calib_idle(_gDevice)
#define atcab_sleep()                           calib_sleep(_gDevice)
#define _atcab_exit(...)                         _calib_exit(_gDevice, __VA_ARGS__)
#define atcab_get_zone_size(...)                calib_get_zone_size(_gDevice, __VA_ARGS__)


// AES command functions
#define atcab_aes(...)                          calib_aes(_gDevice, __VA_ARGS__)
#define atcab_aes_encrypt(...)                  calib_aes_encrypt(_gDevice, __VA_ARGS__)
#define atcab_aes_encrypt_ext                   calib_aes_encrypt
#define atcab_aes_decrypt(...)                  calib_aes_decrypt(_gDevice, __VA_ARGS__)
#define atcab_aes_decrypt_ext                   calib_aes_decrypt
#define atcab_aes_gfm(...)                      calib_aes_gfm(_gDevice, __VA_ARGS__)

#define atcab_aes_gcm_init(...)                 calib_aes_gcm_init(_gDevice, __VA_ARGS__)
#define atcab_aes_gcm_init_rand(...)            calib_aes_gcm_init_rand(_gDevice, __VA_ARGS__)
#define atcab_aes_gcm_aad_update(...)           calib_aes_gcm_aad_update(_gDevice, __VA_ARGS__)
#define atcab_aes_gcm_encrypt_update(...)       calib_aes_gcm_encrypt_update(_gDevice, __VA_ARGS__)
#define atcab_aes_gcm_encrypt_finish(...)       calib_aes_gcm_encrypt_finish(_gDevice, __VA_ARGS__)
#define atcab_aes_gcm_decrypt_update(...)       calib_aes_gcm_decrypt_update(_gDevice, __VA_ARGS__)
#define atcab_aes_gcm_decrypt_finish(...)       calib_aes_gcm_decrypt_finish(_gDevice, __VA_ARGS__)

// CheckMAC command functions
#define atcab_checkmac(...)                     calib_checkmac(_gDevice, __VA_ARGS__)
#define atcab_checkmac_with_response_mac(...)   calib_checkmac_with_response_mac(_gDevice, __VA_ARGS__)

// Counter command functions
#define atcab_counter(...)                      calib_counter(_gDevice, __VA_ARGS__)
#define atcab_counter_increment(...)            calib_counter_increment(_gDevice, __VA_ARGS__)
#define atcab_counter_read(...)                 calib_counter_read(_gDevice, __VA_ARGS__)

// DeriveKey command functions
#define atcab_derivekey(...)                    calib_derivekey(_gDevice, __VA_ARGS__)

// ECDH command functions
#define atcab_ecdh_base(...)                    calib_ecdh_base(_gDevice, __VA_ARGS__)
#define atcab_ecdh(...)                         calib_ecdh(_gDevice, __VA_ARGS__)
#define atcab_ecdh_enc(...)                     calib_ecdh_enc(_gDevice, __VA_ARGS__)
#define atcab_ecdh_ioenc(...)                   calib_ecdh_ioenc(_gDevice, __VA_ARGS__)
#define atcab_ecdh_tempkey(...)                 calib_ecdh_tempkey(_gDevice, __VA_ARGS__)
#define atcab_ecdh_tempkey_ioenc(...)           calib_ecdh_tempkey_ioenc(_gDevice, __VA_ARGS__)

// GenDig command functions
#define atcab_gendig(...)                       calib_gendig(_gDevice, __VA_ARGS__)

// GenDivKey command functions
#define atcab_gendivkey(...)                    calib_sha105_gendivkey(_gDevice, __VA_ARGS__)

// GenKey command functions
#define atcab_genkey_base(...)                  calib_genkey_base(_gDevice, __VA_ARGS__)
#define atcab_genkey(...)                       calib_genkey(_gDevice, __VA_ARGS__)
#define atcab_get_pubkey(...)                   calib_get_pubkey(_gDevice, __VA_ARGS__)
#define atcab_get_pubkey_ext                    calib_get_pubkey

// HMAC command functions
#define atcab_hmac(...)                         calib_hmac(_gDevice, __VA_ARGS__)

// Info command functions
#define atcab_info_base(...)                    calib_info_base(_gDevice, __VA_ARGS__)
#define atcab_info(...)                         calib_info(_gDevice, __VA_ARGS__)
#define atcab_info_get_latch(...)               calib_info_get_latch(_gDevice, __VA_ARGS__)
#define atcab_info_set_latch(...)               calib_info_set_latch(_gDevice, __VA_ARGS__)
#define atcab_info_lock_status(...)             calib_info_lock_status(_gDevice, __VA_ARGS__)
#define atcab_info_chip_status(...)             calib_info_chip_status(_gDevice, __VA_ARGS__)

// KDF command functions
#define atcab_kdf(...)                          calib_kdf(_gDevice, __VA_ARGS__)

// Lock command functions
#if ATCA_CA2_SUPPORT && !ATCA_CA_SUPPORT
#define atcab_lock(...)                          (ATCA_UNIMPLEMENTED)
#define atcab_lock_config_zone()                 calib_ca2_lock_config_zone(_gDevice)
#define atcab_lock_config_zone_crc(...)          (ATCA_UNIMPLEMENTED)
#define atcab_lock_data_zone()                   calib_ca2_lock_data_zone(_gDevice)
#define atcab_lock_data_zone_crc(...)            (ATCA_UNIMPLEMENTED)
#define atcab_lock_data_slot(...)                calib_ca2_lock_data_slot(_gDevice, __VA_ARGS__)
#else
#define atcab_lock(...)                          calib_lock(_gDevice, __VA_ARGS__)
#define atcab_lock_config_zone()                 calib_lock_config_zone(_gDevice)
#define atcab_lock_config_zone_crc(...)          calib_lock_config_zone_crc(_gDevice, __VA_ARGS__)
#define atcab_lock_data_zone()                   calib_lock_data_zone(_gDevice)
#define atcab_lock_data_zone_crc(...)            calib_lock_data_zone_crc(_gDevice, __VA_ARGS__)
#define atcab_lock_data_slot(...)                calib_lock_data_slot(_gDevice, __VA_ARGS__)
#endif

// MAC command functions
#define atcab_mac(...)                          calib_mac(_gDevice, __VA_ARGS__)

// Nonce command functions
#define atcab_nonce_base(...)                   calib_nonce_base(_gDevice, __VA_ARGS__)
#define atcab_nonce(...)                        calib_nonce(_gDevice, __VA_ARGS__)
#define atcab_nonce_load(...)                   calib_nonce_load(_gDevice, __VA_ARGS__)
#define atcab_nonce_rand(...)                   calib_nonce_rand(_gDevice, __VA_ARGS__)
#define atcab_challenge(...)                    calib_challenge(_gDevice, __VA_ARGS__)
#define atcab_challenge_seed_update(...)        calib_challenge_seed_update(_gDevice, __VA_ARGS__)
#define atcab_nonce_gen_session_key(...)        calib_nonce_gen_session_key(_gDevice, __VA_ARGS__)

// PrivWrite command functions
#define atcab_priv_write(...)                   calib_priv_write(_gDevice, __VA_ARGS__)


// Random command functions
#define atcab_random(...)                       calib_random(_gDevice, __VA_ARGS__)
#define atcab_random_ext                        calib_random

// Read command functions
#define atcab_is_slot_locked(...)               calib_is_slot_locked(_gDevice, __VA_ARGS__)
#define atcab_is_private(...)                   calib_is_private(_gDevice, __VA_ARGS__)
#define atcab_is_private_ext                    calib_is_private

#if ATCA_CA2_SUPPORT && !ATCA_CA_SUPPORT
#define atcab_read_zone(...)                    calib_ca2_read_zone(_gDevice, __VA_ARGS__)
#define atcab_is_locked(...)                    calib_ca2_is_locked(_gDevice, __VA_ARGS__)
#define atcab_is_config_locked(...)             calib_ca2_is_locked(_gDevice, ATCA_ZONE_CONFIG, __VA_ARGS__)
#define atcab_is_data_locked(...)               calib_ca2_is_locked(_gDevice, ATCA_ZONE_DATA, __VA_ARGS__)
#define atcab_read_bytes_zone(...)              calib_ca2_read_bytes_zone(_gDevice, __VA_ARGS__)
#define atcab_read_bytes_zone_ext               calib_ca2_read_bytes_zone
#define atcab_read_serial_number(...)           calib_ca2_read_serial_number(_gDevice, __VA_ARGS__)
#define atcab_read_config_zone(...)             calib_ca2_read_config_zone(_gDevice, __VA_ARGS__)
#else
#define atcab_read_zone(...)                    calib_read_zone_ext(_gDevice, __VA_ARGS__)
#define atcab_is_locked(...)                    calib_is_locked_ext(_gDevice, __VA_ARGS__)
#define atcab_is_config_locked(...)             calib_is_locked_ext(_gDevice, LOCK_ZONE_CONFIG, __VA_ARGS__)
#define atcab_is_data_locked(...)               calib_is_locked_ext(_gDevice, LOCK_ZONE_DATA, __VA_ARGS__)
#define atcab_read_bytes_zone(...)              calib_read_bytes_zone_ext(_gDevice, __VA_ARGS__)
#define atcab_read_bytes_zone_ext               calib_read_bytes_zone_ext
#define atcab_read_serial_number(...)           calib_read_serial_number_ext(_gDevice, __VA_ARGS__)
#define atcab_read_config_zone(...)             calib_read_config_zone(_gDevice, __VA_ARGS__)
#endif

#define atcab_cmp_config_zone(...)              calib_cmp_config_zone(_gDevice, __VA_ARGS__)
#define atcab_read_pubkey(...)                  calib_read_pubkey(_gDevice, __VA_ARGS__)
#define atcab_read_pubkey_ext                   calib_read_pubkey
#define atcab_read_sig(...)                     calib_read_sig(_gDevice, __VA_ARGS__)
#define atcab_read_enc(...)                     calib_read_enc(_gDevice, __VA_ARGS__)


// SecureBoot command functions
#define atcab_secureboot(...)                   calib_secureboot(_gDevice, __VA_ARGS__)
#define atcab_secureboot_mac(...)               calib_secureboot_mac(_gDevice, __VA_ARGS__)

// SelfTest command functions
#define atcab_selftest(...)                     calib_selftest(_gDevice, __VA_ARGS__)

// SHA command functions
#define atcab_sha_base(...)                     calib_sha_base(_gDevice, __VA_ARGS__)
#define atcab_sha_start()                       calib_sha_start(_gDevice)
#define atcab_sha_update(...)                   calib_sha_update(_gDevice, __VA_ARGS__)
#define atcab_sha_end(...)                      calib_sha_end(_gDevice, __VA_ARGS__)
#define atcab_sha_read_context(...)             calib_sha_read_context(_gDevice, __VA_ARGS__)
#define atcab_sha_write_context(...)            calib_sha_write_context(_gDevice, __VA_ARGS__)
#define atcab_sha(...)                          calib_sha(_gDevice, __VA_ARGS__)
#define atcab_hw_sha2_256(...)                  calib_hw_sha2_256(_gDevice, __VA_ARGS__)
#define atcab_hw_sha2_256_init(...)             calib_hw_sha2_256_init(_gDevice, __VA_ARGS__)
#define atcab_hw_sha2_256_update(...)           calib_hw_sha2_256_update(_gDevice, __VA_ARGS__)
#define atcab_hw_sha2_256_finish(...)           calib_hw_sha2_256_finish(_gDevice, __VA_ARGS__)
#define atcab_sha_hmac_init(...)                calib_sha_hmac_init(_gDevice, __VA_ARGS__)
#define atcab_sha_hmac_update(...)              calib_sha_hmac_update(_gDevice, __VA_ARGS__)
#define atcab_sha_hmac_finish(...)              calib_sha_hmac_finish(_gDevice, __VA_ARGS__)
#define atcab_sha_hmac(...)                     calib_sha_hmac(_gDevice, __VA_ARGS__)
#define atcab_sha_hmac_ext                      calib_sha_hmac
#define SHA_CONTEXT_MAX_SIZE                    (99)

// Sign command functions
#define atcab_sign_base(...)                    calib_sign_base(_gDevice, __VA_ARGS__)
#if ATCA_CA2_SUPPORT && !ATCA_CA_SUPPORT
#define atcab_sign(...)                         calib_ca2_sign(_gDevice, __VA_ARGS__)
#define atcab_sign_ext                          calib_ca2_sign
#else
#define atcab_sign(...)                         calib_sign_ext(_gDevice, __VA_ARGS__)
#define atcab_sign_ext                          calib_sign_ext
#endif

#define atcab_sign_internal(...)                calib_sign_internal(_gDevice, __VA_ARGS__)

// UpdateExtra command functions
#define atcab_updateextra(...)                  calib_updateextra(_gDevice, __VA_ARGS__)

// Verify command functions
#define atcab_verify(...)                       calib_verify(_gDevice, __VA_ARGS__)
#define atcab_verify_extern(...)                calib_verify_extern(_gDevice, __VA_ARGS__)
#define atcab_verify_extern_ext                 calib_verify_extern
#define atcab_verify_extern_mac(...)            calib_verify_extern_mac(_gDevice, __VA_ARGS__)
#define atcab_verify_stored(...)                calib_verify_stored(_gDevice, __VA_ARGS__)
#define atcab_verify_stored_ext                 calib_verify_stored
#define atcab_verify_stored_with_tempkey(...)   calib_verify_stored_with_tempkey(_gDevice, __VA_ARGS__)
#define atcab_verify_stored_mac(...)            calib_verify_stored_mac(_gDevice, __VA_ARGS__)
#define atcab_verify_validate(...)              calib_verify_validate(_gDevice, __VA_ARGS__)
#define atcab_verify_invalidate(...)            calib_verify_invalidate(_gDevice, __VA_ARGS__)

// Write command functions
#if ATCA_CA2_SUPPORT && !ATCA_CA_SUPPORT
#define atcab_write(...)                        calib_ca2_write(_gDevice, __VA_ARGS__)
#define atcab_write_zone(...)                   calib_ca2_write_zone(_gDevice, __VA_ARGS__)
#define atcab_write_bytes_zone(...)             calib_ca2_write_bytes_zone(_gDevice, __VA_ARGS__)
#define atcab_write_bytes_zone_ext              calib_ca2_write_bytes_zone
#define atcab_write_config_zone(...)            calib_ca2_write_config_zone(_gDevice, __VA_ARGS__)
#define atcab_write_config_counter(...)         calib_ca2_write_config_counter(_gDevice, __VA_ARGS__)
#else
#define atcab_write(...)                        calib_write_ext(_gDevice, __VA_ARGS__)
#define atcab_write_zone(...)                   calib_write_zone_ext(_gDevice, __VA_ARGS__)
#define atcab_write_bytes_zone(...)             calib_write_bytes_zone_ext(_gDevice, __VA_ARGS__)
#define atcab_write_bytes_zone_ext              calib_write_bytes_zone_ext
#define atcab_write_config_zone(...)            calib_write_config_zone_ext(_gDevice, __VA_ARGS__)
#define atcab_write_config_counter(...)         calib_write_config_counter_ext(_gDevice, __VA_ARGS__)
#endif

#define atcab_write_pubkey(...)                 calib_write_pubkey(_gDevice, __VA_ARGS__)
#define atcab_write_enc(...)                    calib_write_enc(_gDevice, __VA_ARGS__)
#endif

#ifdef __cplusplus
}
#endif

/** @} */

#endif