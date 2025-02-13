/**
 * \file
 * \brief CryptoAuthLib Basic API methods - a simple crypto authentication API.
 * These methods manage a global ATCADevice object behind the scenes. They also
 * manage the wake/idle state transitions so callers don't need to.
 *
 * \copyright (c) 2015-2020 Microchip Technology Inc. and its subsidiaries.
 *
 * \page License
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
 * PARTICULAR PURPOSE. IN NO EVENT WILL MICROCHIP BE LIABLE FOR ANY INDIRECT,
 * SPECIAL, PUNITIVE, INCIDENTAL OR CONSEQUENTIAL LOSS, DAMAGE, COST OR EXPENSE
 * OF ANY KIND WHATSOEVER RELATED TO THE SOFTWARE, HOWEVER CAUSED, EVEN IF
 * MICROCHIP HAS BEEN ADVISED OF THE POSSIBILITY OR THE DAMAGES ARE
 * FORESEEABLE. TO THE FULLEST EXTENT ALLOWED BY LAW, MICROCHIP'S TOTAL
 * LIABILITY ON ALL CLAIMS IN ANY WAY RELATED TO THIS SOFTWARE WILL NOT EXCEED
 * THE AMOUNT OF FEES, IF ANY, THAT YOU HAVE PAID DIRECTLY TO MICROCHIP FOR
 * THIS SOFTWARE.
 */

#ifndef ATCA_BASIC_H_
#define ATCA_BASIC_H_
/*lint +flb */

#include "cryptoauthlib.h"
#include "crypto/atca_crypto_sw_sha2.h"

/** \defgroup atcab_ Basic Crypto API methods (atcab_)
 *
 * \brief
 * These methods provide the most convenient, simple API to CryptoAuth chips
 *
   @{ */

#ifdef __cplusplus
extern "C" {
#endif

ATCA_DLL ATCADevice g_atcab_device_ptr;

// Basic global methods
ATCA_STATUS atcab_version(char *ver_str);
ATCA_STATUS atcab_init_ext(ATCADevice* device, ATCAIfaceCfg* cfg);
ATCA_STATUS atcab_init(ATCAIfaceCfg *cfg);
ATCA_STATUS atcab_init_device(ATCADevice ca_device);
ATCA_STATUS atcab_release_ext(ATCADevice* device);
ATCA_STATUS atcab_release(void);
ATCADevice atcab_get_device(void);
ATCADeviceType atcab_get_device_type_ext(ATCADevice device);
ATCADeviceType atcab_get_device_type(void);
uint8_t atcab_get_device_address(ATCADevice device);

bool atcab_is_ca_device(ATCADeviceType dev_type);
bool atcab_is_ca2_device(ATCADeviceType dev_type);
bool atcab_is_ta_device(ATCADeviceType dev_type);

#define atcab_get_addr(...)                     calib_get_addr(__VA_ARGS__)
#define atca_execute_command(...)               calib_execute_command(__VA_ARGS__)


/* Extra AES Block Mode Support */
#include "crypto/atca_crypto_hw_aes.h"

// Hardware Accelerated algorithms
#if ATCAB_PBKDF2_SHA256_EN
ATCA_STATUS atcab_pbkdf2_sha256_ext(ATCADevice device, const uint32_t iter, const uint16_t slot, const uint8_t* salt, const size_t salt_len, uint8_t* result,
                                    size_t result_len);
ATCA_STATUS atcab_pbkdf2_sha256(const uint32_t iter, const uint16_t slot, const uint8_t* salt, const size_t salt_len, uint8_t* result, size_t result_len);
#endif

#ifdef ATCA_USE_ATCAB_FUNCTIONS

/* Basic global methods */
ATCA_STATUS atcab_wakeup(void);
ATCA_STATUS atcab_idle(void);
ATCA_STATUS atcab_sleep(void);
//ATCA_STATUS atcab_get_addr(uint8_t zone, uint16_t slot, uint8_t block, uint8_t offset, uint16_t* addr);
ATCA_STATUS atcab_get_zone_size(uint8_t zone, uint16_t slot, size_t* size);
ATCA_STATUS atcab_get_zone_size_ext(ATCADevice device, uint8_t zone, uint16_t slot, size_t* size);

// AES command functions
ATCA_STATUS atcab_aes(uint8_t mode, uint16_t key_id, const uint8_t* aes_in, uint8_t* aes_out);
ATCA_STATUS atcab_aes_encrypt(uint16_t key_id, uint8_t key_block, const uint8_t* plaintext, uint8_t* ciphertext);
ATCA_STATUS atcab_aes_encrypt_ext(ATCADevice device, uint16_t key_id, uint8_t key_block, const uint8_t* plaintext, uint8_t* ciphertext);
ATCA_STATUS atcab_aes_decrypt(uint16_t key_id, uint8_t key_block, const uint8_t* ciphertext, uint8_t* plaintext);
ATCA_STATUS atcab_aes_decrypt_ext(ATCADevice device, uint16_t key_id, uint8_t key_block, const uint8_t* ciphertext, uint8_t* plaintext);
ATCA_STATUS atcab_aes_gfm(const uint8_t* h, const uint8_t* input, uint8_t* output);

/* AES GCM */
#if CALIB_AES_GCM_EN
ATCA_STATUS atcab_aes_gcm_init(atca_aes_gcm_ctx_t* ctx, uint16_t key_id, uint8_t key_block, const uint8_t* iv, size_t iv_size);
ATCA_STATUS atcab_aes_gcm_init_ext(ATCADevice device, atca_aes_gcm_ctx_t* ctx, uint16_t key_id, uint8_t key_block, const uint8_t* iv, size_t iv_size);
ATCA_STATUS atcab_aes_gcm_init_rand(atca_aes_gcm_ctx_t* ctx, uint16_t key_id, uint8_t key_block, size_t rand_size,
                                    const uint8_t* free_field, size_t free_field_size, uint8_t* iv);
ATCA_STATUS atcab_aes_gcm_aad_update(atca_aes_gcm_ctx_t* ctx, const uint8_t* aad, uint32_t aad_size);
ATCA_STATUS atcab_aes_gcm_aad_update_ext(ATCADevice device, atca_aes_gcm_ctx_t* ctx, const uint8_t* aad, uint32_t aad_size);
ATCA_STATUS atcab_aes_gcm_encrypt_update(atca_aes_gcm_ctx_t* ctx, const uint8_t* plaintext, uint32_t plaintext_size, uint8_t* ciphertext);
ATCA_STATUS atcab_aes_gcm_encrypt_update_ext(ATCADevice device, atca_aes_gcm_ctx_t* ctx, const uint8_t* plaintext, uint32_t plaintext_size,
                                             uint8_t* ciphertext);
ATCA_STATUS atcab_aes_gcm_encrypt_finish(atca_aes_gcm_ctx_t* ctx, uint8_t* tag, size_t tag_size);
ATCA_STATUS atcab_aes_gcm_encrypt_finish_ext(ATCADevice device, atca_aes_gcm_ctx_t* ctx, uint8_t* tag, size_t tag_size);
ATCA_STATUS atcab_aes_gcm_decrypt_update(atca_aes_gcm_ctx_t* ctx, const uint8_t* ciphertext, uint32_t ciphertext_size, uint8_t* plaintext);
ATCA_STATUS atcab_aes_gcm_decrypt_update_ext(ATCADevice device, atca_aes_gcm_ctx_t* ctx, const uint8_t* ciphertext, uint32_t ciphertext_size,
                                             uint8_t* plaintext);
ATCA_STATUS atcab_aes_gcm_decrypt_finish(atca_aes_gcm_ctx_t* ctx, const uint8_t* tag, size_t tag_size, bool* is_verified);
ATCA_STATUS atcab_aes_gcm_decrypt_finish_ext(ATCADevice device, atca_aes_gcm_ctx_t* ctx, const uint8_t* tag, size_t tag_size, bool* is_verified);
#endif

/* CheckMAC command */
ATCA_STATUS atcab_checkmac(uint8_t mode, uint16_t key_id, const uint8_t* challenge, const uint8_t* response, const uint8_t* other_data);
ATCA_STATUS atcab_checkmac_with_response_mac(uint8_t mode, const uint8_t* challenge, const uint8_t* response, const uint8_t* other_data, uint8_t *mac);

/* Counter command */
ATCA_STATUS atcab_counter(uint8_t mode, uint16_t counter_id, uint32_t* counter_value);
ATCA_STATUS atcab_counter_increment(uint16_t counter_id, uint32_t* counter_value);
ATCA_STATUS atcab_counter_read(uint16_t counter_id, uint32_t* counter_value);

/* DeriveKey command */
ATCA_STATUS atcab_derivekey(uint8_t mode, uint16_t key_id, const uint8_t* mac);
ATCA_STATUS atcab_derivekey_ext(ATCADevice device, uint8_t mode, uint16_t key_id, const uint8_t* mac);

/* ECDH command */
ATCA_STATUS atcab_ecdh_base(uint8_t mode, uint16_t key_id, const uint8_t* public_key, uint8_t* pms, uint8_t* out_nonce);
ATCA_STATUS atcab_ecdh(uint16_t key_id, const uint8_t* public_key, uint8_t* pms);

#if defined(ATCA_USE_CONSTANT_HOST_NONCE)
ATCA_STATUS atcab_ecdh_enc(uint16_t key_id, const uint8_t* public_key, uint8_t* pms, const uint8_t* read_key, uint16_t read_key_id);
#else
ATCA_STATUS atcab_ecdh_enc(uint16_t key_id, const uint8_t* public_key, uint8_t* pms, const uint8_t* read_key, uint16_t read_key_id,
                           const uint8_t num_in[NONCE_NUMIN_SIZE]);
#endif

ATCA_STATUS atcab_ecdh_ioenc(uint16_t key_id, const uint8_t* public_key, uint8_t* pms, const uint8_t* io_key);
ATCA_STATUS atcab_ecdh_tempkey(const uint8_t* public_key, uint8_t* pms);
ATCA_STATUS atcab_ecdh_tempkey_ioenc(const uint8_t* public_key, uint8_t* pms, const uint8_t* io_key);

// GenDig command functions
ATCA_STATUS atcab_gendig(uint8_t zone, uint16_t key_id, const uint8_t* other_data, uint8_t other_data_size);

// GenDivKey command functions
ATCA_STATUS atcab_gendivkey(const uint8_t* other_data);

// GenKey command functions
ATCA_STATUS atcab_genkey_base(uint8_t mode, uint16_t key_id, const uint8_t* other_data, uint8_t* public_key);
ATCA_STATUS atcab_genkey(uint16_t key_id, uint8_t* public_key);
ATCA_STATUS atcab_genkey_ext(ATCADevice device, uint16_t key_id, uint8_t* public_key);
ATCA_STATUS atcab_get_pubkey(uint16_t key_id, uint8_t* public_key);
ATCA_STATUS atcab_get_pubkey_ext(ATCADevice device, uint16_t key_id, uint8_t* public_key);

// HMAC command functions
ATCA_STATUS atcab_hmac(uint8_t mode, uint16_t key_id, uint8_t* digest);

// Info command functions
ATCA_STATUS atcab_info_base(uint8_t mode, uint16_t param2, uint8_t* out_data);
ATCA_STATUS atcab_info(uint8_t* revision);
ATCA_STATUS atcab_info_ext(ATCADevice device, uint8_t* revision);
ATCA_STATUS atcab_info_lock_status(uint16_t param2, uint8_t *is_locked);
ATCA_STATUS atcab_info_chip_status(uint8_t* chip_status);
ATCA_STATUS atcab_info_set_latch(bool state);
ATCA_STATUS atcab_info_get_latch(bool* state);

// KDF command functions
ATCA_STATUS atcab_kdf(uint8_t mode, uint16_t key_id, const uint32_t details, const uint8_t* message, uint8_t* out_data, uint8_t* out_nonce);

// Lock command functions
ATCA_STATUS atcab_lock(uint8_t mode, uint16_t summary_crc);
ATCA_STATUS atcab_lock_config_zone(void);
ATCA_STATUS atcab_lock_config_zone_ext(ATCADevice device);
ATCA_STATUS atcab_lock_config_zone_crc(uint16_t summary_crc);
ATCA_STATUS atcab_lock_data_zone(void);
ATCA_STATUS atcab_lock_data_zone_ext(ATCADevice device);
ATCA_STATUS atcab_lock_data_zone_crc(uint16_t summary_crc);
ATCA_STATUS atcab_lock_data_slot(uint16_t slot);
ATCA_STATUS atcab_lock_data_slot_ext(ATCADevice device, uint16_t slot);

// MAC command functions
ATCA_STATUS atcab_mac(uint8_t mode, uint16_t key_id, const uint8_t* challenge, uint8_t* digest);

// Nonce command functions
ATCA_STATUS atcab_nonce_base(uint8_t mode, uint16_t zero, const uint8_t* num_in, uint8_t* rand_out);
ATCA_STATUS atcab_nonce(const uint8_t* num_in);
ATCA_STATUS atcab_nonce_load(uint8_t target, const uint8_t* num_in, uint16_t num_in_size);
ATCA_STATUS atcab_nonce_rand(const uint8_t* num_in, uint8_t* rand_out);
ATCA_STATUS atcab_nonce_rand_ext(ATCADevice device, const uint8_t* num_in, uint8_t* rand_out);
ATCA_STATUS atcab_challenge(const uint8_t* num_in);
ATCA_STATUS atcab_challenge_seed_update(const uint8_t* num_in, uint8_t* rand_out);

// PrivWrite command functions
#if defined(ATCA_USE_CONSTANT_HOST_NONCE)
ATCA_STATUS atcab_priv_write(uint16_t key_id, const uint8_t priv_key[36], uint16_t write_key_id, const uint8_t write_key[32]);
#else
ATCA_STATUS atcab_priv_write(uint16_t key_id, const uint8_t priv_key[36], uint16_t write_key_id, const uint8_t write_key[32],
                             const uint8_t num_in[NONCE_NUMIN_SIZE]);
#endif

// Random command functions
ATCA_STATUS atcab_random(uint8_t* rand_out);
ATCA_STATUS atcab_random_ext(ATCADevice device, uint8_t* rand_out);

// Read command functions
ATCA_STATUS atcab_read_zone(uint8_t zone, uint16_t slot, uint8_t block, uint8_t offset, uint8_t* data, uint8_t len);
ATCA_STATUS atcab_read_zone_ext(ATCADevice device, uint8_t zone, uint16_t slot, uint8_t block, uint8_t offset, uint8_t* data, uint8_t len);
ATCA_STATUS atcab_is_locked(uint8_t zone, bool* is_locked);
ATCA_STATUS atcab_is_config_locked(bool* is_locked);
ATCA_STATUS atcab_is_config_locked_ext(ATCADevice device, bool* is_locked);
ATCA_STATUS atcab_is_data_locked(bool* is_locked);
ATCA_STATUS atcab_is_data_locked_ext(ATCADevice device, bool* is_locked);
ATCA_STATUS atcab_is_slot_locked(uint16_t slot, bool* is_locked);
ATCA_STATUS atcab_is_slot_locked_ext(ATCADevice device, uint16_t slot, bool* is_locked);
ATCA_STATUS atcab_is_private_ext(ATCADevice device, uint16_t slot, bool* is_private);
ATCA_STATUS atcab_is_private(uint16_t slot, bool* is_private);
ATCA_STATUS atcab_read_bytes_zone_ext(ATCADevice device, uint8_t zone, uint16_t slot, size_t offset, uint8_t* data, size_t length);
ATCA_STATUS atcab_read_bytes_zone(uint8_t zone, uint16_t slot, size_t offset, uint8_t* data, size_t length);
ATCA_STATUS atcab_read_serial_number(uint8_t* serial_number);
ATCA_STATUS atcab_read_serial_number_ext(ATCADevice device, uint8_t* serial_number);
ATCA_STATUS atcab_read_pubkey(uint16_t slot, uint8_t* public_key);
ATCA_STATUS atcab_read_pubkey_ext(ATCADevice device, uint16_t slot, uint8_t* public_key);
ATCA_STATUS atcab_read_sig(uint16_t slot, uint8_t* sig);
ATCA_STATUS atcab_read_config_zone(uint8_t* config_data);
ATCA_STATUS atcab_read_config_zone_ext(ATCADevice device, uint8_t* config_data);
ATCA_STATUS atcab_cmp_config_zone(uint8_t* config_data, bool* same_config);

#if defined(ATCA_USE_CONSTANT_HOST_NONCE)
ATCA_STATUS atcab_read_enc(uint16_t key_id, uint8_t block, uint8_t* data, const uint8_t* enc_key, const uint16_t enc_key_id);
#else
ATCA_STATUS atcab_read_enc(uint16_t key_id, uint8_t block, uint8_t* data, const uint8_t* enc_key, const uint16_t enc_key_id,
                           const uint8_t num_in[NONCE_NUMIN_SIZE]);
#endif

// SecureBoot command functions
ATCA_STATUS atcab_secureboot(uint8_t mode, uint16_t param2, const uint8_t* digest, const uint8_t* signature, uint8_t* mac);
ATCA_STATUS atcab_secureboot_mac(uint8_t mode, const uint8_t* digest, const uint8_t* signature, const uint8_t* num_in, const uint8_t* io_key,
                                 bool* is_verified);

/* SelfTest Command */
ATCA_STATUS atcab_selftest(uint8_t mode, uint16_t param2, uint8_t* result);

/* SHA Command  */
#define SHA_CONTEXT_MAX_SIZE                    (109)
ATCA_STATUS atcab_sha_base(uint8_t mode, uint16_t length, const uint8_t* data_in, uint8_t* data_out, uint16_t* data_out_size);
ATCA_STATUS atcab_sha_start(void);
ATCA_STATUS atcab_sha_update(const uint8_t* message);
ATCA_STATUS atcab_sha_end(uint8_t* digest, uint16_t length, const uint8_t* message);
ATCA_STATUS atcab_sha_read_context(uint8_t* context, uint16_t* context_size);
ATCA_STATUS atcab_sha_write_context(const uint8_t* context, uint16_t context_size);
ATCA_STATUS atcab_sha(uint16_t length, const uint8_t* message, uint8_t* digest);
ATCA_STATUS atcab_hw_sha2_256(const uint8_t* data, size_t data_size, uint8_t* digest);

ATCA_STATUS atcab_hw_sha2_256_init(atca_sha256_ctx_t* ctx);
ATCA_STATUS atcab_hw_sha2_256_update(atca_sha256_ctx_t* ctx, const uint8_t* data, size_t data_size);
ATCA_STATUS atcab_hw_sha2_256_finish(atca_sha256_ctx_t* ctx, uint8_t* digest);
ATCA_STATUS atcab_sha_hmac_init(atca_hmac_sha256_ctx_t* ctx, uint16_t key_slot);
ATCA_STATUS atcab_sha_hmac_update(atca_hmac_sha256_ctx_t* ctx, const uint8_t* data, size_t data_size);
ATCA_STATUS atcab_sha_hmac_finish(atca_hmac_sha256_ctx_t* ctx, uint8_t* digest, uint8_t target);

ATCA_STATUS atcab_sha_hmac(const uint8_t* data, size_t data_size, uint16_t key_slot, uint8_t* digest, uint8_t target);
ATCA_STATUS atcab_sha_hmac_ext(ATCADevice device, const uint8_t* data, size_t data_size, uint16_t key_slot, uint8_t* digest, uint8_t target);

/* Sign command */
ATCA_STATUS atcab_sign_base(uint8_t mode, uint16_t key_id, uint8_t* signature);
ATCA_STATUS atcab_sign(uint16_t key_id, const uint8_t* msg, uint8_t* signature);
ATCA_STATUS atcab_sign_ext(ATCADevice device, uint16_t key_id, const uint8_t* msg, uint8_t* signature);
ATCA_STATUS atcab_sign_internal(uint16_t key_id, bool is_invalidate, bool is_full_sn, uint8_t* signature);

/* UpdateExtra command */
ATCA_STATUS atcab_updateextra(uint8_t mode, uint16_t new_value);

/* Verify command */
ATCA_STATUS atcab_verify(uint8_t mode, uint16_t key_id, const uint8_t* signature, const uint8_t* public_key, const uint8_t* other_data, uint8_t* mac);
ATCA_STATUS atcab_verify_extern(const uint8_t* message, const uint8_t* signature, const uint8_t* public_key, bool* is_verified);
ATCA_STATUS atcab_verify_extern_ext(ATCADevice device, const uint8_t* message, const uint8_t* signature, const uint8_t* public_key, bool* is_verified);
ATCA_STATUS atcab_verify_extern_mac(const uint8_t* message, const uint8_t* signature, const uint8_t* public_key, const uint8_t* num_in, const uint8_t* io_key,
                                    bool* is_verified);
ATCA_STATUS atcab_verify_stored(const uint8_t* message, const uint8_t* signature, uint16_t key_id, bool* is_verified);
ATCA_STATUS atcab_verify_stored_ext(ATCADevice device, const uint8_t* message, const uint8_t* signature, uint16_t key_id, bool* is_verified);
ATCA_STATUS atcab_verify_stored_with_tempkey(const uint8_t* signature, uint16_t key_id, bool* is_verified);
ATCA_STATUS atcab_verify_stored_mac(const uint8_t* message, const uint8_t* signature, uint16_t key_id, const uint8_t* num_in, const uint8_t* io_key,
                                    bool* is_verified);

ATCA_STATUS atcab_verify_validate(uint16_t key_id, const uint8_t* signature, const uint8_t* other_data, bool* is_verified);
ATCA_STATUS atcab_verify_invalidate(uint16_t key_id, const uint8_t* signature, const uint8_t* other_data, bool* is_verified);

/* Write command functions */
ATCA_STATUS atcab_write(uint8_t zone, uint16_t address, const uint8_t* value, const uint8_t* mac);
ATCA_STATUS atcab_write_zone(uint8_t zone, uint16_t slot, uint8_t block, uint8_t offset, const uint8_t* data, uint8_t len);
ATCA_STATUS atcab_write_zone_ext(ATCADevice device, uint8_t zone, uint16_t slot, uint8_t block, uint8_t offset, const uint8_t* data, uint8_t len);
ATCA_STATUS atcab_write_bytes_zone_ext(ATCADevice device, uint8_t zone, uint16_t slot, size_t offset_bytes, const uint8_t* data, size_t length);
ATCA_STATUS atcab_write_bytes_zone(uint8_t zone, uint16_t slot, size_t offset_bytes, const uint8_t* data, size_t length);
ATCA_STATUS atcab_write_pubkey(uint16_t slot, const uint8_t* public_key);
ATCA_STATUS atcab_write_pubkey_ext(ATCADevice device, uint16_t slot, const uint8_t* public_key);
ATCA_STATUS atcab_write_config_zone(const uint8_t* config_data);
ATCA_STATUS atcab_write_config_zone_ext(ATCADevice device, const uint8_t* config_data);

#if defined(ATCA_USE_CONSTANT_HOST_NONCE)
ATCA_STATUS atcab_write_enc(uint16_t key_id, uint8_t block, const uint8_t* data, const uint8_t* enc_key, const uint16_t enc_key_id);
#else
ATCA_STATUS atcab_write_enc(uint16_t key_id, uint8_t block, const uint8_t* data, const uint8_t* enc_key, const uint16_t enc_key_id,
                            const uint8_t num_in[NONCE_NUMIN_SIZE]);
#endif

ATCA_STATUS atcab_write_config_counter(uint16_t counter_id, uint32_t counter_value);

#endif /* ATCA_TA_SUPPORT && ATCA_CA_SUPPORT */

#ifdef __cplusplus
}
#endif

/** @} */
/*lint -flb*/
#endif /* ATCA_BASIC_H_ */
