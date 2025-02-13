/**
 * \file
 * \brief Common defines for CryptoAuthLib software crypto wrappers.
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

#ifndef ATCA_CRYPTO_SW_H
#define ATCA_CRYPTO_SW_H

#include <stdint.h>
#include <stdlib.h>

#include "crypto/crypto_sw_config_check.h"
#include "atca_status.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ATCA_SHA1_DIGEST_SIZE       (20U)
#define ATCA_SHA2_256_DIGEST_SIZE   (32U)
#define ATCA_SHA2_256_BLOCK_SIZE    (64U)
#define ATCA_SHA2_384_DIGEST_SIZE   (48U)
#define ATCA_SHA2_384_BLOCK_SIZE    (128U)
#define ATCA_SHA2_512_DIGEST_SIZE   (64U)
#define ATCA_SHA2_512_BLOCK_SIZE    (128U)

#if ATCA_HOSTLIB_EN
ATCA_STATUS atcac_sw_random(uint8_t* data, size_t data_size);
#endif

#if ATCAC_SHA1_EN || ATCA_CRYPTO_SHA1_EN
#if ATCA_CRYPTO_SHA1_EN
typedef struct atcac_sha1_ctx
{
    uint32_t pad[32];
} atcac_sha1_ctx_t;
#else
struct atcac_sha1_ctx;
#endif

#if defined(ATCA_BUILD_SHARED_LIBS) || defined(ATCA_HEAP)
struct atcac_sha1_ctx * atcac_sha1_ctx_new(void);
void atcac_sha1_ctx_free(struct atcac_sha1_ctx * ctx);
#endif

ATCA_STATUS atcac_sw_sha1_init(struct atcac_sha1_ctx* ctx);
ATCA_STATUS atcac_sw_sha1_update(struct atcac_sha1_ctx* ctx, const uint8_t* data, size_t data_size);
ATCA_STATUS atcac_sw_sha1_finish(struct atcac_sha1_ctx* ctx, uint8_t digest[ATCA_SHA1_DIGEST_SIZE]);
#endif /* ATCAC_SHA1_EN || ATCA_CRYPTO_SHA1_EN */


#if ATCAC_SHA256_EN || ATCA_CRYPTO_SHA256_EN
#if ATCA_CRYPTO_SHA256_EN
typedef struct atcac_sha2_256_ctx
{
    uint32_t pad[48];
} atcac_sha2_256_ctx_t;
#else
struct atcac_sha2_256_ctx;
#endif

#if defined(ATCA_BUILD_SHARED_LIBS) || defined(ATCA_HEAP)
struct atcac_sha2_256_ctx * atcac_sha256_ctx_new(void);
void atcac_sha256_ctx_free(struct atcac_sha2_256_ctx * ctx);
#endif

ATCA_STATUS atcac_sw_sha2_256_init(struct atcac_sha2_256_ctx* ctx);
ATCA_STATUS atcac_sw_sha2_256_update(struct atcac_sha2_256_ctx* ctx, const uint8_t* data, size_t data_size);
ATCA_STATUS atcac_sw_sha2_256_finish(struct atcac_sha2_256_ctx* ctx, uint8_t digest[ATCA_SHA2_256_DIGEST_SIZE]);
#endif /* ATCAC_SHA256_EN || ATCA_CRYPTO_SHA256_EN */

#if ATCAC_SHA384_EN || ATCA_CRYPTO_SHA384_EN
#if ATCA_CRYPTO_SHA384_EN
typedef struct atcac_sha2_384_ctx
{
    uint64_t pad[48];
} atcac_sha2_384_ctx_t;
#else
struct atcac_sha2_384_ctx;
#endif

#if defined(ATCA_BUILD_SHARED_LIBS) || defined(ATCA_HEAP)
struct atcac_sha2_384_ctx * atcac_sha384_ctx_new(void);
void atcac_sha384_ctx_free(struct atcac_sha2_384_ctx * ctx);
#endif

ATCA_STATUS atcac_sw_sha2_384_init(struct atcac_sha2_384_ctx* ctx);
ATCA_STATUS atcac_sw_sha2_384_update(struct atcac_sha2_384_ctx* ctx, const uint8_t* data, size_t data_size);
ATCA_STATUS atcac_sw_sha2_384_finish(struct atcac_sha2_384_ctx* ctx, uint8_t digest[ATCA_SHA2_384_DIGEST_SIZE]);
#endif /* ATCAC_SHA384_EN || ATCA_CRYPTO_SHA384_EN */

#if ATCAC_SHA512_EN || ATCA_CRYPTO_SHA512_EN
#if ATCA_CRYPTO_SHA512_EN
typedef struct atcac_sha2_512_ctx
{
    uint64_t pad[48];
} atcac_sha2_512_ctx_t;
#else
struct atcac_sha2_512_ctx;
#endif

#if defined(ATCA_BUILD_SHARED_LIBS) || defined(ATCA_HEAP)
struct atcac_sha2_512_ctx * atcac_sha512_ctx_new(void);
void atcac_sha512_ctx_free(struct atcac_sha2_512_ctx * ctx);
#endif

ATCA_STATUS atcac_sw_sha2_512_init(struct atcac_sha2_512_ctx* ctx);
ATCA_STATUS atcac_sw_sha2_512_update(struct atcac_sha2_512_ctx* ctx, const uint8_t* data, size_t data_size);
ATCA_STATUS atcac_sw_sha2_512_finish(struct atcac_sha2_512_ctx* ctx, uint8_t digest[ATCA_SHA2_512_DIGEST_SIZE]);
#endif /* ATCAC_SHA512_EN || ATCA_CRYPTO_SHA512_EN */

#if ATCAC_SHA256_HMAC_EN || ATCA_CRYPTO_SHA2_HMAC_EN || LIBRARY_BUILD_EN_CHECK
#if ATCA_CRYPTO_SHA2_HMAC_EN
typedef struct atcac_hmac_ctx
{
    atcac_sha2_256_ctx_t* sha256_ctx;
    uint8_t               ipad[ATCA_SHA2_256_BLOCK_SIZE];
    uint8_t               opad[ATCA_SHA2_256_BLOCK_SIZE];
} atcac_hmac_ctx_t;
#elif LIBRARY_BUILD_EN_CHECK
typedef struct atcac_hmac_ctx
{
    uint8_t ctx[MAX_HMAC_CTX_SIZE];
} atcac_hmac_ctx_t;
#else
struct atcac_hmac_ctx;
#endif

#if defined(ATCA_BUILD_SHARED_LIBS) || defined(ATCA_HEAP)
struct atcac_hmac_ctx * atcac_hmac_ctx_new(void);
void atcac_hmac_ctx_free(struct atcac_hmac_ctx * ctx);
#endif

ATCA_STATUS atcac_sha256_hmac_init(struct atcac_hmac_ctx* ctx, struct atcac_sha2_256_ctx* sha256_ctx,
                                   const uint8_t* key, const uint8_t key_len);
ATCA_STATUS atcac_sha256_hmac_update(struct atcac_hmac_ctx* ctx, const uint8_t* data, size_t data_size);
ATCA_STATUS atcac_sha256_hmac_finish(struct atcac_hmac_ctx* ctx, uint8_t* digest, size_t* digest_len);
#endif /* ATCAC_SHA256_HMAC_EN || ATCA_CRYPTO_SHA2_HMAC_EN || LIBRARY_BUILD_EN_CHECK */


#if ATCAC_AES_CMAC_EN || ATCA_CRYPTO_AES_CMAC_EN
#if ATCA_CRYPTO_AES_CMAC_EN
/* Dummy structure for memory reservation */
typedef struct atcac_aes_cmac_ctx 
{
    uint8_t ctx[MAX_AES_CMAC_CTX_SIZE];
}atcac_aes_cmac_ctx_t;
#else
struct atcac_aes_cmac_ctx;
#endif

#if defined(ATCA_BUILD_SHARED_LIBS) || defined(ATCA_HEAP)
struct atcac_aes_cmac_ctx * atcac_aes_cmac_ctx_new(void);
void atcac_aes_cmac_ctx_free(struct atcac_aes_cmac_ctx * ctx);
#endif

ATCA_STATUS atcac_aes_cmac_init(struct atcac_aes_cmac_ctx* ctx, const uint8_t* key, const uint8_t key_len);
ATCA_STATUS atcac_aes_cmac_update(struct atcac_aes_cmac_ctx* ctx, const uint8_t* data, const size_t data_size);
ATCA_STATUS atcac_aes_cmac_finish(struct atcac_aes_cmac_ctx* ctx, uint8_t* cmac, size_t* cmac_size);
#endif /* ATCAC_AES_CMAC_EN || ATCA_CRYPTO_AES_CMAC_EN */


#if ATCAC_AES_GCM_EN || ATCA_CRYPTO_AES_GCM_EN
#if ATCA_CRYPTO_AES_GCM_EN
/* Dummy structure for memory reservation */
typedef struct atcac_aes_gcm_ctx 
{
    uint8_t ctx[MAX_AES_GCM_CTX_SIZE];
}atcac_aes_gcm_ctx_t;
#else
struct atcac_aes_gcm_ctx;
#endif

#if defined(ATCA_BUILD_SHARED_LIBS) || defined(ATCA_HEAP)
struct atcac_aes_gcm_ctx * atcac_aes_gcm_ctx_new(void);
void atcac_aes_gcm_ctx_free(struct atcac_aes_gcm_ctx * ctx);
#endif

ATCA_STATUS atcac_aes_gcm_encrypt_start(struct atcac_aes_gcm_ctx* ctx, const uint8_t* key, const uint8_t key_len,
                                        const uint8_t* iv, const uint8_t iv_len);
ATCA_STATUS atcac_aes_gcm_decrypt_start(struct atcac_aes_gcm_ctx* ctx, const uint8_t* key, const uint8_t key_len,
                                        const uint8_t* iv, const uint8_t iv_len);
ATCA_STATUS atcac_aes_gcm_encrypt(struct atcac_aes_gcm_ctx* ctx, const uint8_t* plaintext, const size_t pt_len,
                                  uint8_t* ciphertext, uint8_t* tag, size_t tag_len, const uint8_t* aad,
                                  const size_t aad_len);
ATCA_STATUS atcac_aes_gcm_decrypt(struct atcac_aes_gcm_ctx* ctx, const uint8_t* ciphertext, const size_t ct_len,
                                  uint8_t* plaintext, const uint8_t* tag, size_t tag_len, const uint8_t* aad,
                                  const size_t aad_len, bool* is_verified);

ATCA_STATUS atcac_aes_gcm_aad_update(struct atcac_aes_gcm_ctx* ctx, const uint8_t* aad, const size_t aad_len);
ATCA_STATUS atcac_aes_gcm_encrypt_update(struct atcac_aes_gcm_ctx* ctx, const uint8_t* plaintext, const size_t pt_len,
                                         uint8_t* ciphertext, size_t* ct_len);
ATCA_STATUS atcac_aes_gcm_encrypt_finish(struct atcac_aes_gcm_ctx* ctx, uint8_t* tag, size_t tag_len);
ATCA_STATUS atcac_aes_gcm_decrypt_update(struct atcac_aes_gcm_ctx* ctx, const uint8_t* ciphertext, const size_t ct_len,
                                         uint8_t* plaintext, size_t* pt_len);
ATCA_STATUS atcac_aes_gcm_decrypt_finish(struct atcac_aes_gcm_ctx* ctx, const uint8_t* tag, size_t tag_len,
                                         bool* is_verified);

#endif /* ATCAC_AES_GCM_EN || ATCA_CRYPTO_AES_GCM_EN */

#if ATCAC_PKEY_EN
struct atcac_pk_ctx;
#if defined(ATCA_BUILD_SHARED_LIBS) || defined(ATCA_HEAP)
struct atcac_pk_ctx * atcac_pk_ctx_new(void);
void atcac_pk_ctx_free(struct atcac_pk_ctx * ctx);
#endif

ATCA_STATUS atcac_pk_init(struct atcac_pk_ctx* ctx, const uint8_t* buf, size_t buflen, uint8_t key_type, bool pubkey);
ATCA_STATUS atcac_pk_init_pem(struct atcac_pk_ctx* ctx, const uint8_t* buf, size_t buflen, bool pubkey);
ATCA_STATUS atcac_pk_free(struct atcac_pk_ctx* ctx);
ATCA_STATUS atcac_pk_public(struct atcac_pk_ctx* ctx, uint8_t* buf, size_t* buflen);
ATCA_STATUS atcac_pk_sign(struct atcac_pk_ctx* ctx, const uint8_t* digest, size_t dig_len, uint8_t* signature, size_t* sig_len);
ATCA_STATUS atcac_pk_verify(struct atcac_pk_ctx* ctx, const uint8_t* digest, size_t dig_len, const uint8_t* signature, size_t sig_len);
ATCA_STATUS atcac_pk_derive(struct atcac_pk_ctx* private_ctx, struct atcac_pk_ctx* public_ctx, uint8_t* buf, size_t* buflen);
#endif /* ATCAC_PKEY_EN */

#if ATCAC_PBKDF2_SHA256_EN
ATCA_STATUS atcac_pbkdf2_sha256(const uint32_t iter, const uint8_t* password, const size_t password_len,
                                const uint8_t* salt, const size_t salt_len, uint8_t* result, size_t result_len);
#endif

#if defined(HOSTLIB_CERT_EN)
#if HOSTLIB_CERT_EN
#include "cal_buffer.h"
struct atcac_x509_ctx;

ATCA_STATUS atcac_parse_der(struct atcac_x509_ctx ** cert, cal_buffer *der);
ATCA_STATUS atcac_get_subject(const struct atcac_x509_ctx* cert, cal_buffer* cert_subject);
ATCA_STATUS atcac_get_subj_public_key(const struct atcac_x509_ctx * cert, cal_buffer * subj_public_key);
ATCA_STATUS atcac_get_subj_key_id(const struct atcac_x509_ctx * cert, cal_buffer * subj_public_key_id);
ATCA_STATUS atcac_get_issue_date(const struct atcac_x509_ctx * cert, cal_buffer * not_before, uint8_t * fmt);
ATCA_STATUS atcac_get_expire_date(const struct atcac_x509_ctx * cert, cal_buffer * not_after, uint8_t * fmt);
ATCA_STATUS atcac_get_cert_sn(const struct atcac_x509_ctx * cert, cal_buffer * cert_sn);
ATCA_STATUS atcac_get_issuer(const struct atcac_x509_ctx* cert, cal_buffer* issuer_buf);
ATCA_STATUS atcac_get_auth_key_id(const struct atcac_x509_ctx * cert, cal_buffer * auth_key_id);
void atcac_x509_free(void* cert);

#endif /* HOSTLIB_CERT_EN */
#endif /* defined(HOSTLIB_CERT_EN) */

#ifdef __cplusplus
}
#endif

#endif /* ATCA_CRYPTO_SW_H */
