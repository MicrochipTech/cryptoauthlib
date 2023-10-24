/**
 * \file
 * \brief PKCS11 Library Initialization & Context
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

#ifndef PKCS11_INIT_H_
#define PKCS11_INIT_H_

#include "atca_compiler.h"
#include "pkcs11_config.h"
#include "pkcs11_os.h"
#include "cryptoauthlib.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Device operations requiring context tracking */
#define PKCS11_AES_OP           (0x0u)
#define PKCS11_DIGEST_OP_0      (0x1u)
#define PKCS11_DIGEST_OP_1      (0x2u)
#define PKCS11_AUTH_OP_0        (0x3u)
#define PKCS11_AUTH_OP_1        (0x4u)

#define PKCS11_MAX_DEV_CTX      (5u)

#define MAX_DIGEST_SESSIONS     (2u)
#define MAX_AUTH_SESSIONS       (2u)

/** Context Tracking Info */
typedef struct
{
    CK_SESSION_HANDLE session;
#if defined(_WIN32) || defined(__linux__) || defined(__APPLE__)
    hal_pid_t owner;
#endif
} pkcs11_dev_ctx;

/** Reservable Device Resources */
typedef struct
{
    pkcs11_dev_ctx contexts[PKCS11_MAX_DEV_CTX];
} pkcs11_dev_res;

/** Device state tracker structure */
typedef struct
{
    /** Lock to protect concurent access to the device */
    hal_mutex_t dev_lock;
    /** Track the usage of device resources*/
    pkcs11_dev_res resources[PKCS11_MAX_SLOTS_ALLOWED];
} pkcs11_dev_state;

/** Library Context */
typedef struct pkcs11_lib_ctx_s
{
    /** Indicates that the library has been initialized */
    CK_BBOOL initialized;
    /** Arguments provided by the app for C_Initialize */
    CK_C_INITIALIZE_ARGS init_args;
    /** Application Lock for concurrent access to the library if the application will be using threads */
    CK_VOID_PTR lib_lock;
    /** Device State state and Lock (if configured) */
    pkcs11_dev_state* dev_state;
    /** Flag to indicate if a device lock is enabled and configured */
    CK_BBOOL dev_lock_enabled;
    /** Configured slots in the library */
    CK_VOID_PTR slots;
    /** Number of configured slots */
    CK_ULONG slot_cnt;
#if !PKCS11_USE_STATIC_CONFIG
    /** Filesystem path where the base config is located */
    CK_CHAR config_path[200];
#endif
} pkcs11_lib_ctx;


#ifdef __cplusplus
}
#endif

CK_RV pkcs11_init(CK_C_INITIALIZE_ARGS const * pInitArgs);
CK_RV pkcs11_deinit(CK_VOID_PTR pReserved);
CK_RV pkcs11_init_check(pkcs11_lib_ctx_ptr * ppContext, CK_BBOOL lock);

pkcs11_lib_ctx_ptr pkcs11_get_context(void);
CK_RV pkcs11_lock_context(pkcs11_lib_ctx_ptr pContext);
CK_RV pkcs11_unlock_context(pkcs11_lib_ctx_ptr pContext);

CK_RV pkcs11_lock_device(pkcs11_lib_ctx_ptr pContext);
CK_RV pkcs11_unlock_device(pkcs11_lib_ctx_ptr pContext);

CK_RV pkcs11_lock_both(pkcs11_lib_ctx_ptr pContext);
CK_RV pkcs11_unlock_both(pkcs11_lib_ctx_ptr pContext);

#endif /* PKCS11_INIT_H_ */
