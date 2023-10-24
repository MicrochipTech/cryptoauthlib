/*
 * Copyright (c) 2017 SURFnet bv
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*****************************************************************************
   cryptoki.h

   Set the PKCS#11 macros.
*****************************************************************************/

#ifndef CRYPTOKI_H
#define CRYPTOKI_H

#include "atca_compiler.h"



#ifdef _MSC_VER
#pragma warning(push, 0)
#endif

//#if defined(_WIN32) || defined(__GNUC__)
//#pragma pack(push, cryptoki, 1)
//#endif

// Generic helper definitions for shared library support
#if defined _WIN32 || defined __CYGWIN__
#define PKCS11_HELPER_DLL_IMPORT __declspec(dllimport)
#define PKCS11_HELPER_DLL_EXPORT __declspec(dllexport)
#define PKCS11_HELPER_DLL_LOCAL
#else
#if __GNUC__ >= 4
#define PKCS11_HELPER_DLL_IMPORT __attribute__ ((visibility("default")))
#define PKCS11_HELPER_DLL_EXPORT __attribute__ ((visibility("default")))
#define PKCS11_HELPER_DLL_LOCAL  __attribute__ ((visibility("hidden")))
#else
#define PKCS11_HELPER_DLL_IMPORT
#define PKCS11_HELPER_DLL_EXPORT
#define PKCS11_HELPER_DLL_LOCAL
#endif
#endif

// Now we use the generic helper definitions above to define PKCS11_API and PKCS11_LOCAL.
// PKCS11_API is used for the public API symbols. It either DLL imports or DLL exports (or does nothing for static build)
// PKCS11_LOCAL is used for non-api symbols.




#ifdef PKCS11_DLL_EXPORTS // defined if we are building the PKCS11 DLL (instead of using it)
#define PKCS11_API PKCS11_HELPER_DLL_EXPORT
#elif defined(PKCS11_DLL) // defined if PKCS11 is compiled as a DLL
#define PKCS11_API PKCS11_HELPER_DLL_IMPORT
#else // PKCS11_DLL is not defined: this means PKCS11 is a static lib.
#define PKCS11_API
#endif // PKCS11_DLL
#define PKCS11_LOCAL PKCS11_HELPER_DLL_LOCAL

// 1. CK_PTR: The indirection string for making a pointer to an
// object.

#define CK_PTR *

// 2. CK_DECLARE_FUNCTION(returnType, name): A macro which makes
// an importable Cryptoki library function declaration out of a
// return type and a function name.

#define CK_DECLARE_FUNCTION(returnType, name) returnType PKCS11_API name

// 3. CK_DECLARE_FUNCTION_POINTER(returnType, name): A macro
// which makes a Cryptoki API function pointer declaration or
// function pointer type declaration out of a return type and a
// function name.

#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType PKCS11_API(*name)

// 4. CK_CALLBACK_FUNCTION(returnType, name): A macro which makes
// a function pointer type for an application callback out of
// a return type for the callback and a name for the callback.

#define CK_CALLBACK_FUNCTION(returnType, name) returnType(*name)

// 5. NULL_PTR: This macro is the value of a NULL pointer.

#ifndef NULL_PTR
#define NULL_PTR 0
#endif

#ifdef __COVERITY__
#pragma coverity compliance block(include) \
    (deviate "CERT DCL37-C" "PKCS11 headers are defined by the standard and may not be modified") \
    (deviate "MISRA C-2012 Rule 3.1" "PKCS11 headers are defined by the standard and may not be modified") \
    (deviate "MISRA C-2012 Rule 5.2" "PKCS11 headers are defined by the standard and may not be modified") \
    (deviate "MISRA C-2012 Rule 5.8" "PKCS11 headers are defined by the standard and may not be modified") \
    (deviate "MISRA C-2012 Rule 21.1" "PKCS11 headers are defined by the standard and may not be modified") \
    (deviate "MISRA C-2012 Rule 21.2" "PKCS11 headers are defined by the standard and may not be modified")
#endif

#include "pkcs11.h"

#ifdef __COVERITY__
#pragma coverity compliance end_block(include) \
    "CERT DCL37-C" \
    "MISRA C-2012 Rule 3.1" \
    "MISRA C-2012 Rule 5.2" \
    "MISRA C-2012 Rule 5.8" \
    "MISRA C-2012 Rule 21.1" \
    "MISRA C-2012 Rule 21.2"
#endif


//#if defined(_WIN32) || defined(__GNUC__)
//#pragma pack(pop, cryptoki)
//#endif

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#endif // !CRYPTOKI_H
