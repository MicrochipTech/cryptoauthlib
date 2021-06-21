/*
 *  Resources copied from mbedtls internals 
 * 
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

#ifndef ATCA_MBEDTLS_PATCH_H
#define ATCA_MBEDTLS_PATCH_H

#ifdef MBEDTLS_ECDSA_C
int mbedtls_ecdsa_signature_to_asn1(const mbedtls_mpi* r, const mbedtls_mpi* s, unsigned char* sig, size_t* slen);
#endif


#endif
