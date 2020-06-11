

#ifndef AES_CMAC_NIST_VECTORS_H
#define AES_CMAC_NIST_VECTORS_H

#include <stdint.h>

extern const uint8_t g_aes_keys[4][16];
extern const uint8_t g_plaintext[64];

extern const uint32_t g_cmac_msg_sizes[4];
extern const uint8_t g_cmacs[4][4][16];

#endif /* AES_CMAC_NIST_VECTORS_H */
