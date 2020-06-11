

#ifndef AES_GCM_NIST_VECTORS_H
#define AES_GCM_NIST_VECTORS_H

#include <stdint.h>
#include <stdlib.h>

#define GCM_TEST_VECTORS_DATA_SIZE_MAX      100
#define GCM_TEST_VECTORS_COUNT              13

#ifndef AES_DATA_SIZE
#define AES_DATA_SIZE                       16
#endif

typedef struct
{
    const char* vector_name;
    uint8_t     key[32];
    size_t      iv_size;
    uint8_t     iv[GCM_TEST_VECTORS_DATA_SIZE_MAX];
    uint32_t    text_size;
    uint8_t     plaintext[GCM_TEST_VECTORS_DATA_SIZE_MAX];
    uint8_t     ciphertext[GCM_TEST_VECTORS_DATA_SIZE_MAX];
    uint32_t    aad_size;
    uint8_t     aad[GCM_TEST_VECTORS_DATA_SIZE_MAX];
    uint8_t     tag[AES_DATA_SIZE];
}aes_gcm_test_vectors;

extern const aes_gcm_test_vectors gcm_test_cases[GCM_TEST_VECTORS_COUNT];

#endif /* AES_GCM_NIST_VECTORS_H */
