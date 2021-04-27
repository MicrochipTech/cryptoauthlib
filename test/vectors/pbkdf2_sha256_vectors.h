/**
 * \file
 * \brief Embedded vectors for the PBKDF2 algorithm
 */

#ifndef PBKDF2_VECTORS_H
#define PBKDF2_VECTORS_H


typedef struct
{
    uint32_t        c;
    const char *    p;
    size_t          plen;
    const char *    s;
    size_t          slen;
    const uint8_t * dk;
    size_t          dklen;
} pbkdf2_sha256_test_vector;

typedef struct
{
    uint32_t    c;
    const char* s;
    size_t      slen;
    uint8_t     dk[32];
} pbkdf2_sha256_fixed_size_test_vector;

extern const pbkdf2_sha256_test_vector pbkdf2_sha256_test_vectors[];
extern const size_t pbkdf2_sha256_test_vectors_count;

extern const pbkdf2_sha256_fixed_size_test_vector pbkdf2_sha256_fixed_size_test_vectors[];
extern const size_t pbkdf2_sha256_fixed_size_test_vectors_count;


#endif /* PBKDF2_VECTORS_H */
