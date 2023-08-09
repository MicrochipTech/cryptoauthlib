/**
 * \file
 * \brief Embedded vectors for the PKCS7 padding algorithm
 */

#ifndef PKCS7_PAD_VECTORS_H
#define PKCS7_PAD_VECTORS_H

typedef struct
{
    const char * in;
    const char * out;
    uint8_t      blocksize;
} pkcs7_pad_test_vector;

extern const pkcs7_pad_test_vector pkcs7_pad_test_vectors[];
extern const pkcs7_pad_test_vector pkcs7_unpad_test_vectors[];
extern const size_t pkcs7_pad_test_vectors_count;
extern const size_t pkcs7_unpad_test_vectors_count;

#endif /* PKCS7_PAD_VECTORS_H */
