/**
 * \file
 * \brief Embedded vectors for PKCS7 Padding
 */

#include "cryptoauthlib.h"
#include "pkcs7_pad_vectors.h"

const pkcs7_pad_test_vector pkcs7_pad_test_vectors[] = {
    {
        "FFFFFF",
        "FFFFFF0D0D0D0D0D0D0D0D0D0D0D0D0D",
        16
    },
    {
        "FFFFFFFF",
        "FFFFFFFF1C1C1C1C1C1C1C1C1C1C1C1C1C1C1C1C1C1C1C1C1C1C1C1C1C1C1C1C",
        32,
    },
    {
        "FFFFFFFFFFFF",
        "FFFFFFFFFFFF3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A",
        64
    },
    {
        "FFFFFFFFFFFFFFFF",
        "FFFFFFFFFFFFFFFF0808080808080808",
        8
    },
    {
        "FFFFFFFFFFFFFFFFFF",
        "FFFFFFFFFFFFFFFFFF07070707070707",
        8
    },
    {
        "82",
        "8207070707070707",
        8
    }
};
const size_t pkcs7_pad_test_vectors_count = sizeof(pkcs7_pad_test_vectors) / sizeof(pkcs7_pad_test_vectors[0]);

const pkcs7_pad_test_vector pkcs7_unpad_test_vectors[] = {
    {
        "FFFFFFFFFFFFFFFFFF07070706070707",
        NULL,
        8
    },
    {
        "FFFFFFFFFFFFFFFFFFFF070707070707",
        NULL,
        8
    },
    {
        "82040404",
        NULL,
        4
    },
    {
        "82050505",
        NULL,
        4
    },
    {
        "820606060606",
        NULL,
        6
    },
    {
        "8208080808080808",
        NULL,
        8
    }
};
const size_t pkcs7_unpad_test_vectors_count = sizeof(pkcs7_unpad_test_vectors) / sizeof(pkcs7_unpad_test_vectors[0]);
