#include "vector_utils.h"

#if defined(_WIN32) || defined(__linux__)

#include <stdbool.h>
#include <string.h>

#include "third_party/unity/unity.h"

static void hex_to_uint8(const char hex_str[2], uint8_t* num)
{
    *num = 0;

    if (hex_str[0] >= '0' && hex_str[0] <= '9')
    {
        *num += (hex_str[0] - '0') << 4;
    }
    else if (hex_str[0] >= 'A' && hex_str[0] <= 'F')
    {
        *num += (hex_str[0] - 'A' + 10) << 4;
    }
    else if (hex_str[0] >= 'a' && hex_str[0] <= 'f')
    {
        *num += (hex_str[0] - 'a' + 10) << 4;
    }
    else
    {
        TEST_FAIL_MESSAGE("Not a hex digit.");
    }

    if (hex_str[1] >= '0' && hex_str[1] <= '9')
    {
        *num += (hex_str[1] - '0');
    }
    else if (hex_str[1] >= 'A' && hex_str[1] <= 'F')
    {
        *num += (hex_str[1] - 'A' + 10);
    }
    else if (hex_str[1] >= 'a' && hex_str[1] <= 'f')
    {
        *num += (hex_str[1] - 'a' + 10);
    }
    else
    {
        TEST_FAIL_MESSAGE("Not a hex digit.");
    }
}

static void hex_to_data(const char* hex_str, uint8_t* data, size_t data_size)
{
    size_t i = 0;

    TEST_ASSERT_EQUAL_MESSAGE(data_size * 2, strlen(hex_str) - 1, "Hex string unexpected length.");

    for (i = 0; i < data_size; i++)
    {
        hex_to_uint8(&hex_str[i * 2], &data[i]);
    }
}

static char line[16384];

ATCA_STATUS read_rsp_match_value(FILE* file, const char* name, const char* match)
{
    char* str = NULL;
    size_t name_size = strlen(name);

    do
    {
        str = fgets(line, sizeof(line), file);
        if (str == NULL)
        {
            continue;
        }
        else
        {
            size_t ln = strlen(line);
            if (ln > 0 && line[ln - 2] == '\r')
            {
                line[ln - 1] = 0;
            }
        }

        if (memcmp(line, name, name_size) == 0)
        {
            str = &line[name_size];
        }
        else
        {
            str = NULL;
        }
    }
    while (str == NULL && !feof(file));

    if (str != NULL)
    {
        if (0 == strcmp(str, match))
        {
            return ATCA_SUCCESS;
        }
    }

    return ATCA_GEN_FAIL;
}

ATCA_STATUS read_rsp_hex_value(FILE* file, const char* name, uint8_t* data, size_t data_size)
{
    char* str = NULL;
    size_t name_size = strlen(name);

    do
    {
        str = fgets(line, sizeof(line), file);
        if (str == NULL)
        {
            continue;
        }
        else
        {
            size_t ln = strlen(line);
            if (ln > 0 && line[ln - 2] == '\r')
            {
                line[ln - 1] = 0;
            }
        }

        if (memcmp(line, name, name_size) == 0)
        {
            str = &line[name_size];
        }
        else
        {
            str = NULL;
        }
    }
    while (str == NULL && !feof(file));
    if (str == NULL)
    {
        return ATCA_GEN_FAIL;
    }
    hex_to_data(str, data, data_size);

    return ATCA_SUCCESS;
}

ATCA_STATUS read_rsp_int_value(FILE* file, const char* name, char* found, int* value)
{
    static char line[2048];
    char* str = NULL;
    size_t name_size = strlen(name);

    do
    {
        str = fgets(line, sizeof(line), file);
        if (str == NULL)
        {
            continue;
        }
        else
        {
            size_t ln = strlen(line);
            if (ln > 0 && line[ln - 2] == '\r')
            {
                line[ln - 1] = 0;
            }
        }

        if (line[0] == '[' && NULL != found)
        {
            char * eq = strstr(line, " = ");
            if (NULL != eq)
            {
                str = eq + 3;
                *eq = '\0';
                found = &line[1];
            }
        }
        else if (memcmp(line, name, name_size) == 0)
        {
            str = &line[name_size];
        }
        else
        {
            str = NULL;
        }
    }
    while (str == NULL && !feof(file));

    if (str == NULL)
    {
        return ATCA_GEN_FAIL;
    }
    *value = atoi(str);

    return ATCA_SUCCESS;
}

static FILE * g_rsp_file;
static void * g_rsp_ctx;

ATCA_STATUS open_vectors_file(const char * path)
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if (NULL != g_rsp_file)
    {
        (void)fclose(g_rsp_file);
        g_rsp_file = NULL;
    }

    if (NULL != (g_rsp_file = fopen(path, "r")))
    {
        status = ATCA_SUCCESS;
    }
    else
    {
        status = ATCA_GEN_FAIL;
    }

    return status;
}

void close_vectors_file(void)
{
    if (NULL != g_rsp_file)
    {
        (void)fclose(g_rsp_file);
        g_rsp_file = NULL;
    }
    if (NULL != g_rsp_ctx)
    {
        free(g_rsp_ctx);
        g_rsp_ctx = NULL;
    }
}

void free_vector(void * ptr)
{
    if (NULL != ptr)
    {
        free(ptr);
    }
}

ATCA_STATUS load_cmac_vector(cmac_vector ** vector)
{
    ATCA_STATUS status = ATCA_BAD_PARAM;
    cmac_vector * v = NULL;

    do
    {
        int count = 0;
        int klen = 0;
        int mlen = 0;
        int tlen = 0;

        if (NULL == g_rsp_file || NULL == vector)
        {
            break;
        }

        if (ATCA_SUCCESS != (status = read_rsp_int_value(g_rsp_file, "Count = ", NULL, &count)))
        {
            /* End of file */
            *vector = NULL;
            status = ATCA_SUCCESS;
            break;
        }

        if (ATCA_SUCCESS != (status = read_rsp_int_value(g_rsp_file, "Klen = ", NULL, &klen)))
        {
            break;
        }
        if (0 > klen)
        {
            status = ATCA_GEN_FAIL;
            break;
        }

        if (ATCA_SUCCESS != (status = read_rsp_int_value(g_rsp_file, "Mlen = ", NULL, &mlen)))
        {
            break;
        }
        if (0 > mlen)
        {
            status = ATCA_GEN_FAIL;
            break;
        }

        if (ATCA_SUCCESS != (status = read_rsp_int_value(g_rsp_file, "Tlen = ", NULL, &tlen)))
        {
            break;
        }
        if (0 > tlen)
        {
            status = ATCA_GEN_FAIL;
            break;
        }

        size_t vsize = sizeof(cmac_vector_info) + (size_t)(klen + tlen) + (size_t)((0 == mlen) ? 1 : mlen);
        if (NULL != (v = malloc(vsize)))
        {
            v->meta.count = count;
            v->meta.klen = klen;
            v->meta.mlen = mlen;
            v->meta.tlen = tlen;
            v->meta.key = v->data;
            v->meta.mac = &v->data[klen];
            v->meta.msg = &v->data[klen + tlen];
        }
        else
        {
            status = ATCA_ALLOC_FAILURE;
            break;
        }

        if (ATCA_SUCCESS != (status = read_rsp_hex_value(g_rsp_file, "Key = ", v->meta.key, klen)))
        {
            break;
        }

        if (ATCA_SUCCESS != (status = read_rsp_hex_value(g_rsp_file, "Msg = ", v->meta.msg, (0 == mlen) ? 1 : mlen)))
        {
            break;
        }

        if (ATCA_SUCCESS == (status = read_rsp_hex_value(g_rsp_file, "Mac = ", v->meta.mac, tlen)))
        {
            *vector = v;
        }
    }
    while (false);

    if (ATCA_SUCCESS != status && NULL != v)
    {
        free(v);
    }

    return status;
}


ATCA_STATUS load_hmac_vector(hmac_vector ** vector)
{
    ATCA_STATUS status = ATCA_BAD_PARAM;
    hmac_vector * v = NULL;

    do
    {
        int count = 0;
        int klen = 0;
        int tlen = 0;

        if (NULL == g_rsp_file || NULL == vector)
        {
            break;
        }

        if (ATCA_SUCCESS != (status = read_rsp_int_value(g_rsp_file, "Count = ", NULL, &count)))
        {
            /* End of file */
            *vector = NULL;
            status = ATCA_SUCCESS;
            break;
        }

        if (ATCA_SUCCESS != (status = read_rsp_int_value(g_rsp_file, "Klen = ", NULL, &klen)))
        {
            break;
        }
        if (0 > klen)
        {
            status = ATCA_GEN_FAIL;
            break;
        }

        if (ATCA_SUCCESS != (status = read_rsp_int_value(g_rsp_file, "Tlen = ", NULL, &tlen)))
        {
            break;
        }
        if (0 > tlen)
        {
            status = ATCA_GEN_FAIL;
            break;
        }

        if (NULL != (v = malloc(sizeof(hmac_vector_info) + 128U + (size_t)klen + (size_t)tlen)))
        {
            v->meta.count = count;
            v->meta.klen = klen;
            v->meta.tlen = tlen;
            v->meta.mlen = 128U;
            v->meta.key = v->data;
            v->meta.mac = &v->data[klen];
            v->meta.msg = &v->data[klen + tlen];
        }
        else
        {
            status = ATCA_ALLOC_FAILURE;
            break;
        }

        if (ATCA_SUCCESS != (status = read_rsp_hex_value(g_rsp_file, "Key = ", v->meta.key, klen)))
        {
            break;
        }

        if (ATCA_SUCCESS != (status = read_rsp_hex_value(g_rsp_file, "Msg = ", v->meta.msg, 128U)))
        {
            break;
        }

        if (ATCA_SUCCESS == (status = read_rsp_hex_value(g_rsp_file, "Mac = ", v->meta.mac, tlen)))
        {
            *vector = v;
        }
    }
    while (false);

    if (ATCA_SUCCESS != status && NULL != v)
    {
        free(v);
    }

    return status;
}

ATCA_STATUS load_sha_vector(sha_vector ** vector, size_t digest_size)
{
    ATCA_STATUS status = ATCA_BAD_PARAM;
    sha_vector * v = NULL;

    do
    {
        int len_bits = 0;
        size_t len = 0;

        if (NULL == g_rsp_file || NULL == vector)
        {
            break;
        }

        if (ATCA_SUCCESS != (status = read_rsp_int_value(g_rsp_file, "Len = ", NULL, &len_bits)))
        {
            /* End of file */
            *vector = NULL;
            status = ATCA_SUCCESS;
            break;
        }
        if (0 > len_bits)
        {
            status = ATCA_GEN_FAIL;
            break;
        }
        else
        {
            len = (size_t)(len_bits == 0 ? 1 : len_bits / 8);
        }

        if (NULL != (v = malloc(sizeof(sha_vector_info) + digest_size + len)))
        {
            v->meta.len = len_bits / 8;
            v->meta.digest = v->data;
            v->meta.msg = &v->data[digest_size];
        }
        else
        {
            status = ATCA_ALLOC_FAILURE;
            break;
        }

        if (ATCA_SUCCESS != (status = read_rsp_hex_value(g_rsp_file, "Msg = ", v->meta.msg, len)))
        {
            break;
        }

        if (ATCA_SUCCESS == (status = read_rsp_hex_value(g_rsp_file, "MD = ", v->meta.digest, digest_size)))
        {
            *vector = v;
        }

    }
    while (false);

    if (ATCA_SUCCESS != status && NULL != v)
    {
        free(v);
    }

    return status;
}

ATCA_STATUS load_aes_gcm_vector(aes_gcm_vector ** vector)
{
    ATCA_STATUS status = ATCA_BAD_PARAM;
    aes_gcm_vector * v = NULL;

    do
    {
        int len_bits = 0;
        size_t len = 0;



    }
    while (false);


// [Keylen = 128]
// [IVlen = 96]
// [PTlen = 0]
// [AADlen = 128]
// [Taglen = 128]
    return status;
}

typedef struct
{
    /* Expected to be 0x03 or 0x10001*/
    int e;
    /* Maximum private key size */
    uint8_t n[4096 / 8];
} rsa_ctx;

ATCA_STATUS load_rsa_vector(rsa_vector ** vector, size_t mod, char * hash_alg)
{
    ATCA_STATUS status = ATCA_BAD_PARAM;
    rsa_vector * v = NULL;
    rsa_ctx * ctx = NULL;

    do
    {
        int len_bits = 0;
        size_t len = mod / 8;

        if (NULL == g_rsp_file || NULL == vector)
        {
            break;
        }

        if (NULL != g_rsp_ctx)
        {
            ctx = (rsa_ctx*)g_rsp_ctx;
        }
        else
        {
            /* Maximum private key size */
            if (NULL != (g_rsp_ctx = malloc(sizeof(rsa_ctx))))
            {
                memset(g_rsp_ctx, 0, sizeof(rsa_ctx));
            }
            else
            {
                status = ATCA_ALLOC_FAILURE;
                break;
            }
        }

        if (NULL != (v = malloc(sizeof(rsa_vector_info) + 128U + len)))
        {
            v->meta.mlen = 128U;
            v->meta.msg = v->data;
            v->meta.sig = &v->data[128];
        }
        else
        {
            status = ATCA_ALLOC_FAILURE;
            break;
        }

        if (0 == ctx->e)
        {
            if (ATCA_SUCCESS != (status = read_rsp_hex_value(g_rsp_file, "n = ", ctx->n, len)))
            {
                break;
            }

            if (ATCA_SUCCESS != (status = read_rsp_int_value(g_rsp_file, "e = ", NULL, &ctx->e)))
            {
                break;
            }
        }

        if (ATCA_SUCCESS != (status = read_rsp_match_value(g_rsp_file, "SHAAlg = ", hash_alg)))
        {
            break;
        }

        if (ATCA_SUCCESS != (status = read_rsp_hex_value(g_rsp_file, "Msg = ", v->meta.msg, len)))
        {
            break;
        }

        if (ATCA_SUCCESS == (status = read_rsp_hex_value(g_rsp_file, "S = ", v->meta.sig, len)))
        {
            *vector = v;
        }

    }
    while (false);

    if (ATCA_SUCCESS != status && NULL != v)
    {
        free(v);
    }

    return status;
}


#endif
