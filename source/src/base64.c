#include "base64.h"  
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

int base64_encode(char *in_str, int in_len, char *out_str)
{
    BIO *b64, *bio;
    BUF_MEM *bptr = NULL;
    size_t size = 0;

    if (in_str == NULL || out_str == NULL)
        return -1;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_write(bio, in_str, in_len);
    BIO_flush(bio);

    BIO_get_mem_ptr(bio, &bptr);
    memcpy(out_str, bptr->data, bptr->length);
    out_str[bptr->length] = '\0';
    size = bptr->length;

    BIO_free_all(bio);
    return size;
}

int base64_decode(char *in_str, char *out_str)
{
    BIO *b64, *bio;
    int size = 0;

    if (in_str == NULL || out_str == NULL)
        return -1;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_mem_buf(in_str, -1);
    bio = BIO_push(b64, bio);

	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    size = BIO_read(bio, out_str, strlen(in_str));
    out_str[size] = '\0';

    BIO_free_all(bio);
    return size;
}

