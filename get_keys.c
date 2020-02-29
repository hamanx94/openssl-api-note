#include <stdlib.h>
#include <stdio.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/err.h>

int generate_rsakey(int bits, EVP_PKEY *pkey)
{
    RSA *rsa = RSA_new();
    BIGNUM *bn = BN_new();
    int ret;

    BN_set_word(bn, RSA_F4);
    ret = RSA_generate_key_ex(rsa, bits, bn, NULL);
    if(ret != 1)
    {
        ret = ERR_get_error();
        goto __EXIT;
    }

    EVP_PKEY_assign_RSA(pkey, rsa);
    ret = 0;

__EXIT:
    if(bn)  BN_free(bn);
    return ret;
}

int store_rsakey(EVP_PKEY *pkey, char *filename)
{
    FILE *fp;
    int ret;

    fp = fopen(filename, "w");
    if(fp == NULL)
        return 1;

    ret = PEM_write_PrivateKey(fp, pkey, NULL, NULL, 0, NULL, NULL);
    if(ret != 1)
    {
        ret = ERR_get_error();
        goto __EXIT;
    }

    ret = 0;
__EXIT:
    if(fp) fclose(fp);
    return ret;
}

int get_MDE(EVP_PKEY *pkey, char **RSA_n, char **RSA_e, char **RSA_d)
{
    RSA *rsa;

    if(pkey == NULL)
        return 1;

    rsa = EVP_PKEY_get1_RSA(pkey);
    if(rsa == NULL)
        return ERR_get_error();

    *RSA_n = BN_bn2hex(rsa->n);
    *RSA_e = BN_bn2hex(rsa->e);
    *RSA_d = BN_bn2hex(rsa->d);

    RSA_free(rsa);

    return 0;
}

int read_rsakey_from_file(char *filename, EVP_PKEY **pkey)
{
    FILE *fp;

    fp = fopen(filename, "r");
    if(fp == NULL)
        return 1;

    *pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    if(*pkey == NULL)
        return ERR_get_error();

    return 0;
}
