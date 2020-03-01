#include <openssl/ssl.h>

#define d_CSR_VERSION                       NID_pkcs
#define d_CSR_COUNTRY                       ""
#define d_CSR_STATE                         ""
#define d_CSR_LOCALITY                      ""
#define d_CSR_ORGANISATION                  ""
#define d_CSR_ORGANISATIONAL_UNIT           ""
#define d_CSR_EMAIL_ADDRESS                 ""

#define d_CRT_VERSION                       NID_pkcs

int generate_csr(EVP_PKEY *pkey, char *common, char *csr, int *csr_len)
{
    int rc = -1;
    X509_REQ *req = NULL;
    X509_NAME *name = NULL;
    BIO *bio = NULL;
    char *p = NULL;

    do
    {
        req = X509_REQ_new();
        if(!req)
        {
            break;
        }

        if(X509_REQ_set_version(req, d_CSR_VERSION) != 1)
        {
            break;
        }

        name = X509_REQ_get_subject_name(req);

        if(X509_NAME_add_entry_by_txt(name, "C",  MBSTRING_ASC, (unsigned char *)d_CSR_COUNTRY, -1, -1, 0) != 1)
        {
            break;
        }

        if(X509_NAME_add_entry_by_txt(name, "ST",  MBSTRING_ASC, (unsigned char *)d_CSR_STATE, -1, -1, 0) != 1)
        {
            break;
        }

        if(X509_NAME_add_entry_by_txt(name, "L",  MBSTRING_ASC, (unsigned char *)d_CSR_LOCALITY, -1, -1, 0) != 1)
        {
            break;
        }

        if(X509_NAME_add_entry_by_txt(name, "O",  MBSTRING_ASC, (unsigned char *)d_CSR_ORGANISATION, -1, -1, 0) != 1)
        {
            break;
        }

        if(X509_NAME_add_entry_by_txt(name, "OU",  MBSTRING_ASC, (unsigned char *)d_CSR_ORGANISATIONAL_UNIT, -1, -1, 0) != 1)
        {
            break;
        }

        if(X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)common, -1, -1, 0) != 1)
        {
            break;
        }

        if(X509_NAME_add_entry_by_txt(name, "emailAddress", MBSTRING_ASC, (unsigned char *)d_CSR_EMAIL_ADDRESS, -1, -1, 0) != 1)
        {
            break;
        }

        if(X509_REQ_set_pubkey(req, pkey) != 1)
        {
            break;
        }

        if(X509_REQ_sign(req, pkey, EVP_sha256()) <= 0)
        {
            break;
        }

        bio = BIO_new(BIO_s_mem());
        if(!bio)
        {
            break;
        }

        if(PEM_write_bio_X509_REQ(bio, req) != 1)
        {
            break;
        }

        *csr_len = (int) BIO_get_mem_data(bio, &p);
        memcpy(csr, p, *csr_len);

        rc = 0;

    }while(0);

    if(req) X509_REQ_free(req);
    if(bio) BIO_free_all(bio);

    return rc;
}

int sign_csr(X509_REQ *csr, X509 *crt, EVP_PKEY *pkey, int days, char *sign, int *sign_len)
{
    int rc = -1;
    X509 *sign_crt = NULL;
    X509_NAME *name_csr = NULL;
    X509_NAME *name_crt = NULL;
    EVP_PKEY *csr_pkey = NULL;
    BIO *bio = NULL;
    char *p = NULL;

    do
    {

        name_csr = X509_REQ_get_subject_name(csr);
        name_crt = X509_get_subject_name(crt);

        sign_crt = X509_new();
        if(!sign_crt)
        {
            break;
        }

        if(X509_set_subject_name(sign_crt, name_csr) != 1)
        {
            break;
        }

        if(X509_set_issuer_name(sign_crt, name_crt) != 1)
        {
            break;
        }

        if(ASN1_INTEGER_set(X509_get_serialNumber(sign_crt), d_CRT_VERSION) != 1)
        {
            break;
        }

        if(!X509_gmtime_adj(X509_get_notBefore(sign_crt), 0))
        {
            break;
        }

        if(!X509_gmtime_adj(X509_get_notAfter(sign_crt), (days * 60 * 60 * 24)))
        {
            break;
        }

        csr_pkey = X509_REQ_get_pubkey(csr);
        if(!csr_pkey || X509_set_pubkey(sign_crt, csr_pkey) != 1)
        {
            break;
        }

        if(X509_sign(sign_crt, pkey, EVP_sha256()) <= 0)
        {
            break;
        }

        bio = BIO_new(BIO_s_mem());
        if(!bio)
        {
            break;
        }

        if(PEM_write_bio_X509(bio, sign_crt) != 1)
        {
            break;
        }

        *sign_len = (int) BIO_get_mem_data(bio, &p);
        memcpy(sign, p, *sign_len);

        rc = 0;

    }while(0);

    if(sign_crt) X509_free(sign_crt);
    if(bio) BIO_free_all(bio);

    return rc;
}

int gen_selfsigned_crt(char *common, int days, EVP_PKEY *pkey, char *selfsigned, int *selfsigned_len)
{
    X509 *x509 = NULL;
    X509_NAME *name = NULL;
    int rc = -1;
    BIO *bio = NULL;
    char *p = NULL;
    do
    {
        x509 = X509_new();

        if(X509_set_version(x509, d_CSR_VERSION) != 1)
        {
            break;
        }

        name = X509_NAME_new();

        if(X509_NAME_add_entry_by_txt(name, "C",  MBSTRING_ASC, (unsigned char *)d_CSR_COUNTRY, -1, -1, 0) != 1)
        {
            break;
        }

        if(X509_NAME_add_entry_by_txt(name, "ST",  MBSTRING_ASC, (unsigned char *)d_CSR_STATE, -1, -1, 0) != 1)
        {
            break;
        }

        if(X509_NAME_add_entry_by_txt(name, "L",  MBSTRING_ASC, (unsigned char *)d_CSR_LOCALITY, -1, -1, 0) != 1)
        {
            break;
        }

        if(X509_NAME_add_entry_by_txt(name, "O",  MBSTRING_ASC, (unsigned char *)d_CSR_ORGANISATION, -1, -1, 0) != 1)
        {
            break;
        }

        if(X509_NAME_add_entry_by_txt(name, "OU",  MBSTRING_ASC, (unsigned char *)d_CSR_ORGANISATIONAL_UNIT, -1, -1, 0) != 1)
        {
            break;
        }

        if(X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)common, -1, -1, 0) != 1)
        {
            break;
        }

        if(X509_NAME_add_entry_by_txt(name, "emailAddress", MBSTRING_ASC, (unsigned char *)d_CSR_EMAIL_ADDRESS, -1, -1, 0) != 1)
        {
            break;
        }

        if(!X509_set_issuer_name(x509, name))
        {
            break;
        }

        if(! X509_set_subject_name(x509, name))
        {
            break;
        }

        if(!(X509_gmtime_adj(X509_get_notBefore(x509), 0)))
        {
            break;
        }

        if(!(X509_gmtime_adj(X509_get_notAfter(x509), days * 24 * 60 * 60)))
        {
            break;
        }

        if(X509_set_pubkey(x509, pkey) != 1)
        {
            break;
        }

        if(X509_sign(x509, pkey, EVP_sha256()) <= 0)
        {
            break;
        }

        bio = BIO_new(BIO_s_mem());
        if(!bio)
        {
            break;
        }

        if(PEM_write_bio_X509(bio, x509) != 1)
        {
            break;
        }

        *selfsigned_len = (int) BIO_get_mem_data(bio, &p);
        memcpy(selfsigned, p, *selfsigned_len);

        rc = 0;
    } while(0);

    if(bio) BIO_free(bio);
    if(x509) X509_free(x509);
    if(name) X509_NAME_free(name);

    return rc;
}
