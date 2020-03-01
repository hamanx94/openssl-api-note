/* verify certificate by OpenSSL library */
#include <openssl/ssl.h>
#include <openssl/rsa.h>

/* using X509_verify_cert */
int verify_certificate(char *cert_name, char *root_name)
{
    X509_STORE *store = X509_STORE_new();
    X509_STORE_CTX *store_ctx = X509_STORE_CTX_new();
    X509 *x509Cert = NULL, *x509CA = NULL;
    char baMsg[256];
    int ret = 0xFF;
    int ok = 0;
    FILE *fpCert = NULL;
    FILE *fpRoot = NULL;
    
    OpenSSL_add_all_digests();
    
    fpCert = fopen(cert_name, "r");
    
    fpRoot = fopen(root_name, "r");

    do
    {
        x509Cert = PEM_read_X509(fpCert, NULL, NULL, NULL);
        if(x509Cert == NULL)
        {
            sprintf((char *)baMsg, "PEM_read_X509:%s error", cert_name);
            ret = 0x02;
            break;
        }

        STACK_OF(X509) *trusted_chain;
        trusted_chain = sk_X509_new_null();

        x509CA = PEM_read_X509(fpRoot, NULL, NULL, NULL);
        sk_X509_push(trusted_chain, x509CA);
        X509_STORE_CTX_init(store_ctx, store, x509Cert, NULL);
        X509_STORE_CTX_trusted_stack(store_ctx, trusted_chain);
        
        ok = X509_verify_cert(store_ctx);
        if(ok != 1)
        {
            sprintf((char *)baMsg, "Verify %s error, %s", cert_name, X509_verify_cert_error_string(store_ctx->error));
            ret = 0x04;
            break;
        }

        ret = 0x00;
    } while(0);

    if(fpRoot) fclose(fpRoot);
    if(fpCert) fclose(fpCert);

    X509_STORE_CTX_cleanup(store_ctx);
    X509_STORE_CTX_free(store_ctx);
    X509_STORE_free(store);

    return ret;
}

/* using X509_verify */
int verify_certificate(char *cert_name, char *root_name)
{
    int rc = -1;
    int result;
    FILE *fpCert = NULL, *fpRoot = NULL;
    EVP_PKEY *RootPK = NULL;
    X509 *x509Cert = NULL;
    X509 *x509Root = NULL;

    OpenSSL_add_all_digests();

    do
    {
        fpRoot = fopen(root_name, "rb");
        if(fpRoot == NULL)
        {
            rc = -1;
            break;
        }
        
        fpCert = fopen(cert_name, "rb");
        if(fpCert == NULL)
        {
            rc = -2;
            break;
        }

        x509Root = PEM_read_X509(fpRoot, NULL, NULL, NULL);
        if(x509Root == NULL)
        {
            rc = -4;
            break;
        }
        
        RootPK = X509_get_pubkey(x509Root);
        if(RootPK == NULL)
        {
            rc = -5;
            break;
        }

        x509Cert = PEM_read_X509(fpCert, NULL, NULL, NULL);
        if(x509Cert == NULL)
        {
            rc = -8;
            break;
        }

        result = X509_verify(x509Cert, RootPK);
        if(result != 1)
        {
            rc = -9;
            break;
        }
        else
        {
            rc = 0;
            break;
        }
    }while(0);

    if(fpRoot) fclose(fpRoot);
    if(fpCert) fclose(fpCert);
    if(x509Root) X509_free(x509Root);
    if(x509Cert) X509_free(x509Cert);
    if(RootPK) EVP_PKEY_free(RootPK);
    
    return rc;
}
