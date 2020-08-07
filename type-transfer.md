# PEM to DER

i2d_X509_REQ, X509_REQ *x
```c
    int rc;
    unsigned char *buf;
    
    buf = NULL;
    rc = i2d_X509_REQ(x, &buf);
    if(rc <= 0)
        return;
```

i2d_X509, X509 *x 
```c
    int rc;
    unsigned char *buf;
    
    buf = NULL;
    rc = i2d_X509(x, &buf);
    if(rc <= 0)
        return;
```

i2d_RSAPrivateKey, RSA *r
```c
    int rc;
    unsigned char *buf;

    buf = NULL;
    rc = i2d_RSAPrivateKey(r, &buf);
    if(rc <= 0)
        return;
```
i2d_RSAPublicKey, RSA *r
```c
    int rc;
    unsigned char *buf;

    buf = NULL;
    rc = i2d_RSAPublicKey(r, &buf);
    if(rc <= 0)
        return;
```

# DER to PEM

d2i_X509_REQ
```c
    X509_REQ *x509;
    const unsigned char *pp = DER_BUF;
    x509 = d2i_X509_REQ(NULL, &pp, DER_LEN);
    if(x509 == NULL)
        return;
```

d2i_X509
```c
    X509 *x509;
    const unsigned char *pp = DER_BUF;
    x509 = d2i_X509(NULL, &pp, DER_LEN);
    if(x509 == NULL)
        return;
```

d2i_RSAPublicKey
```c
    RSA *r = NULL;
    const unsigned char *p;
    
    p = DER_BUF;
    r = d2i_RSAPublicKey(NULL, &p, DER_LEN);
    if(r == NULL)
        return;
```

# Certificate Info

X509_print_ex, X509 *x509ca
```c
    BIO *out = BIO_new(BIO_s_mem());
    char *p = NULL;
    int ret, length; 
    
    ret = X509_print_ex(out, x509ca, XN_FLAG_COMPAT, X509_FLAG_COMPAT);
    if(ret == 1)
    {
        length = (int) BIO_get_mem_data(out, &p);
        // p is the certificate info
    }
    BIO_free(out);
```
