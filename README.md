# openssl-api-note
> Job accumulation...

## aes.md

    aes ecb and cbc

## gen_crt.c
+ generate_csr  
```cpp
    int generate_csr(EVP_PKEY *pkey, char *common, char *csr, int *csr_len)
```
+ sign_csr  
```cpp
    int sign_csr(X509_REQ *csr, X509 *crt, EVP_PKEY *pkey, int days, char *sign, int *sign_len)
```
+ gen_selfsigned_crt  
```cpp
    int gen_selfsigned_crt(char *common, int days, EVP_PKEY *pkey, char *selfsigned, int *selfsigned_len)
```
  
## get_keys.c  
+ generate_rsakey  
```cpp
    int generate_rsakey(int bits, EVP_PKEY *pkey)
```
+ store_rsakey  
```cpp
    int store_rsakey(EVP_PKEY *pkey, char *filename)
```
+ get_MDE  
```cpp
    int get_MDE(EVP_PKEY *pkey, char **RSA_n, char **RSA_e, char **RSA_d)
```
+ read_rsakey_from_file  
```cpp
    int read_rsakey_from_file(char *filename, EVP_PKEY **pkey)
```

## verify_cert.c  
+ verify_certificate
```cpp
    /* using X509_verify_cert  */
    int verify_certificate(char *cert_name, char *root_name)
    
    /* using X509_verify */
    int verify_certificate(char *cert_name, char *root_name)
```
