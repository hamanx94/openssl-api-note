```cpp
#include "openssl/aes.h"
/*
* cipherMode: 
*             #define 	AES_ENCRYPT   1 
*             #define 	AES_DECRYPT   0
*/
int aes_cbc_cipher(int cipherMode, 
                   unsigned char *key, 
                   int keyLen, 
                   unsigned char *iv, 
                   unsigned char *in, 
                   int len, 
                   unsigned char *out)
{
    int rc;
    AES_KEY aes;

    if(cipherMode == AES_ENCRYPT)
        rc = AES_set_encrypt_key(key, (keyLen * 8), &aes);
    else
        rc = AES_set_decrypt_key(key, (keyLen * 8), &aes);
        
    if(rc < 0)
        return 1;
        
    AES_cbc_encrypt((const unsigned char*)in, (unsigned char *)out, len, &aes, iv, cipherMode);
    return 0;
}

int aes_ecb_cipher(int cipherMode, 
                   unsigned char *key, 
                   int keyLen,
                   unsigned char *in, 
                   int len, 
                   unsigned char *out)
{
    int rc, i;
    AES_KEY aes;
    
    if((len % AES_BLOCK_SIZE) > 0)
        return 1;

    if(cipherMode == AES_ENCRYPT)
        rc = AES_set_encrypt_key(key, (keyLen * 8), &aes);
    else
        rc = AES_set_decrypt_key(key, (keyLen * 8), &aes);
        
    if(rc < 0)
        return 1;
        
    for(i = 0 ; i < keyLen ; i += AES_BLOCK_SIZE)          
        AES_ecb_encrypt((const unsigned char*)&in[i], (unsigned char *)&out[i], &aes, cipherMode);
        
    return 0;
}

```
