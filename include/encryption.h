#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <openssl/evp.h>

void deriveKey(const char *password, unsigned char *salt, unsigned char *key, unsigned int key_len);
int encryptAES(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv,
               unsigned char *ciphertext);
int decryptAES(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv,
               unsigned char *plaintext);

void base64Encode(const unsigned char *input, int length, char *output);
int base64Decode(const char *input, unsigned char *output);

#endif // ENCRYPTION_H
