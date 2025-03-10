#include "encryption.h"
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <string.h>

void deriveKey(const char *password, unsigned char *salt, unsigned char *key, unsigned int key_len) {
    PKCS5_PBKDF2_HMAC(password, strlen(password), salt, strlen((char *)salt), 10000, EVP_sha256(), key_len, key);
}

void addPadding(unsigned char *data, int data_len, int block_size) {
    int padding_len = block_size - (data_len % block_size);
    for (int i = 0; i < padding_len; i++) {
        data[data_len + i] = padding_len;
    }
}

void removePadding(unsigned char *data, int *data_len) {
    int padding_len = data[*data_len - 1];
    *data_len -= padding_len;
}

int encryptAES(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv,
               unsigned char *ciphertext) {
    int ciphertext_len;
    int len;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    addPadding(plaintext, plaintext_len, EVP_CIPHER_CTX_block_size(ctx));

    if (!EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len + EVP_CIPHER_CTX_block_size(ctx))) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len = len;

    if (!EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

int decryptAES(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv,
               unsigned char *plaintext) {
    int plaintext_len;
    int len;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len = len;

    if (!EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len += len;

    removePadding(plaintext, &plaintext_len);

    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

void base64Encode(const unsigned char *input, int length, char *output) {
    BIO *bmem = BIO_new(BIO_s_mem());
    BIO *b64 = BIO_new(BIO_f_base64());
    b64 = BIO_push(b64, bmem);
    BIO_write(b64, input, length);
    BIO_flush(b64);
    BUF_MEM *bptr;
    BIO_get_mem_ptr(b64, &bptr);
    memcpy(output, bptr->data, bptr->length);
    output[bptr->length] = '\0';
    BIO_free_all(b64);
}

int base64Decode(const char *input, unsigned char *output) {
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *bmem = BIO_new_mem_buf(input, strlen(input));
    bmem = BIO_push(b64, bmem);
    int length = BIO_read(bmem, output, strlen(input));
    BIO_free_all(bmem);
    return length;
}
