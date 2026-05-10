#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <stdint.h>

/**
 * Real AES-256-GCM Encryption
 * Returns 1 on success, 0 on failure.
 */
int encrypt_aes_gcm(const uint8_t *plaintext, int plaintext_len, 
                    const uint8_t *key, const uint8_t *iv, 
                    uint8_t *ciphertext, uint8_t *tag) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    if(!(ctx = EVP_CIPHER_CTX_new())) return 0;

    // Initialize encryption with AES-256-GCM
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) goto err;

    // Set IV length (standard 12 bytes for GCM)
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL)) goto err;

    // Initialize key and IV
    if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) goto err;

    // Provide the message to be encrypted
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) goto err;
    ciphertext_len = len;

    // Finalize encryption
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) goto err;
    ciphertext_len += len;

    // Get the authentication tag
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag)) goto err;

    EVP_CIPHER_CTX_free(ctx);
    return 1;

err:
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

/**
 * Real AES-256-GCM Decryption
 * Returns 1 on success (authenticated), 0 on failure/tampering.
 */
int decrypt_aes_gcm(const uint8_t *ciphertext, int ciphertext_len, 
                    const uint8_t *key, const uint8_t *iv, 
                    const uint8_t *tag, uint8_t *plaintext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    int ret;

    if(!(ctx = EVP_CIPHER_CTX_new())) return 0;

    // Initialize decryption with AES-256-GCM
    if(!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) goto err;

    // Set IV length
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL)) goto err;

    // Initialize key and IV
    if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) goto err;

    // Provide the message to be decrypted
    if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) goto err;
    plaintext_len = len;

    // Set expected tag value for authentication
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)tag)) goto err;

    // Finalize decryption. A return value > 0 means the tag matched (success).
    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

    EVP_CIPHER_CTX_free(ctx);
    return (ret > 0) ? 1 : 0;

err:
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}