/* Copyright (C) 2012-2013 Paul Ionkin <paul.ionkin@gmail.com>
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE.txt', which is part of this source code package.
 */
#include "hfs_encryption.h"

struct _HfsEncryption {
    Application *app;
    ConfData *conf;

    EVP_CIPHER_CTX e_ctx; 
    EVP_CIPHER_CTX d_ctx;
};

#define ENC_LOG "enc_dir"

#define BUFFER_SIZE 1024*1024

HfsEncryption *hfs_encryption_create (Application *app)
{
    HfsEncryption *enc;
    FILE *f;
    size_t bytes_read;
    unsigned char buf[BUFFER_SIZE];
    int i, nrounds = 5;
    unsigned char key[32], iv[32];
    unsigned char *key_data;
    size_t key_data_len;
    unsigned char *salt;
    unsigned int salt_ints[2];

    enc = g_new0 (HfsEncryption, 1);
    enc->app = app;
    enc->conf = application_get_conf (app);

    // try to load key file
    f = fopen (conf_get_string (enc->conf, "encryption.key_file"), "r");
    if (!f) {
        LOG_err (ENC_LOG, "Failed to open key file: %s", conf_get_string (enc->conf, "encryption.key_file"));
        return NULL;
    }

    key_data = NULL;
    key_data_len = 0;
    
    // load key from file
    while ((bytes_read = fread (buf, 1, BUFFER_SIZE, f)) > 0) {
        if (!key_data) {
            key_data = g_malloc0 (sizeof (unsigned char) * bytes_read);
        } else {
             key_data = g_realloc (key_data, sizeof (unsigned char) * (bytes_read + key_data_len));
        }

        if (!key_data) {
            LOG_err (ENC_LOG, "Memory allocation failed !");
            return NULL;
        }
        
        memcpy (key + key_data_len, buf, bytes_read);
        key_data_len += bytes_read;
    }

    fclose (f);

    LOG_debug (ENC_LOG, "Loaded key, size: %zu", key_data_len);

    salt_ints[0] = ENC_SALT_1;
    salt_ints[1] = ENC_SALT_2;
    salt = (unsigned char *)&salt_ints;

    i = EVP_BytesToKey (EVP_aes_256_cbc (), EVP_sha1 (), salt, key_data, key_data_len, nrounds, key, iv);
    if (i != 32) {
        LOG_err (ENC_LOG, "Key size is %d bits - should be 256 bits\n", i);
        return NULL;
    }
    
    EVP_CIPHER_CTX_init (&enc->e_ctx);
    EVP_EncryptInit_ex (&enc->e_ctx, EVP_aes_256_cbc (), NULL, key, iv);
    EVP_CIPHER_CTX_init (&enc->d_ctx);
    EVP_DecryptInit_ex (&enc->d_ctx, EVP_aes_256_cbc (), NULL, key, iv);

    g_free (key_data);

    return enc;
}

void hfs_encryption_destroy (HfsEncryption *enc)
{
    EVP_CIPHER_CTX_cleanup (&enc->e_ctx);
    EVP_CIPHER_CTX_cleanup (&enc->d_ctx);
    g_free (enc);
}

unsigned char *hfs_encryption_encrypt (HfsEncryption *enc, unsigned char *buf, int *len)
{
    int c_len = *len + AES_BLOCK_SIZE, f_len = 0;
    unsigned char *out;
    
    out = g_malloc0 (c_len);

    EVP_EncryptInit_ex (&enc->e_ctx, NULL, NULL, NULL, NULL);
    EVP_EncryptUpdate (&enc->e_ctx, out, &c_len, buf, *len);
    EVP_EncryptFinal_ex (&enc->e_ctx, out + c_len, &f_len);

    *len = c_len + f_len;
    
    LOG_debug (ENC_LOG, "Encrypted %d bytes", *len);
    
    return out;
}

unsigned char *hfs_encryption_decrypt (HfsEncryption *enc, unsigned char *buf, int *len)
{
    int p_len = *len, f_len = 0;
    unsigned char *out;
    
    out = g_malloc0 (p_len + AES_BLOCK_SIZE);

    EVP_DecryptInit_ex (&enc->d_ctx, NULL, NULL, NULL, NULL);
    EVP_DecryptUpdate (&enc->d_ctx, out, &p_len, buf, *len);
    EVP_DecryptFinal_ex (&enc->d_ctx, out + p_len, &f_len);

    *len = p_len + f_len;

    LOG_debug (ENC_LOG, "Decrypted %d bytes", *len);

    return out;
}
