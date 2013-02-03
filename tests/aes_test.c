#include "global.h"

int aes_init(unsigned char *key_data, int key_data_len, unsigned char *salt, EVP_CIPHER_CTX *e_ctx, 
             EVP_CIPHER_CTX *d_ctx)
{
  int i, nrounds = 5;
  unsigned char key[32], iv[32];
  
  i = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), salt, key_data, key_data_len, nrounds, key, iv);
  if (i != 32) {
    printf("Key size is %d bits - should be 256 bits\n", i);
    return -1;
  }

  EVP_CIPHER_CTX_init(e_ctx);
  EVP_EncryptInit_ex(e_ctx, EVP_aes_256_cbc(), NULL, key, iv);
  EVP_CIPHER_CTX_init(d_ctx);
  EVP_DecryptInit_ex(d_ctx, EVP_aes_256_cbc(), NULL, key, iv);

  return 0;
}

unsigned char *aes_encrypt(EVP_CIPHER_CTX *e, unsigned char *plaintext, int *len)
{
  int c_len = *len + AES_BLOCK_SIZE, f_len = 0;
  unsigned char *ciphertext = malloc(c_len);

  EVP_EncryptInit_ex(e, NULL, NULL, NULL, NULL);

  EVP_EncryptUpdate(e, ciphertext, &c_len, plaintext, *len);

  EVP_EncryptFinal_ex(e, ciphertext+c_len, &f_len);

  *len = c_len + f_len;
  return ciphertext;
}

unsigned char *aes_decrypt(EVP_CIPHER_CTX *e, unsigned char *ciphertext, int *len)
{
  int p_len = *len, f_len = 0;
  unsigned char *plaintext = malloc(p_len + AES_BLOCK_SIZE);
  
  EVP_DecryptInit_ex(e, NULL, NULL, NULL, NULL);
  EVP_DecryptUpdate(e, plaintext, &p_len, ciphertext, *len);
  EVP_DecryptFinal_ex(e, plaintext+p_len, &f_len);

  *len = p_len + f_len;
  return plaintext;
}

// 14k
#define BUFFER_SIZE 1024*104*14

int main(int argc, char **argv)
{
  EVP_CIPHER_CTX en, de;
  FILE *fin, *fout;

  unsigned int salt[2];
  unsigned char *key_data;
  int key_data_len, i;
    size_t written;
    int bytes_read;
    int len;
    unsigned char buf[BUFFER_SIZE];


  if (argc < 2) {
      printf ("%s key path_to_file\n", argv[0]);
      exit (1);
  }
  salt[0] = g_random_int ();
  salt[1] = g_random_int ();

  fin = fopen (argv[2], "r");
  g_assert (fin);
  fout = fopen ("file.out", "w");
  g_assert (fout);

  key_data = (unsigned char *)argv[1];
  key_data_len = strlen(argv[1]);
  
  if (aes_init(key_data, key_data_len, (unsigned char *)&salt, &en, &de)) {
    printf("Couldn't initialize AES cipher\n");
    return -1;
  }

    while ((bytes_read = fread (buf, 1, BUFFER_SIZE, fin)) > 0) {
        char *plaintext;
        unsigned char *ciphertext;
        
        ciphertext = aes_encrypt (&en, buf, &bytes_read);
        plaintext = (char *)aes_decrypt (&de, ciphertext, &bytes_read);

        written = fwrite (plaintext, 1, bytes_read, fout);
        free(ciphertext);
        free(plaintext);
  }

    fclose (fin);
    fclose (fout);

  EVP_CIPHER_CTX_cleanup(&en);
  EVP_CIPHER_CTX_cleanup(&de);

  return 0;
}
  
