#ifndef CRYPTO_ENGINE_H
#define CRYPTO_ENGINE_H

void generate_rsa_key();
void encrypt_aes(const unsigned char *input, unsigned char *output, const unsigned char *key, const unsigned char *iv);
void decrypt_aes(const unsigned char *input, unsigned char *output, const unsigned char *key, const unsigned char *iv);
void generate_sha256(const unsigned char *input, unsigned char *output);
void create_signature(const unsigned char *input, unsigned char *output);

#endif // CRYPTO_ENGINE_H
