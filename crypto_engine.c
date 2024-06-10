#include "crypto_engine.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mbedtls/rsa.h>
#include <mbedtls/pk.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/aes.h>
#include <mbedtls/sha256.h>
#include <mbedtls/md.h>

void generate_rsa_key() {
    mbedtls_pk_context key;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "rsa_genkey";

    mbedtls_pk_init(&key);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);

    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *) pers, strlen(pers));

    mbedtls_pk_setup(&key, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
    mbedtls_rsa_gen_key(mbedtls_pk_rsa(key), mbedtls_ctr_drbg_random, &ctr_drbg, 2048, 65537);

    unsigned char buf[512];
size_t olen = 0;

FILE *f = fopen("private_key.pem", "wb");
mbedtls_pk_write_key_pem(&key, buf, sizeof(buf));
fwrite(buf, 1, olen, f);
fclose(f);

f = fopen("public_key.pem", "wb");
mbedtls_pk_write_pubkey_pem(&key, buf, sizeof(buf));
fwrite(buf, 1, olen, f);
fclose(f);

    mbedtls_pk_free(&key);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
}

void encrypt_aes(const unsigned char *input, unsigned char *output, const unsigned char *key, const unsigned char *iv) {
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_enc(&aes, key, 128);
    mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, 16, (unsigned char *)iv, input, output);
    mbedtls_aes_free(&aes);
}

void decrypt_aes(const unsigned char *input, unsigned char *output, const unsigned char *key, const unsigned char *iv) {
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_dec(&aes, key, 128);
    mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, 16, (unsigned char *)iv, input, output);
    mbedtls_aes_free(&aes);
}


void generate_sha256(const unsigned char *input, unsigned char *output) {
    mbedtls_sha256_context sha256;
    mbedtls_sha256_init(&sha256);
    mbedtls_sha256_starts(&sha256, 0);
    mbedtls_sha256_update(&sha256, input, strlen((char *) input));
    mbedtls_sha256_finish(&sha256, output);
    mbedtls_sha256_free(&sha256);
}

void create_signature(const unsigned char *input, unsigned char *output) {
    mbedtls_md_context_t md_ctx;
    mbedtls_md_init(&md_ctx);
    mbedtls_md_setup(&md_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
    mbedtls_md_starts(&md_ctx);
    mbedtls_md_update(&md_ctx, input, strlen((char *) input));
    mbedtls_md_finish(&md_ctx, output);
    mbedtls_md_free(&md_ctx);
}
