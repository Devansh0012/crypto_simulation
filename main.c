#include <stdio.h>
#include <stdlib.h>
#include "crypto_engine.h"

void print_menu() {
    printf("Cryptography Simulation\n");
    printf("1. Key Generation\n");
    printf("2. Encryption\n");
    printf("3. Decryption\n");
    printf("4. Hashing\n");
    printf("5. Digital Signature\n");
    printf("6. Exit\n");
}

int main() {
    int choice;
    unsigned char input[128], output[128], key[32], iv[16];

    while (1) {
        print_menu();
        printf("Enter your choice: ");
        scanf("%d", &choice);

        switch (choice) {
            case 1:
                generate_rsa_key();
                printf("RSA Key Pair Generated.\n");
                break;
            case 2:
                printf("Enter text to encrypt: ");
                scanf("%s", input);
                printf("Enter key: ");
                scanf("%s", key);
                printf("Enter IV: ");
                scanf("%s", iv);
                encrypt_aes(input, output, key, iv);
                printf("Encrypted text: %s\n", output);
                break;
            case 3:
                printf("Enter text to decrypt: ");
                scanf("%s", input);
                printf("Enter key: ");
                scanf("%s", key);
                printf("Enter IV: ");
                scanf("%s", iv);
                decrypt_aes(input, output, key, iv);
                printf("Decrypted text: %s\n", output);
                break;
            case 4:
                printf("Enter text to hash: ");
                scanf("%s", input);
                generate_sha256(input, output);
                printf("SHA-256 Hash: %s\n", output);
                break;
            case 5:
                printf("Enter text to sign: ");
                scanf("%s", input);
                create_signature(input, output);
                printf("Digital Signature: %s\n", output);
                break;
            case 6:
                exit(0);
            default:
                printf("Invalid choice. Please try again.\n");
        }
    }
    return 0;
}
