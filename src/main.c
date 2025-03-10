#include <stdio.h>
#include <string.h>
#include "password_manager.h"
#include "encryption.h"

void displayMenu() {
    printf("\nPassword Manager\n");
    printf("1. Add Password\n");
    printf("2. Delete Password\n");
    printf("3. Get Password\n");
    printf("4. List All Passwords\n");
    printf("5. Save Passwords to File\n");
    printf("6. Load Passwords from File\n");
    printf("7. Exit\n");
    printf("Choose an option: ");
}

int main() {
    int choice;
    Password pwd;
    unsigned char key[32];
    unsigned char iv[16];
    unsigned char salt[] = "sp4r1ng";
    const char *masterPassword = "yzLIP4oJiGzhZHWr";
    unsigned char ciphertext[128];
    unsigned char decryptedtext[128];

    deriveKey(masterPassword, salt, key, sizeof(key));

    memset(iv, 0x00, sizeof(iv));

    do {
        displayMenu();
        scanf("%d", &choice);

        switch (choice) {
            case 1:
                printf("Enter site: ");
                scanf("%s", pwd.site);
                printf("Enter username: ");
                scanf("%s", pwd.username);
                printf("Enter password: ");
                scanf("%s", pwd.password);

                int plaintext_len = strlen((char *)pwd.password);
                int ciphertext_len = encryptAES(pwd.password, plaintext_len, key, iv, ciphertext);
                memcpy(pwd.password, ciphertext, ciphertext_len);
                addPassword(&pwd);
                break;
            case 2:
                printf("Enter site to delete: ");
                scanf("%s", pwd.site);
                deletePassword(pwd.site);
                break;
            case 3:
                printf("Enter site to retrieve: ");
                scanf("%s", pwd.site);
                Password *retrieved = getPassword(pwd.site);
                if (retrieved) {
                    int decrypted_len = decryptAES(retrieved->password, sizeof(retrieved->password), key, iv, decryptedtext);
                    decryptedtext[decrypted_len] = '\0'; // Null-terminate the string
                    printf("Username: %s, Password: %s\n", retrieved->username, decryptedtext);
                } else {
                    printf("No password found for site: %s\n", pwd.site);
                }
                break;
            case 4:
                listAllPasswords();
                break;
            case 5:
                savePasswordsToFile("passwords.bin");
                break;
            case 6:
                loadPasswordsFromFile("passwords.bin");
                break;
            case 7:
                printf("Exiting...\n");
                break;
            default:
                printf("Invalid choice. Please try again.\n");
        }
    } while (choice != 7);

    return 0;
}
