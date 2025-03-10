#include "password_manager.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

Password passwords[100];
int count = 0;

void addPassword(const Password *pwd) {
    if (count < 100) {
        passwords[count++] = *pwd;
        printf("Password added successfully.\n");
    } else {
        printf("Password storage is full.\n");
    }
}

void deletePassword(const char *site) {
    for (int i = 0; i < count; i++) {
        if (strcmp(passwords[i].site, site) == 0) {
            for (int j = i; j < count - 1; j++) {
                passwords[j] = passwords[j + 1];
            }
            count--;
            printf("Password deleted successfully.\n");
            return;
        }
    }
    printf("No password found for site: %s\n", site);
}

Password* getPassword(const char *site) {
    for (int i = 0; i < count; i++) {
        if (strcmp(passwords[i].site, site) == 0) {
            return &passwords[i];
        }
    }
    return NULL;
}

void listAllPasswords() {
    for (int i = 0; i < count; i++) {
        printf("Site: %s, Username: %s\n", passwords[i].site, passwords[i].username);
    }
}

void savePasswordsToFile(const char *filename) {
    FILE *file = fopen(filename, "wb");
    if (!file) {
        perror("Failed to open file");
        return;
    }
    fwrite(&count, sizeof(int), 1, file);
    fwrite(passwords, sizeof(Password), count, file);
    fclose(file);
    printf("Passwords saved to file.\n");
}

void loadPasswordsFromFile(const char *filename) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("Failed to open file");
        return;
    }
    fread(&count, sizeof(int), 1, file);
    fread(passwords, sizeof(Password), count, file);
    fclose(file);
    printf("Passwords loaded from file.\n");
}
