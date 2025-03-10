#ifndef PASSWORD_MANAGER_H
#define PASSWORD_MANAGER_H

typedef struct {
    char site[50];
    char username[50];
    unsigned char password[64];
} Password;

void addPassword(const Password *pwd);
void deletePassword(const char *site);
Password* getPassword(const char *site);
void listAllPasswords();
void savePasswordsToFile(const char *filename);
void loadPasswordsFromFile(const char *filename);

#endif // PASSWORD_MANAGER_H