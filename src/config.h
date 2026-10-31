#ifndef VERGEAUTH_CONFIG_H
#define VERGEAUTH_CONFIG_H

#include <stddef.h>

struct user {
    char name[256];
    char password[256];
};

struct config {
    unsigned short listen_port;
    char upstream_host[256];
    unsigned short upstream_port;
    struct user *users;
    size_t user_count;
};

int config_load(const char *path, int users_only, struct config *out,
                char *error, size_t error_size);
void config_free(struct config *config);
int config_authenticate(const struct config *config, const unsigned char *name,
                        size_t name_len, const unsigned char *password,
                        size_t password_len);
int parse_authority(const char *text, int default_port, char *host,
                    size_t host_size, unsigned short *port);

#endif
