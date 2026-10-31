#include "config.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int parse_port(const char *s, unsigned short *port)
{
    unsigned long n = 0;
    if (!*s) return -1;
    for (; *s; ++s) {
        if (*s < '0' || *s > '9') return -1;
        n = n * 10 + (unsigned long)(*s - '0');
        if (n > 65535) return -1;
    }
    if (n == 0) return -1;
    *port = (unsigned short)n;
    return 0;
}

int parse_authority(const char *text, int default_port, char *host,
                    size_t host_size, unsigned short *port)
{
    const char *start = text, *end, *suffix;
    size_t len;
    if (*text == '[') {
        struct in6_addr address;
        start = text + 1;
        end = strchr(start, ']');
        if (!end) return -1;
        suffix = end + 1;
        len = (size_t)(end - start);
        if (len == 0 || len >= host_size) return -1;
        memcpy(host, start, len);
        host[len] = '\0';
        if (inet_pton(AF_INET6, host, &address) != 1) return -1;
    } else {
        end = strchr(start, ':');
        if (!end) end = start + strlen(start);
        suffix = end;
        len = (size_t)(end - start);
        if (len == 0 || len >= host_size) return -1;
        for (size_t i = 0; i < len; ++i) {
            unsigned char c = (unsigned char)start[i];
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                  (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_'))
                return -1;
        }
        memcpy(host, start, len);
        host[len] = '\0';
    }
    if (*suffix == ':') return parse_port(suffix + 1, port);
    if (*suffix || default_port <= 0) return -1;
    *port = (unsigned short)default_port;
    return 0;
}

/* Tokenize in place. Quotes and backslash escapes permit spaces in passwords. */
static int tokenize(char *line, char **tokens, size_t capacity)
{
    char *read = line, *write = line;
    size_t count = 0;
    while (*read) {
        char quote = 0;
        while (isspace((unsigned char)*read)) ++read;
        if (!*read || *read == '#') break;
        if (count == capacity) return -1;
        tokens[count++] = write;
        while (*read && (quote || !isspace((unsigned char)*read))) {
            char c = *read++;
            if (c == '\\') {
                if (!*read) return -1;
                c = *read++;
            } else if (c == '\'' || c == '"') {
                if (!quote) { quote = c; continue; }
                if (quote == c) { quote = 0; continue; }
            }
            if ((unsigned char)c < 32 || (unsigned char)c == 127) return -1;
            *write++ = c;
        }
        if (quote) return -1;
        /* Move read first: write can point at the same separating space. */
        while (isspace((unsigned char)*read)) ++read;
        *write++ = '\0';
    }
    return (int)count;
}

void config_free(struct config *config)
{
    if (config->users) {
        volatile unsigned char *p = (volatile unsigned char *)config->users;
        size_t n = config->user_count * sizeof(*config->users);
        while (n--) *p++ = 0;
        free(config->users);
    }
    memset(config, 0, sizeof(*config));
}

int config_load(const char *path, int users_only, struct config *out,
                char *error, size_t error_size)
{
    FILE *file = fopen(path, "r");
    struct config config = {0};
    char *line = NULL;
    size_t capacity = 0;
    ssize_t line_length;
    size_t line_number = 0;
    const char *reason = NULL;
    int have_listen = 0, have_upstream = 0;
    if (!file) {
        snprintf(error, error_size, "%s: %s", path, strerror(errno));
        return -1;
    }
    while ((line_length = getline(&line, &capacity, file)) >= 0) {
        char *tokens[4];
        const char *directive;
        int count;
        ++line_number;
        if (line_length > 8191) {
            reason = "configuration line is too long"; break;
        }
        if (memchr(line, '\0', (size_t)line_length)) {
            reason = "configuration contains a NUL byte"; break;
        }
        directive = line;
        while (isspace((unsigned char)*directive)) ++directive;
        if (users_only && ((!strncmp(directive, "listen", 6) &&
                            (!directive[6] || isspace((unsigned char)directive[6]))) ||
                           (!strncmp(directive, "upstream", 8) &&
                            (!directive[8] || isspace((unsigned char)directive[8]))))) continue;
        count = tokenize(line, tokens, 4);
        if (count < 0) { reason = "invalid quoting or too many arguments"; break; }
        if (!count) continue;
        if (strcmp(tokens[0], "user") == 0) {
            struct user *users;
            size_t nl, pl;
            if (count != 3) { reason = "expected: user <name> <password>"; break; }
            nl = strlen(tokens[1]); pl = strlen(tokens[2]);
            if (!nl || nl > 255 || !pl || pl > 255 || strchr(tokens[1], ':')) {
                reason = "credentials must be 1..255 bytes; usernames cannot contain ':'";
                break;
            }
            for (size_t i = 0; i < config.user_count; ++i)
                if (!strcmp(config.users[i].name, tokens[1])) reason = "duplicate username";
            if (reason) break;
            users = realloc(config.users, (config.user_count + 1) * sizeof(*users));
            if (!users) { reason = "out of memory"; break; }
            config.users = users;
            memset(&users[config.user_count], 0, sizeof(*users));
            memcpy(users[config.user_count].name, tokens[1], nl);
            memcpy(users[config.user_count].password, tokens[2], pl);
            ++config.user_count;
        } else if (!strcmp(tokens[0], "listen")) {
            if (users_only) continue;
            if (count != 2 || have_listen++ || parse_port(tokens[1], &config.listen_port)) {
                reason = "expected one listen <port>, port in 1..65535"; break;
            }
        } else if (!strcmp(tokens[0], "upstream")) {
            const char *address;
            if (users_only) continue;
            if (count != 2 || have_upstream++) {
                reason = "expected one upstream <host:port>"; break;
            }
            address = tokens[1];
            if (!strncmp(address, "http://", 7)) address += 7;
            if (parse_authority(address, 0, config.upstream_host,
                                sizeof(config.upstream_host), &config.upstream_port)) {
                reason = "invalid upstream address (use host:port or [IPv6]:port)"; break;
            }
        } else {
            reason = "unknown configuration directive"; break;
        }
    }
    if (!reason && ferror(file)) reason = "cannot read configuration";
    if (!reason && !users_only && (!have_listen || !have_upstream))
        reason = "listen and upstream are required";
    free(line);
    fclose(file);
    if (reason) {
        snprintf(error, error_size, "%s:%zu: %s", path, line_number, reason);
        config_free(&config);
        return -1;
    }
    *out = config;
    return 0;
}

int config_authenticate(const struct config *config, const unsigned char *name,
                        size_t name_len, const unsigned char *password,
                        size_t password_len)
{
    unsigned int matched = 0;
    if (!name_len || name_len > 255 || !password_len || password_len > 255) return 0;
    for (size_t i = 0; i < config->user_count; ++i) {
        const struct user *u = &config->users[i];
        unsigned int diff = (unsigned int)(strlen(u->name) ^ name_len) |
                            (unsigned int)(strlen(u->password) ^ password_len);
        for (size_t j = 0; j < 255; ++j) {
            diff |= (unsigned int)((unsigned char)u->name[j] ^ (j < name_len ? name[j] : 0));
            diff |= (unsigned int)((unsigned char)u->password[j] ^ (j < password_len ? password[j] : 0));
        }
        matched |= (diff == 0);
    }
    return matched != 0;
}
