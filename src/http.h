#ifndef VERGEAUTH_HTTP_H
#define VERGEAUTH_HTTP_H

#include "config.h"
#include <event2/buffer.h>
#include <llhttp.h>

#define HTTP_HEADER_LIMIT 65536
#define HTTP_FIELD_LIMIT 128

struct http_field { char *name; char *value; };
struct http_message {
    llhttp_t parser;
    llhttp_settings_t settings;
    struct http_field fields[HTTP_FIELD_LIMIT];
    size_t field_count;
    size_t header_bytes;
    char *url;
    int headers_done;
    int complete;
    int tunnel_response;
    int head_response;
    int chunked;
    struct evbuffer *body_output;
};

void http_init(struct http_message *message, llhttp_type_t type);
void http_free(struct http_message *message);
const char *http_header(const struct http_message *message, const char *name, int *count);
int http_authenticated(const struct http_message *message, const struct config *config);
int http_request(struct http_message *message, struct evbuffer *output,
                 char *target, size_t target_size);
int http_response(struct http_message *message, struct evbuffer *output);
int http_body(struct http_message *message, const char *data, size_t length, size_t *used);

#endif
