#include "proxy.h"
#include "http.h"

#include <arpa/inet.h>
#include <event2/bufferevent.h>
#include <event2/dns.h>
#include <event2/event.h>
#include <event2/listener.h>
#include <event2/util.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define BUFFER_LIMIT (256 * 1024)
#define BUFFER_LOW (64 * 1024)
#define IO_BLOCK (32 * 1024)
#define MAX_CONNECTIONS 4096

enum state {
    DETECT, HTTP_HEADERS, SOCKS_HELLO, SOCKS_AUTH, SOCKS_REQUEST,
    CONNECTING, CONNECT_RESPONSE, HTTP_EXCHANGE, TUNNEL, CLOSING
};

struct server;
struct connection {
    struct server *server;
    struct connection *next, *prev;
    struct bufferevent *client, *upstream;
    struct http_message request, response;
    enum state state;
    int socks, connect_method, response_started, interim_count;
    int client_eof, upstream_eof, client_shutdown, upstream_shutdown;
};

struct server {
    struct event_base *base;
    struct evdns_base *dns;
    struct evconnlistener *listener;
    struct event *reload_event, *term_event, *int_event;
    struct config *config;
    const char *path;
    struct connection *connections;
    size_t connection_count;
    int failed;
};

static void client_read(struct bufferevent *bev, void *arg);
static void upstream_read(struct bufferevent *bev, void *arg);
static void upstream_event(struct bufferevent *bev, short events, void *arg);
static void upstream_write(struct bufferevent *bev, void *arg);

static void connection_free(struct connection *c)
{
    if (c->prev) c->prev->next = c->next;
    else c->server->connections = c->next;
    if (c->next) c->next->prev = c->prev;
    --c->server->connection_count;
    if (c->client) bufferevent_free(c->client);
    if (c->upstream) bufferevent_free(c->upstream);
    http_free(&c->request);
    http_free(&c->response);
    free(c);
}

/* Drain the client output before destruction, including authentication errors. */
static void finish(struct connection *c)
{
    struct timeval timeout = {10, 0};
    c->state = CLOSING;
    if (c->upstream) { bufferevent_free(c->upstream); c->upstream = NULL; }
    bufferevent_disable(c->client, EV_READ);
    bufferevent_setwatermark(c->client, EV_WRITE, 0, 0);
    bufferevent_set_timeouts(c->client, NULL, &timeout);
    if (!evbuffer_get_length(bufferevent_get_output(c->client))) connection_free(c);
}

static void http_error(struct connection *c, int code, const char *reason)
{
    if (!c->response_started) {
        struct evbuffer *out = bufferevent_get_output(c->client);
        evbuffer_add_printf(out, "HTTP/1.1 %d %s\r\n%sContent-Length: 0\r\nConnection: close\r\n\r\n",
            code, reason, code == 407 ? "Proxy-Authenticate: Basic realm=\"vergeauth\"\r\n" : "");
    }
    finish(c);
}

static void socks_reply(struct connection *c, unsigned char code)
{
    unsigned char reply[10] = {5, 0, 0, 1, 0, 0, 0, 0, 0, 0};
    reply[1] = code;
    bufferevent_write(c->client, reply, sizeof(reply));
}

static void gateway_error(struct connection *c, int timeout)
{
    if (c->socks) { socks_reply(c, timeout ? 6 : 5); finish(c); }
    else http_error(c, timeout ? 504 : 502, timeout ? "Gateway Timeout" : "Bad Gateway");
}

/* A bounded complete header block is parsed before it can affect upstream IO. */
static int read_headers(struct bufferevent *bev, struct http_message *m)
{
    struct evbuffer *in = bufferevent_get_input(bev);
    struct evbuffer_ptr end = evbuffer_search(in, "\r\n\r\n", 4, NULL);
    size_t length;
    unsigned char *data;
    llhttp_errno_t err;
    if (end.pos < 0) return evbuffer_get_length(in) >= HTTP_HEADER_LIMIT ? -2 : 0;
    length = (size_t)end.pos + 4;
    if (length > HTTP_HEADER_LIMIT) return -2;
    data = evbuffer_pullup(in, (ev_ssize_t)length);
    if (!data) return -1;
    err = llhttp_execute(&m->parser, (const char *)data, length);
    if (!m->headers_done || (err != HPE_OK && err != HPE_PAUSED && err != HPE_PAUSED_UPGRADE)) return -1;
    evbuffer_drain(in, length);
    return 1;
}

static void set_timeouts(struct bufferevent *bev, long seconds)
{
    struct timeval timeout = {seconds, 0};
    bufferevent_set_timeouts(bev, &timeout, &timeout);
}

static int connect_upstream(struct connection *c, struct evbuffer *request)
{
    c->upstream = bufferevent_socket_new(c->server->base, -1,
                                        BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
    if (!c->upstream) return -1;
    bufferevent_setcb(c->upstream, upstream_read, upstream_write, upstream_event, c);
    bufferevent_setwatermark(c->upstream, EV_READ, 0, BUFFER_LIMIT);
    bufferevent_setwatermark(c->upstream, EV_WRITE, BUFFER_LOW, 0);
    set_timeouts(c->upstream, 15);
    if (bufferevent_write_buffer(c->upstream, request)) return -1;
    c->state = CONNECTING;
    bufferevent_disable(c->client, EV_READ);
    bufferevent_enable(c->upstream, EV_READ | EV_WRITE);
    return bufferevent_socket_connect_hostname(c->upstream, c->server->dns, AF_UNSPEC,
        c->server->config->upstream_host, c->server->config->upstream_port);
}

static void http_start(struct connection *c)
{
    struct evbuffer *out;
    char target[HTTP_HEADER_LIMIT + 1];
    int result = read_headers(c->client, &c->request);
    if (result == 0) return;
    if (result < 0) {
        http_error(c, result == -2 ? 431 : 400, result == -2 ? "Request Header Fields Too Large" : "Bad Request");
        return;
    }
    if (!http_authenticated(&c->request, c->server->config)) {
        http_error(c, 407, "Proxy Authentication Required"); return;
    }
    out = evbuffer_new();
    if (!out) { http_error(c, 500, "Internal Server Error"); return; }
    if (http_request(&c->request, out, target, sizeof(target))) {
        evbuffer_free(out); http_error(c, 400, "Bad Request"); return;
    }
    c->connect_method = c->request.parser.method == HTTP_CONNECT;
    c->response.tunnel_response = c->connect_method;
    c->response.head_response = c->request.parser.method == HTTP_HEAD;
    result = connect_upstream(c, out);
    evbuffer_free(out);
    if (result < 0) gateway_error(c, 0);
}

static int socks_hello(struct connection *c)
{
    struct evbuffer *in = bufferevent_get_input(c->client);
    unsigned char head[2], *data, reply[2] = {5, 255};
    size_t length;
    if (evbuffer_get_length(in) < 2) return 0;
    evbuffer_copyout(in, head, 2);
    length = (size_t)head[1] + 2;
    if (evbuffer_get_length(in) < length) return 0;
    data = evbuffer_pullup(in, (ev_ssize_t)length);
    if (!data) { connection_free(c); return -1; }
    if (head[0] == 5)
        for (size_t i = 2; i < length; ++i) if (data[i] == 2) reply[1] = 2;
    evbuffer_drain(in, length);
    bufferevent_write(c->client, reply, 2);
    if (reply[1] == 255) { finish(c); return -1; }
    c->state = SOCKS_AUTH;
    return 1;
}

static int socks_auth(struct connection *c)
{
    struct evbuffer *in = bufferevent_get_input(c->client);
    unsigned char *data, reply[2] = {1, 1};
    size_t available = evbuffer_get_length(in), nl, pl, length;
    if (available < 2) return 0;
    data = evbuffer_pullup(in, (ev_ssize_t)(available > 513 ? 513 : available));
    if (!data) { connection_free(c); return -1; }
    nl = data[1];
    if (data[0] != 1 || !nl) {
        bufferevent_write(c->client, reply, 2); finish(c); return -1;
    }
    if (available < nl + 3) return 0;
    pl = data[nl + 2];
    length = nl + pl + 3;
    if (available < length) return 0;
    if (config_authenticate(c->server->config, data + 2, nl, data + nl + 3, pl)) reply[1] = 0;
    evbuffer_drain(in, length);
    bufferevent_write(c->client, reply, 2);
    if (reply[1]) { finish(c); return -1; }
    c->state = SOCKS_REQUEST;
    return 1;
}

static void socks_request(struct connection *c)
{
    struct evbuffer *in = bufferevent_get_input(c->client), *out;
    unsigned char *data;
    size_t available = evbuffer_get_length(in), length, address_len, offset;
    unsigned short port;
    char host[256], target[320], checked[256];
    int result;
    if (available < 4) return;
    data = evbuffer_pullup(in, (ev_ssize_t)(available > 262 ? 262 : available));
    if (!data) { connection_free(c); return; }
    if (data[0] != 5 || data[2] != 0) { socks_reply(c, 1); finish(c); return; }
    if (data[1] != 1) { socks_reply(c, 7); finish(c); return; }
    if (data[3] == 1) { address_len = 4; offset = 4; }
    else if (data[3] == 4) { address_len = 16; offset = 4; }
    else if (data[3] == 3) {
        if (available < 5) return;
        address_len = data[4]; offset = 5;
        if (!address_len) { socks_reply(c, 8); finish(c); return; }
    } else { socks_reply(c, 8); finish(c); return; }
    length = offset + address_len + 2;
    if (available < length) return;
    port = (unsigned short)(((unsigned int)data[length - 2] << 8) | data[length - 1]);
    if (data[3] == 3) {
        memcpy(host, data + offset, address_len); host[address_len] = '\0';
        if (memchr(host, '\0', address_len)) { socks_reply(c, 8); finish(c); return; }
    } else if (!inet_ntop(data[3] == 1 ? AF_INET : AF_INET6, data + offset, host, sizeof(host))) {
        socks_reply(c, 8); finish(c); return;
    }
    snprintf(target, sizeof(target), data[3] == 4 ? "[%s]:%u" : "%s:%u", host, port);
    if (parse_authority(target, 0, checked, sizeof(checked), &port)) {
        socks_reply(c, 8); finish(c); return;
    }
    evbuffer_drain(in, length);
    out = evbuffer_new();
    if (!out) { socks_reply(c, 1); finish(c); return; }
    evbuffer_add_printf(out, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target);
    c->connect_method = 1;
    c->response.tunnel_response = 1;
    result = connect_upstream(c, out);
    evbuffer_free(out);
    if (result < 0) gateway_error(c, 0);
}

static void relay(struct bufferevent *source, struct bufferevent *destination)
{
    struct evbuffer *in = bufferevent_get_input(source), *out = bufferevent_get_output(destination);
    size_t queued = evbuffer_get_length(out), length = evbuffer_get_length(in);
    if (queued < BUFFER_LIMIT) {
        if (length > BUFFER_LIMIT - queued) length = BUFFER_LIMIT - queued;
        evbuffer_remove_buffer(in, out, length);
    }
    if (evbuffer_get_length(out) >= BUFFER_LIMIT) bufferevent_disable(source, EV_READ);
}

/* TCP FIN in one direction must not truncate data flowing in the other. */
static int tunnel_shutdown(struct connection *c)
{
    if (c->client_eof && !c->upstream_shutdown &&
        !evbuffer_get_length(bufferevent_get_input(c->client)) &&
        !evbuffer_get_length(bufferevent_get_output(c->upstream))) {
        shutdown(bufferevent_getfd(c->upstream), SHUT_WR);
        c->upstream_shutdown = 1;
    }
    if (c->upstream_eof && !c->client_shutdown &&
        !evbuffer_get_length(bufferevent_get_input(c->upstream)) &&
        !evbuffer_get_length(bufferevent_get_output(c->client))) {
        shutdown(bufferevent_getfd(c->client), SHUT_WR);
        c->client_shutdown = 1;
    }
    if (c->upstream_shutdown && c->client_shutdown) { connection_free(c); return 1; }
    return 0;
}

static int transfer_body(struct bufferevent *source, struct bufferevent *destination,
                         struct http_message *message)
{
    struct evbuffer *in = bufferevent_get_input(source), *out = bufferevent_get_output(destination);
    message->body_output = out;
    while (!message->complete && evbuffer_get_length(in) && evbuffer_get_length(out) < BUFFER_LIMIT) {
        size_t length = evbuffer_get_length(in), used = 0;
        unsigned char *data;
        if (length > IO_BLOCK) length = IO_BLOCK;
        data = evbuffer_pullup(in, (ev_ssize_t)length);
        if (!data || http_body(message, (const char *)data, length, &used)) return -1;
        evbuffer_drain(in, used);
    }
    if (message->complete || evbuffer_get_length(out) >= BUFFER_LIMIT) bufferevent_disable(source, EV_READ);
    return 0;
}

static void client_read(struct bufferevent *bev, void *arg)
{
    struct connection *c = arg;
    if (c->state == DETECT) {
        unsigned char first;
        if (evbuffer_copyout(bufferevent_get_input(bev), &first, 1) != 1) return;
        c->socks = first == 5;
        c->state = c->socks ? SOCKS_HELLO : HTTP_HEADERS;
    }
    if (c->state == HTTP_HEADERS) { http_start(c); return; }
    if (c->state == SOCKS_HELLO && socks_hello(c) <= 0) return;
    if (c->state == SOCKS_AUTH && socks_auth(c) <= 0) return;
    if (c->state == SOCKS_REQUEST) { socks_request(c); return; }
    if (c->state == HTTP_EXCHANGE) {
        if (transfer_body(c->client, c->upstream, &c->request)) {
            http_error(c, 400, "Bad Request"); return;
        }
        if (c->client_eof && !c->request.complete &&
            !evbuffer_get_length(bufferevent_get_input(c->client))) {
            http_error(c, 400, "Bad Request"); return;
        }
    } else if (c->state == TUNNEL) {
        relay(c->client, c->upstream);
        tunnel_shutdown(c);
    }
}

static void upstream_read(struct bufferevent *bev, void *arg)
{
    struct connection *c = arg;
    if (c->state == CONNECT_RESPONSE || c->state == HTTP_EXCHANGE) {
        while (!c->response.headers_done) {
            struct evbuffer *headers;
            int result = read_headers(bev, &c->response);
            if (result == 0) {
                if (c->upstream_eof) gateway_error(c, 0);
                return;
            }
            if (result < 0) { gateway_error(c, 0); return; }
            if (c->response.parser.status_code < 200 && c->response.parser.status_code != 101) {
                if (++c->interim_count > 16) { gateway_error(c, 0); return; }
                if (!c->connect_method && http_response(&c->response, bufferevent_get_output(c->client))) {
                    gateway_error(c, 0); return;
                }
                http_free(&c->response);
                http_init(&c->response, HTTP_RESPONSE);
                c->response.tunnel_response = c->connect_method;
                c->response.head_response = c->request.parser.method == HTTP_HEAD;
                continue;
            }
            if (c->connect_method) {
                if (c->response.parser.http_major != 1 || c->response.parser.http_minor > 1 ||
                    c->response.parser.status_code < 200 || c->response.parser.status_code >= 300) {
                    gateway_error(c, 0); return;
                }
                if (c->socks) socks_reply(c, 0);
                else bufferevent_write(c->client, "HTTP/1.1 200 Connection Established\r\n\r\n", 39);
                c->response_started = 1;
                c->state = TUNNEL;
                set_timeouts(c->upstream, 300);
                if (!c->client_eof) bufferevent_enable(c->client, EV_READ);
                relay(c->client, c->upstream);
                break;
            }
            headers = evbuffer_new();
            if (!headers) { gateway_error(c, 0); return; }
            if (http_response(&c->response, headers)) {
                evbuffer_free(headers); gateway_error(c, 0); return;
            }
            bufferevent_write_buffer(c->client, headers);
            evbuffer_free(headers);
            c->response_started = 1;
        }
    }
    if (c->state == TUNNEL) {
        relay(c->upstream, c->client);
        tunnel_shutdown(c);
    } else if (c->state == HTTP_EXCHANGE && c->response.headers_done) {
        if (transfer_body(c->upstream, c->client, &c->response)) { finish(c); return; }
        if (c->upstream_eof && !c->response.complete &&
            !evbuffer_get_length(bufferevent_get_input(c->upstream))) {
            llhttp_finish(&c->response.parser);
            /* Invalid/truncated responses also terminate the connection. */
            finish(c); return;
        }
        if (c->response.complete) finish(c);
    }
}

static void client_write(struct bufferevent *bev, void *arg)
{
    struct connection *c = arg;
    if (c->state == CLOSING) {
        if (!evbuffer_get_length(bufferevent_get_output(bev))) connection_free(c);
        return;
    }
    if ((c->state == TUNNEL || c->state == HTTP_EXCHANGE) && c->upstream) {
        if (!c->upstream_eof) bufferevent_enable(c->upstream, EV_READ);
        upstream_read(c->upstream, c);
    }
}

static void upstream_write(struct bufferevent *bev, void *arg)
{
    struct connection *c = arg;
    (void)bev;
    if (c->state == TUNNEL || c->state == HTTP_EXCHANGE) {
        if (!c->client_eof && (c->state == TUNNEL || !c->request.complete))
            bufferevent_enable(c->client, EV_READ);
        client_read(c->client, c);
    }
}

static void client_event(struct bufferevent *bev, short events, void *arg)
{
    struct connection *c = arg;
    if (events & (BEV_EVENT_ERROR | BEV_EVENT_TIMEOUT)) { connection_free(c); return; }
    if (events & BEV_EVENT_EOF) {
        c->client_eof = 1;
        bufferevent_disable(bev, EV_READ);
        if (c->state == TUNNEL || c->state == HTTP_EXCHANGE) client_read(bev, c);
        else if (c->state != CONNECTING && c->state != CONNECT_RESPONSE && c->state != CLOSING)
            connection_free(c);
    }
}

static void upstream_event(struct bufferevent *bev, short events, void *arg)
{
    struct connection *c = arg;
    if (events & BEV_EVENT_CONNECTED) {
        set_timeouts(c->client, 300);
        set_timeouts(c->upstream, c->connect_method ? 15 : 300);
        c->state = c->connect_method ? CONNECT_RESPONSE : HTTP_EXCHANGE;
        if (!c->connect_method) {
            if (!c->client_eof && !c->request.complete) bufferevent_enable(c->client, EV_READ);
            client_read(c->client, c);
        }
        return;
    }
    if (events & (BEV_EVENT_ERROR | BEV_EVENT_TIMEOUT)) {
        if (c->state == TUNNEL || c->response_started) finish(c);
        else gateway_error(c, (events & BEV_EVENT_TIMEOUT) != 0);
        return;
    }
    if (events & BEV_EVENT_EOF) {
        c->upstream_eof = 1;
        bufferevent_disable(bev, EV_READ);
        upstream_read(bev, c);
    }
}

static void accept_client(struct evconnlistener *listener, evutil_socket_t fd,
                          struct sockaddr *address, int length, void *arg)
{
    struct server *s = arg;
    struct connection *c;
    (void)listener; (void)address; (void)length;
    if (s->connection_count >= MAX_CONNECTIONS) { evutil_closesocket(fd); return; }
    c = calloc(1, sizeof(*c));
    if (!c) { evutil_closesocket(fd); return; }
    c->server = s;
    c->client = bufferevent_socket_new(s->base, fd, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
    if (!c->client) { evutil_closesocket(fd); free(c); return; }
    c->next = s->connections;
    if (c->next) c->next->prev = c;
    s->connections = c;
    ++s->connection_count;
    http_init(&c->request, HTTP_REQUEST);
    http_init(&c->response, HTTP_RESPONSE);
    bufferevent_setcb(c->client, client_read, client_write, client_event, c);
    bufferevent_setwatermark(c->client, EV_READ, 0, BUFFER_LIMIT);
    bufferevent_setwatermark(c->client, EV_WRITE, BUFFER_LOW, 0);
    set_timeouts(c->client, 30);
    bufferevent_enable(c->client, EV_READ | EV_WRITE);
}

static void reload_users(evutil_socket_t signal_number, short events, void *arg)
{
    struct server *s = arg;
    struct config next = {0}, old = {0};
    char error[512];
    (void)signal_number; (void)events;
    if (config_load(s->path, 1, &next, error, sizeof(error))) {
        log_message("reload rejected; existing users retained: %s", error); return;
    }
    old.users = s->config->users;
    old.user_count = s->config->user_count;
    s->config->users = next.users;
    s->config->user_count = next.user_count;
    config_free(&old);
    log_message("reloaded %zu users", s->config->user_count);
}

static void stop_server(evutil_socket_t signal_number, short events, void *arg)
{
    struct server *s = arg;
    (void)signal_number; (void)events;
    event_base_loopexit(s->base, NULL);
}

static void listener_error(struct evconnlistener *listener, void *arg)
{
    struct server *s = arg;
    (void)listener;
    log_message("listener failed: %s", evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
    s->failed = 1;
    event_base_loopexit(s->base, NULL);
}

int proxy_run(struct config *config, const char *path, int ready_fd)
{
    struct server s = {0};
    struct sockaddr_in address = {0};
    int result = -1;
    s.config = config; s.path = path;
    s.base = event_base_new();
    if (!s.base) goto cleanup;
    s.dns = evdns_base_new(s.base, 1);
    if (!s.dns) goto cleanup;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    address.sin_port = htons(config->listen_port);
    s.listener = evconnlistener_new_bind(s.base, accept_client, &s,
        LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE, 128,
        (struct sockaddr *)&address, sizeof(address));
    if (!s.listener) {
        log_message("cannot listen on port %u: %s", config->listen_port,
                    evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
        goto cleanup;
    }
    evconnlistener_set_error_cb(s.listener, listener_error);
    s.reload_event = evsignal_new(s.base, SIGHUP, reload_users, &s);
    s.term_event = evsignal_new(s.base, SIGTERM, stop_server, &s);
    s.int_event = evsignal_new(s.base, SIGINT, stop_server, &s);
    if (!s.reload_event || !s.term_event || !s.int_event ||
        event_add(s.reload_event, NULL) || event_add(s.term_event, NULL) || event_add(s.int_event, NULL))
        goto cleanup;
    log_message("listening on 0.0.0.0:%u; HTTP upstream %s:%u; %zu users",
                config->listen_port, config->upstream_host, config->upstream_port, config->user_count);
    if (ready_fd >= 0) {
        if (write(ready_fd, "1", 1) != 1) goto cleanup;
        close(ready_fd); ready_fd = -1;
    }
    result = event_base_dispatch(s.base) < 0 || s.failed ? -1 : 0;
cleanup:
    if (ready_fd >= 0) close(ready_fd);
    while (s.connections) connection_free(s.connections);
    if (s.listener) evconnlistener_free(s.listener);
    if (s.reload_event) event_free(s.reload_event);
    if (s.term_event) event_free(s.term_event);
    if (s.int_event) event_free(s.int_event);
    if (s.dns) evdns_base_free(s.dns, 0);
    if (s.base) event_base_free(s.base);
    return result;
}
