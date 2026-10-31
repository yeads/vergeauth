/* Exercise the real proxy callbacks with libevent's in-memory transport.
 * Only socket construction/connect are replaced, so this also runs in a
 * sandbox without networking. TCP/daemon behavior is covered by integration.py.
 */
#include <event2/bufferevent.h>
#include <event2/event.h>
#include <event2/util.h>
#include <stdarg.h>

static struct bufferevent *test_socket_new(struct event_base *, evutil_socket_t, int);
static int test_connect(struct bufferevent *, struct evdns_base *, int, const char *, int);
#define bufferevent_socket_new test_socket_new
#define bufferevent_socket_connect_hostname test_connect
#include "../src/proxy.c"
#undef bufferevent_socket_new
#undef bufferevent_socket_connect_hostname

#define CHECK(expr) do { if (!(expr)) { \
    fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #expr); exit(1); \
} } while (0)

static struct bufferevent *created_peer;
static int connect_count;
static int connect_fails;
static struct server server;
static struct config config;
static struct bufferevent *client_peer, *upstream_peer;
static const char authorization[] = "Proxy-Authorization: Basic YWxpY2U6c2VjcmV0\r\n";

void log_message(const char *format, ...)
{
    (void)format;
}

static struct bufferevent *test_socket_new(struct event_base *base, evutil_socket_t fd, int options)
{
    struct bufferevent *pair[2];
    (void)fd;
    CHECK(bufferevent_pair_new(base, options, pair) == 0);
    created_peer = pair[1];
    bufferevent_enable(created_peer, EV_READ | EV_WRITE);
    return pair[0];
}

static int test_connect(struct bufferevent *bev, struct evdns_base *dns, int family,
                        const char *hostname, int port)
{
    (void)dns; (void)family;
    CHECK(strcmp(hostname, "localhost") == 0);
    CHECK(port == 7897);
    ++connect_count;
    upstream_peer = created_peer;
    if (connect_fails) return -1;
    bufferevent_trigger_event(bev, BEV_EVENT_CONNECTED, BEV_TRIG_DEFER_CALLBACKS);
    return 0;
}

static void pump(void)
{
    for (int i = 0; i < 32; ++i) event_base_loop(server.base, EVLOOP_NONBLOCK);
}

static void setup(void)
{
    memset(&server, 0, sizeof(server));
    memset(&config, 0, sizeof(config));
    config.users = calloc(1, sizeof(*config.users));
    CHECK(config.users);
    strcpy(config.users[0].name, "alice");
    strcpy(config.users[0].password, "secret");
    config.user_count = 1;
    strcpy(config.upstream_host, "localhost");
    config.upstream_port = 7897;
    server.config = &config;
    server.base = event_base_new();
    CHECK(server.base);
    connect_count = connect_fails = 0;
    upstream_peer = NULL;
    accept_client(NULL, -1, NULL, 0, &server);
    CHECK(server.connections);
    client_peer = created_peer;
}

static void teardown(void)
{
    while (server.connections) connection_free(server.connections);
    bufferevent_free(client_peer);
    if (upstream_peer) bufferevent_free(upstream_peer);
    event_base_free(server.base);
    config_free(&config);
}

static void send_bytes(struct bufferevent *peer, const void *data, size_t length)
{
    CHECK(bufferevent_write(peer, data, length) == 0);
    pump();
}

static void send_text(struct bufferevent *peer, const char *text)
{
    send_bytes(peer, text, strlen(text));
}

static char *take(struct bufferevent *peer)
{
    struct evbuffer *in = bufferevent_get_input(peer);
    size_t length = evbuffer_get_length(in);
    char *data = malloc(length + 1);
    CHECK(data);
    CHECK(evbuffer_remove(in, data, length) == (int)length);
    data[length] = '\0';
    return data;
}

static void expect_text(struct bufferevent *peer, const char *expected)
{
    char *data = take(peer);
    if (strcmp(data, expected)) fprintf(stderr, "expected <%s> got <%s>\n", expected, data);
    CHECK(strcmp(data, expected) == 0);
    free(data);
}

static void expect_status(struct bufferevent *peer, const char *status)
{
    char *data = take(peer);
    if (strncmp(data, status, strlen(status))) fprintf(stderr, "expected %s got <%s>\n", status, data);
    CHECK(strncmp(data, status, strlen(status)) == 0);
    free(data);
}

static void request(const char *method, const char *target, const char *auth, const char *extra)
{
    struct evbuffer *out = bufferevent_get_output(client_peer);
    evbuffer_add_printf(out, "%s %s HTTP/1.1\r\nHost: example.test\r\n%s%s\r\n", method, target, auth, extra);
    pump();
}

static void expect_graceful_close(void)
{
    CHECK(server.connections && server.connections->state == CLOSING);
    CHECK(server.connections->client_shutdown);
    bufferevent_trigger_event(server.connections->client, BEV_EVENT_EOF, BEV_TRIG_DEFER_CALLBACKS);
    pump();
    CHECK(!server.connections);
}

static void test_http_auth(void)
{
    const char *invalid[] = {
        "", "Proxy-Authorization: Basic YWxpY2U6d3Jvbmc=\r\n",
        "Proxy-Authorization: Basic YTpi=\r\n", "Proxy-Authorization: Basic YTpi====\r\n",
        "Proxy-Authorization: Bearer token\r\n", "Proxy-Authorization: B\r\n",
        "Proxy-Authorization: Basic YWxpY2U6c2VjcmV0\r\nProxy-Authorization: Basic YWxpY2U6c2VjcmV0\r\n"
    };
    for (size_t i = 0; i < sizeof(invalid) / sizeof(*invalid); ++i) {
        setup();
        request("GET", "http://example.test/", invalid[i], "");
        expect_status(client_peer, "HTTP/1.1 407 ");
        CHECK(connect_count == 0);
        teardown();
    }
    setup();
    request("GET", "http://example.test/", authorization,
            "Proxy-Connection: keep-alive\r\nConnection: X-Hidden\r\nX-Hidden: private\r\nAuthorization: Bearer origin\r\n");
    CHECK(connect_count == 1);
    expect_text(upstream_peer, "GET http://example.test/ HTTP/1.1\r\nHost: example.test\r\nAuthorization: Bearer origin\r\nConnection: close\r\n\r\n");
    send_text(upstream_peer, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nok");
    expect_text(client_peer, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
    expect_graceful_close();
    teardown();
}

static void test_http_framing(void)
{
    setup();
    request("POST", "http://example.test/", authorization, "Content-Length: 4\r\nExpect: 100-continue\r\n");
    free(take(upstream_peer));
    send_text(upstream_peer, "HTTP/1.1 100 Continue\r\n\r\n");
    expect_status(client_peer, "HTTP/1.1 100 ");
    send_text(client_peer, "dataGET http://unauthorized/ HTTP/1.1\r\nHost: unauthorized\r\n\r\n");
    expect_text(upstream_peer, "data");
    CHECK(server.connections->request.complete);
    send_text(upstream_peer, "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ndata");
    expect_text(client_peer, "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\ndata");
    teardown();

    setup();
    request("POST", "http://example.test/", authorization,
            "Transfer-Encoding: chunked\r\nTrailer: Proxy-Authorization\r\n");
    expect_text(upstream_peer, "POST http://example.test/ HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n");
    send_text(client_peer, "3;ext=yes\r\nabc\r\n2\r\nde\r\n0\r\nProxy-Authorization: hidden\r\n\r\n");
    expect_text(upstream_peer, "3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n");
    send_text(upstream_peer, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X-End\r\n\r\n5\r\nhello\r\n0\r\nX-End: ignored\r\n\r\n");
    expect_text(client_peer, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nhello\r\n0\r\n\r\n");
    teardown();

    setup();
    request("HEAD", "http://example.test/", authorization, "");
    send_text(upstream_peer, "HTTP/1.1 200 OK\r\nContent-Length: 123\r\n\r\n");
    expect_text(client_peer, "HTTP/1.1 200 OK\r\nContent-Length: 123\r\nConnection: close\r\n\r\n");
    expect_graceful_close();
    teardown();

    setup();
    request("GET", "http://example.test/", authorization, "");
    send_text(upstream_peer, "HTTP/1.0 200 OK\r\n\r\neof-body");
    CHECK(server.connections);
    bufferevent_trigger_event(server.connections->upstream, BEV_EVENT_EOF, BEV_TRIG_DEFER_CALLBACKS);
    pump();
    expect_text(client_peer, "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\neof-body");
    expect_graceful_close();
    teardown();
}

static void test_invalid_http(void)
{
    const char *extra[] = {
        "Content-Length: 4\r\nTransfer-Encoding: chunked\r\n",
        "Content-Length: 2\r\nContent-Length: 3\r\n", "Host: duplicate\r\n",
        "Connection: Content-Length\r\nContent-Length: 0\r\n", "Upgrade: websocket\r\n"
    };
    for (size_t i = 0; i < sizeof(extra) / sizeof(*extra); ++i) {
        setup();
        request("GET", "http://example.test/", authorization, extra[i]);
        expect_status(client_peer, "HTTP/1.1 400 ");
        CHECK(connect_count == 0);
        teardown();
    }
    setup();
    request("CONNECT", "example.test:443", "", "");
    expect_status(client_peer, "HTTP/1.1 407 ");
    CHECK(!connect_count);
    teardown();

    setup();
    char *large = malloc(66000);
    CHECK(large);
    memset(large, 'a', 66000);
    send_text(client_peer, "GET / HTTP/1.1\r\nX-Large: ");
    send_bytes(client_peer, large, 66000);
    expect_status(client_peer, "HTTP/1.1 431 ");
    CHECK(!connect_count);
    free(large);
    teardown();

    setup();
    connect_fails = 1;
    request("GET", "http://example.test/", authorization, "");
    expect_status(client_peer, "HTTP/1.1 502 ");
    teardown();
}

static void test_http_tunnel(void)
{
    setup();
    request("CONNECT", "example.test:443", authorization, "");
    expect_text(upstream_peer, "CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\n\r\n");
    send_text(client_peer, "early-data");
    expect_text(upstream_peer, "");
    send_text(upstream_peer, "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 Connection Established\r\n\r\ngreeting");
    expect_text(client_peer, "HTTP/1.1 200 Connection Established\r\n\r\ngreeting");
    expect_text(upstream_peer, "early-data");
    send_text(client_peer, "ping");
    expect_text(upstream_peer, "ping");
    send_text(upstream_peer, "pong");
    expect_text(client_peer, "pong");
    CHECK(server.connections->state == TUNNEL);
    teardown();

    setup();
    request("CONNECT", "example.test:443", authorization, "");
    send_text(upstream_peer, "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n");
    expect_status(client_peer, "HTTP/1.1 502 ");
    teardown();
}

static void test_graceful_close(void)
{
    char large[66000];
    memset(large, 'a', sizeof(large));
    setup();
    send_text(client_peer, "GET / HTTP/1.1\r\nX-Large: ");
    send_bytes(client_peer, large, sizeof(large));
    expect_status(client_peer, "HTTP/1.1 431 ");
    CHECK(server.connections && server.connections->state == CLOSING);
    CHECK(server.connections->client_shutdown);
    CHECK(!evbuffer_get_length(bufferevent_get_input(server.connections->client)));
    /* Data still in flight must be discarded after the response is sent. */
    send_bytes(client_peer, large, sizeof(large));
    CHECK(!evbuffer_get_length(bufferevent_get_input(server.connections->client)));
    CHECK(!connect_count);
    expect_graceful_close();
    teardown();

    /* Incoming data must not extend the deadline for releasing a connection. */
    setup();
    request("GET", "http://example.test/", "", "");
    expect_status(client_peer, "HTTP/1.1 407 ");
    struct timeval deadline, after_input;
    CHECK(evtimer_pending(server.connections->close_timer, &deadline));
    send_text(client_peer, "extra input");
    CHECK(evtimer_pending(server.connections->close_timer, &after_input));
    CHECK(deadline.tv_sec == after_input.tv_sec && deadline.tv_usec == after_input.tv_usec);
    event_active(server.connections->close_timer, EV_TIMEOUT, 0);
    pump();
    CHECK(!server.connections);
    teardown();

    /* A client's FIN must not discard an error response still waiting to write. */
    setup();
    bufferevent_disable(client_peer, EV_READ);
    request("GET", "http://example.test/", "", "");
    CHECK(server.connections && !server.connections->client_shutdown);
    CHECK(!evtimer_pending(server.connections->close_timer, NULL));
    bufferevent_trigger_event(server.connections->client, BEV_EVENT_EOF, BEV_TRIG_DEFER_CALLBACKS);
    pump();
    CHECK(server.connections && !server.connections->client_shutdown);
    bufferevent_enable(client_peer, EV_READ);
    pump();
    expect_status(client_peer, "HTTP/1.1 407 ");
    CHECK(!server.connections);
    teardown();
}

static void test_socks(void)
{
    unsigned char negotiation[] = {5, 2, 0, 2, 1, 5, 'a', 'l', 'i', 'c', 'e', 6, 's', 'e', 'c', 'r', 'e', 't'};
    unsigned char req[] = {5, 1, 0, 3, 12, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 't', 'e', 's', 't', 1, 187};
    unsigned char answer[14];
    setup();
    /* Fragment every byte across event-loop iterations. */
    for (size_t i = 0; i < sizeof(negotiation); ++i) send_bytes(client_peer, negotiation + i, 1);
    for (size_t i = 0; i < sizeof(req); ++i) send_bytes(client_peer, req + i, 1);
    expect_text(upstream_peer, "CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\n\r\n");
    send_text(upstream_peer, "HTTP/1.1 200 OK\r\n\r\n");
    CHECK(evbuffer_remove(bufferevent_get_input(client_peer), answer, sizeof(answer)) == 14);
    CHECK(memcmp(answer, "\x05\x02\x01\x00\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00", 14) == 0);
    send_text(client_peer, "payload");
    expect_text(upstream_peer, "payload");
    teardown();

    setup();
    send_bytes(client_peer, "\x05\x01\x00", 3);
    CHECK(evbuffer_remove(bufferevent_get_input(client_peer), answer, 2) == 2);
    CHECK(answer[0] == 5 && answer[1] == 255);
    CHECK(!connect_count);
    teardown();

    setup();
    negotiation[sizeof(negotiation) - 1] = 'x';
    send_bytes(client_peer, negotiation, sizeof(negotiation));
    CHECK(evbuffer_remove(bufferevent_get_input(client_peer), answer, 4) == 4);
    CHECK(!memcmp(answer, "\x05\x02\x01\x01", 4));
    CHECK(!connect_count);
    teardown();
    negotiation[sizeof(negotiation) - 1] = 't';

    const unsigned char addresses[][22] = {
        {5, 1, 0, 1, 127, 0, 0, 1, 1, 187},
        {5, 1, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 187}
    };
    for (size_t i = 0; i < 2; ++i) {
        setup();
        send_bytes(client_peer, negotiation, sizeof(negotiation));
        send_bytes(client_peer, addresses[i], i ? 22 : 10);
        expect_text(upstream_peer, i ? "CONNECT [::1]:443 HTTP/1.1\r\nHost: [::1]:443\r\n\r\n" :
                                      "CONNECT 127.0.0.1:443 HTTP/1.1\r\nHost: 127.0.0.1:443\r\n\r\n");
        teardown();
    }
    for (unsigned char command = 2; command <= 3; ++command) {
        setup();
        send_bytes(client_peer, negotiation, sizeof(negotiation));
        free(take(client_peer));
        req[1] = command;
        send_bytes(client_peer, req, sizeof(req));
        CHECK(evbuffer_remove(bufferevent_get_input(client_peer), answer, 10) == 10);
        CHECK(answer[0] == 5 && answer[1] == 7);
        CHECK(!connect_count);
        teardown();
    }
}

static void test_config_reload(void)
{
    char path[] = "/tmp/vergeauth-protocol-XXXXXX", error[512];
    int fd = mkstemp(path);
    FILE *file;
    struct config loaded = {0};
    CHECK(fd >= 0);
    file = fdopen(fd, "w");
    CHECK(file);
    fputs("# comment\nlisten 7898\nupstream http://[::1]:7897\nuser alice secret # comment\nuser bob 'space password'\n", file);
    CHECK(fclose(file) == 0);
    CHECK(config_load(path, 0, &loaded, error, sizeof(error)) == 0);
    CHECK(loaded.listen_port == 7898 && loaded.upstream_port == 7897);
    CHECK(!strcmp(loaded.upstream_host, "::1"));
    CHECK(config_authenticate(&loaded, (const unsigned char *)"bob", 3,
                               (const unsigned char *)"space password", 14));
    config_free(&loaded);

    setup();
    server.path = path;
    file = fopen(path, "w"); CHECK(file);
    fputs("listen invalid\nupstream invalid\nuser alice changed\n", file);
    fclose(file);
    reload_users(0, 0, &server);
    CHECK(!strcmp(config.users[0].password, "changed"));
    CHECK(!strcmp(config.upstream_host, "localhost") && config.upstream_port == 7897);
    file = fopen(path, "w"); CHECK(file);
    fputs("user alice wrong\nuser alice duplicate\n", file);
    fclose(file);
    reload_users(0, 0, &server);
    CHECK(!strcmp(config.users[0].password, "changed"));
    file = fopen(path, "w"); CHECK(file);
    fputs("# remove all users\n", file);
    fclose(file);
    reload_users(0, 0, &server);
    CHECK(config.user_count == 0);
    request("GET", "http://example.test/", authorization, "");
    expect_status(client_peer, "HTTP/1.1 407 ");
    CHECK(!connect_count);
    teardown();
    unlink(path);
}

static void test_backpressure(void)
{
    size_t length = 2 * 1024 * 1024, received = 0;
    char block[16384];
    memset(block, 'x', sizeof(block));
    setup();
    request("CONNECT", "example.test:443", authorization, "");
    free(take(upstream_peer));
    send_text(upstream_peer, "HTTP/1.1 200 OK\r\n\r\n");
    free(take(client_peer));
    bufferevent_disable(upstream_peer, EV_READ);
    for (size_t sent = 0; sent < length; sent += sizeof(block))
        CHECK(bufferevent_write(client_peer, block, sizeof(block)) == 0);
    pump();
    CHECK(evbuffer_get_length(bufferevent_get_output(server.connections->upstream)) <= BUFFER_LIMIT);
    CHECK(evbuffer_get_length(bufferevent_get_input(server.connections->client)) <= BUFFER_LIMIT);
    bufferevent_enable(upstream_peer, EV_READ);
    for (int i = 0; i < 128 && received < length; ++i) {
        pump();
        struct evbuffer *in = bufferevent_get_input(upstream_peer);
        while (evbuffer_get_length(in)) {
            int n = evbuffer_remove(in, block, sizeof(block));
            CHECK(n > 0);
            for (int j = 0; j < n; ++j) CHECK(block[j] == 'x');
            received += (size_t)n;
        }
    }
    CHECK(received == length);
    teardown();
}

static void test_half_close_and_failures(void)
{
    setup();
    request("CONNECT", "example.test:443", authorization, "");
    free(take(upstream_peer));
    send_text(upstream_peer, "HTTP/1.1 200 OK\r\n\r\n");
    free(take(client_peer));
    send_text(client_peer, "last-request");
    bufferevent_trigger_event(server.connections->client, BEV_EVENT_EOF, BEV_TRIG_DEFER_CALLBACKS);
    pump();
    CHECK(server.connections && server.connections->upstream_shutdown);
    expect_text(upstream_peer, "last-request");
    send_text(upstream_peer, "after-fin");
    expect_text(client_peer, "after-fin");
    bufferevent_trigger_event(server.connections->upstream, BEV_EVENT_EOF, BEV_TRIG_DEFER_CALLBACKS);
    pump();
    CHECK(!server.connections);
    teardown();

    setup();
    request("POST", "http://example.test/", authorization, "Content-Length: 10\r\n");
    send_text(client_peer, "short");
    bufferevent_trigger_event(server.connections->client, BEV_EVENT_EOF, BEV_TRIG_DEFER_CALLBACKS);
    pump();
    expect_status(client_peer, "HTTP/1.1 400 ");
    CHECK(!server.connections);
    teardown();

    setup();
    request("GET", "http://example.test/", authorization, "");
    send_text(upstream_peer, "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort");
    bufferevent_trigger_event(server.connections->upstream, BEV_EVENT_EOF, BEV_TRIG_DEFER_CALLBACKS);
    pump();
    expect_text(client_peer, "HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\nshort");
    expect_graceful_close();
    teardown();

    setup();
    request("CONNECT", "example.test:443", authorization, "");
    bufferevent_trigger_event(server.connections->upstream, BEV_EVENT_TIMEOUT, BEV_TRIG_DEFER_CALLBACKS);
    pump();
    expect_status(client_peer, "HTTP/1.1 504 ");
    expect_graceful_close();
    teardown();

    setup();
    request("GET", "http://example.test/", authorization, "");
    send_text(upstream_peer, "invalid-response\r\n\r\n");
    expect_status(client_peer, "HTTP/1.1 502 ");
    expect_graceful_close();
    teardown();
}

static void test_fragmentation_and_live_reload(void)
{
    const char message[] = "POST http://example.test/ HTTP/1.1\r\nHost: example.test\r\n"
        "Proxy-Authorization: Basic YWxpY2U6c2VjcmV0\r\nContent-Length: 4\r\n\r\ndata";
    /* Split across every request/header/body boundary in turn. */
    for (size_t split = 1; split < sizeof(message) - 1; ++split) {
        setup();
        send_bytes(client_peer, message, split);
        send_bytes(client_peer, message + split, sizeof(message) - split - 1);
        CHECK(connect_count == 1);
        expect_text(upstream_peer, "POST http://example.test/ HTTP/1.1\r\nHost: example.test\r\nContent-Length: 4\r\nConnection: close\r\n\r\ndata");
        teardown();
    }

    setup();
    request("CONNECT", "example.test:443", authorization, "");
    free(take(upstream_peer));
    send_text(upstream_peer, "HTTP/1.1 200 OK\r\n\r\n");
    free(take(client_peer));
    char path[] = "/tmp/vergeauth-reload-XXXXXX";
    int fd = mkstemp(path);
    CHECK(fd >= 0);
    close(fd); /* An empty configuration revokes all users on reload. */
    server.path = path;
    reload_users(0, 0, &server);
    CHECK(config.user_count == 0);
    send_text(client_peer, "existing-tunnel");
    expect_text(upstream_peer, "existing-tunnel");
    send_text(upstream_peer, "still-alive");
    expect_text(client_peer, "still-alive");
    unlink(path);
    teardown();
}

int main(void)
{
    test_graceful_close();
    test_http_auth();
    test_http_framing();
    test_invalid_http();
    test_http_tunnel();
    test_socks();
    test_config_reload();
    test_backpressure();
    test_half_close_and_failures();
    test_fragmentation_and_live_reload();
    puts("protocol tests passed (HTTP, SOCKS5, tunnels, framing, authentication, reload, backpressure)");
    return 0;
}
