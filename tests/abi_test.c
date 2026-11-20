/* Links against the built libstibnite shared library and exercises every
 * exported symbol through include/stibnite.h, using the host's real fcntl.h
 * and socket structures. Exits non-zero on the first failed check. */
#include "stibnite.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>

static int checks = 0;
static int failures = 0;

#define CHECK(cond)                                                        \
    do {                                                                   \
        checks++;                                                          \
        if (!(cond)) {                                                     \
            failures++;                                                    \
            fprintf(stderr, "abi_test.c:%d: check failed: %s\n", __LINE__, #cond); \
        }                                                                  \
    } while (0)

static int connect_v4(const char *ip, uint16_t port) {
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
    sa.sin_len = sizeof sa;
#endif
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    inet_pton(AF_INET, ip, &sa.sin_addr);
    return stibnite_intercept_connect_addr(7, &sa, sizeof sa);
}

static int connect_v6(const char *ip, uint16_t port) {
    struct sockaddr_in6 sa;
    memset(&sa, 0, sizeof sa);
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
    sa.sin6_len = sizeof sa;
#endif
    sa.sin6_family = AF_INET6;
    sa.sin6_port = htons(port);
    inet_pton(AF_INET6, ip, &sa.sin6_addr);
    return stibnite_intercept_connect_addr(7, &sa, sizeof sa);
}

int main(void) {
    CHECK(strcmp(stibnite_version(), "0.2.0") == 0);

    /* 0.1.0 behaviour is unchanged. */
    stibnite_reset();
    stibnite_configure(1, 1, 10);
    int64_t s0, n0, s1, n1;
    CHECK(stibnite_intercept_clock_gettime(&s0, &n0) == 0);
    CHECK(stibnite_intercept_clock_gettime(&s1, &n1) == 0);
    CHECK(s0 == 1772928000 && n0 == 0 && n1 == 10000000);
    CHECK(stibnite_intercept_connect(4) == -1);
    CHECK(stibnite_intercept_open("/etc/hosts", O_RDONLY) == 3);
    CHECK(stibnite_intercept_open("/var/log/x", O_WRONLY) == -1);
    CHECK(stibnite_get_total_calls() == 5);
    CHECK(stibnite_get_blocked_calls() == 2);

    /* NULL pointers are rejected, not dereferenced. */
    CHECK(stibnite_intercept_clock_gettime(NULL, &n0) == -1);
    CHECK(stibnite_intercept_open(NULL, O_RDONLY) == -1);
    CHECK(stibnite_intercept_connect_addr(3, NULL, 0) == -1);
    CHECK(stibnite_add_path_rule(NULL, 1, 3) == -1);
    CHECK(stibnite_add_net_rule(NULL, 1) == -1);
    CHECK(stibnite_set_cwd(NULL) == -1);

    /* Real host O_CREAT is a write, even with O_RDONLY. */
    CHECK(stibnite_intercept_open("/data/new", O_RDONLY | O_CREAT) == -1);
    CHECK(stibnite_intercept_open("/data/new", O_RDONLY | O_TRUNC) == -1);
    CHECK(stibnite_intercept_open("/data/new", O_RDONLY | O_APPEND) == -1);

    /* Path rules, cwd and openat with the host AT_FDCWD. */
    CHECK(stibnite_add_path_rule("/tmp/**", 1, STIBNITE_ACCESS_WRITE) == 0);
    CHECK(stibnite_add_path_rule("/home/*/.ssh/**", 0, STIBNITE_ACCESS_ANY) == 1);
    CHECK(stibnite_intercept_open("/tmp/a/b.log", O_WRONLY | O_CREAT | O_TRUNC) == 3);
    CHECK(stibnite_intercept_open("/tmp/../home/ci/.ssh/id_rsa", O_RDONLY) == -1);
    CHECK(stibnite_set_cwd("/home/ci/work") == 0);
    CHECK(stibnite_intercept_openat(AT_FDCWD, "../.ssh/config", O_RDONLY) == -1);
    CHECK(stibnite_intercept_openat(AT_FDCWD, "notes.txt", O_RDONLY) == 3);
    CHECK(stibnite_intercept_openat(9, "notes.txt", O_RDONLY) == -1);

    /* Network rules with real sockaddr structures. */
    CHECK(stibnite_add_net_rule("127.0.0.0/8", 1) == 0);
    CHECK(stibnite_add_net_rule("*@53", 1) == 1);
    CHECK(stibnite_add_net_rule("10.0.0.0/33", 1) == -1);
    CHECK(connect_v4("127.0.0.1", 5432) == 0);
    CHECK(connect_v4("8.8.8.8", 53) == 0);
    CHECK(connect_v4("8.8.8.8", 443) == -1);
    CHECK(connect_v6("::1", 80) == -1);
    CHECK(connect_v6("::ffff:127.0.0.1", 80) == 0);
    CHECK(connect_v6("2001:4860:4860::8888", 53) == 0);
    {
        struct sockaddr_un un;
        memset(&un, 0, sizeof un);
        un.sun_family = AF_UNIX;
        strcpy(un.sun_path, "/run/app.sock");
        CHECK(stibnite_intercept_connect_addr(5, &un, sizeof un) == -1);
        CHECK(stibnite_add_net_rule("unix", 1) == 2);
        CHECK(stibnite_intercept_connect_addr(5, &un, sizeof un) == 0);
    }
    {
        struct sockaddr_in sa;
        memset(&sa, 0, sizeof sa);
        sa.sin_family = AF_INET;
        CHECK(stibnite_intercept_connect_addr(7, &sa, 4) == -1); /* truncated */
    }

    /* Audit JSON with snprintf-style sizing. */
    size_t need = stibnite_audit_json(NULL, 0);
    CHECK(need > 0);
    char *buf = malloc(need + 1);
    CHECK(buf != NULL);
    CHECK(stibnite_audit_json(buf, need + 1) == need);
    CHECK(strlen(buf) == need);
    CHECK(strstr(buf, "\"target\":\"/home/ci/.ssh/id_rsa\"") != NULL);
    CHECK(strstr(buf, "\"target\":\"[2001:4860:4860::8888]:53\"") != NULL);
    char small[16];
    CHECK(stibnite_audit_json(small, sizeof small) == need);
    CHECK(strlen(small) == sizeof small - 1);
    free(buf);
    CHECK(stibnite_audit_count() > 0);
    stibnite_audit_clear();
    CHECK(stibnite_audit_count() == 0);

    CHECK(stibnite_set_epoch(-1) == -1);
    CHECK(stibnite_set_epoch(86400) == 0);
    CHECK(stibnite_intercept_clock_gettime(&s0, &n0) == 0 && s0 == 86400 && n0 == 0);
    stibnite_clear_path_rules();
    stibnite_clear_net_rules();
    CHECK(connect_v4("127.0.0.1", 5432) == -1);
    stibnite_reset();
    CHECK(stibnite_get_total_calls() == 0);

    printf("abi_test: %d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
