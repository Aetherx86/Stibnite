/*
 * Stibnite: C-ABI Dynamic Hooking & Syscall Boundary Interceptor
 * Licensed under the MIT License.
 *
 * Every function returns -1 (or denies) on NULL pointers instead of
 * dereferencing them. All functions are safe to call from multiple threads.
 */
#ifndef STIBNITE_H
#define STIBNITE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- 0.1.0 interface (unchanged) ---- */
void stibnite_configure(int32_t block_net, int32_t read_only, uint32_t tick_ms);
uint64_t stibnite_get_total_calls(void);
uint64_t stibnite_get_blocked_calls(void);
void stibnite_reset(void);

int32_t stibnite_intercept_connect(int32_t sockfd);
int32_t stibnite_intercept_clock_gettime(int64_t *out_sec, int64_t *out_nsec);
int32_t stibnite_intercept_open(const char *path, int32_t flags);

/* ---- 0.2.0 additions ---- */
#define STIBNITE_ACCESS_READ 1
#define STIBNITE_ACCESS_WRITE 2
#define STIBNITE_ACCESS_ANY 3

const char *stibnite_version(void);

int32_t stibnite_intercept_openat(int32_t dirfd, const char *path, int32_t flags);
int32_t stibnite_intercept_connect_addr(int32_t sockfd, const void *addr, uint32_t addrlen);

int32_t stibnite_add_path_rule(const char *pattern, int32_t allow, int32_t access);
void stibnite_clear_path_rules(void);
int32_t stibnite_add_net_rule(const char *rule, int32_t allow);
void stibnite_clear_net_rules(void);
int32_t stibnite_set_cwd(const char *path);
int32_t stibnite_set_epoch(int64_t sec);

uint64_t stibnite_audit_count(void);
size_t stibnite_audit_json(char *buf, size_t len);
void stibnite_audit_clear(void);

#ifdef __cplusplus
}
#endif

#endif /* STIBNITE_H */
