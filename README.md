# Stibnite

C-ABI Dynamic Hooking & Syscall Boundary Interceptor

A single-source tracing harness and deterministic mocking runtime that injects between native POSIX C-ABI boundaries via `LD_PRELOAD` / `DYLD_INSERT_LIBRARIES`.

## Architecture

- Syscall Boundary Interception: Traps `open`, `openat`, `connect`, and `clock_gettime` to enforce deterministic sandboxing policies and audit kernel boundary crossings.
- Deterministic Time Mocking: Intercepts time queries to advance along a virtual, step-based epoch, eliminating flakiness and race conditions in regression test suites.
- Outbound Network Quarantine: Blocks rogue external socket connection attempts while auditing destination endpoints.
- First-Class C Interop: Built using Zig's native C calling convention (`export fn`), compiling seamlessly to dynamic shared libraries across Linux, macOS, and Windows.

## Exported C-ABI Interface

```c
void stibnite_configure(int32_t block_net, int32_t read_only, uint32_t tick_ms);
uint64_t stibnite_get_total_calls(void);
uint64_t stibnite_get_blocked_calls(void);
void stibnite_reset(void);

int32_t stibnite_intercept_connect(int32_t sockfd);
int32_t stibnite_intercept_clock_gettime(int64_t* out_sec, int64_t* out_nsec);
int32_t stibnite_intercept_open(const char* path, int32_t flags);

/* Added in 0.2.0 */
const char* stibnite_version(void);
int32_t stibnite_intercept_openat(int32_t dirfd, const char* path, int32_t flags);
int32_t stibnite_intercept_connect_addr(int32_t sockfd, const void* addr, uint32_t addrlen);
int32_t stibnite_add_path_rule(const char* pattern, int32_t allow, int32_t access);
void stibnite_clear_path_rules(void);
int32_t stibnite_add_net_rule(const char* rule, int32_t allow);
void stibnite_clear_net_rules(void);
int32_t stibnite_set_cwd(const char* path);
int32_t stibnite_set_epoch(int64_t sec);
uint64_t stibnite_audit_count(void);
size_t stibnite_audit_json(char* buf, size_t len);
void stibnite_audit_clear(void);
```

The full declarations are in `include/stibnite.h`, which `zig build` installs to `zig-out/include/`. The 0.1.0 functions keep their names and signatures. As of 0.2.0 they reject NULL pointers by returning -1 instead of crashing, and every export is serialized by an internal spinlock, so multi-threaded hosts are safe.

## Building and Testing

```bash
# Run unit tests and the C-ABI test program
zig build test

# Build native binary and interposition shared library
zig build -Doptimize=ReleaseFast
```

`zig build test` runs 44 Zig tests (unit, property, differential and fuzz-style) and then `tests/abi_test.c`. That C program links against the built shared library and checks every export (54 checks) using the host's own `fcntl.h` and `sockaddr` structures.

## 0.2.0: Policy Engine, Audit Trail and `eval`

### Path rules

- Paths are canonicalized lexically before any decision. Repeated slashes and `.` segments are removed, `..` is resolved and clamped at `/`, and relative paths are joined with a virtual working directory (`stibnite_set_cwd`, default `/`). As a result, `/tmp/../etc/shadow` is judged as `/etc/shadow`.
- Rules are glob patterns over canonical absolute paths. `*` and `?` match within one segment. A whole `**` segment matches zero or more segments, so `/tmp/**` covers `/tmp` and everything under it. Each rule applies to `read`, `write` or `any` access, and the last matching rule wins. If no rule matches, the `read_only` switch decides. Matching is greedy with a single backtrack point, so it costs O(pattern x path) and has no exponential blowup.
- The open(2) flags are decoded per ABI (Linux, Darwin/BSD, Windows CRT). A request counts as a write if it has write access, `O_CREAT`, `O_TRUNC`, `O_APPEND` or Linux `O_TMPFILE`. This fixes a 0.1.0 gap: on Linux, `O_RDONLY|O_CREAT` (0x40) was treated as a read.
- `openat` treats `AT_FDCWD` (-100 on Linux, -2 on Darwin) as the working directory. A relative path under any other directory descriptor cannot be resolved, so it is denied (`unresolved_dirfd`). Empty paths, NULL and paths longer than PATH_MAX are denied as well.

### Network rules

- `stibnite_intercept_connect_addr` decodes the raw `struct sockaddr` for Linux, Darwin, FreeBSD, OpenBSD/NetBSD and Windows layouts. It supports AF_INET, AF_INET6 and AF_UNIX (including Linux abstract sockets). The decoder checks against the caller's `addrlen` and never trusts `sa_len`.
- IPv4-mapped IPv6 destinations (`::ffff:a.b.c.d`) are normalized to IPv4, so a dual-stack socket cannot bypass an IPv4 rule.
- Rule syntax: `10.0.0.0/8`, `::1/128@8080`, `*@53` (any IP on port 53) or `unix`. Prefixes with host bits set (`10.1.0.0/8`) are rejected as ambiguous. The last matching rule wins, and the `block_net` switch is the fallback.

### Audit trail

Every open, openat and connect decision is recorded in a 256-entry ring with a sequence number, the canonical target, the verdict, the reason (`default_policy`, `rule`, `read_only_fs`, `network_blocked`, `invalid_argument`, `path_too_long`, `unresolved_dirfd` or `unsupported_address`), the deciding rule index and the decoded flag bits. Clock reads are not recorded.

`stibnite_audit_json(buf, len)` follows snprintf conventions. It writes at most `len - 1` bytes plus a NUL and returns the full length needed, so `stibnite_audit_json(NULL, 0)` gives the required size. Non-UTF-8 bytes in paths become U+FFFD, so the output is always valid JSON.

```c
#include <fcntl.h>
#include "stibnite.h"

stibnite_configure(1, 1, 10);                        /* block net, read-only fs */
stibnite_add_path_rule("/tmp/**", 1, STIBNITE_ACCESS_WRITE);
stibnite_add_path_rule("/home/*/.ssh/**", 0, STIBNITE_ACCESS_ANY);
stibnite_add_net_rule("127.0.0.0/8", 1);
stibnite_intercept_open("/tmp/a/b.log", O_WRONLY | O_CREAT | O_TRUNC);  /* 3: allowed */
stibnite_intercept_open("/tmp/../home/ci/.ssh/id_rsa", O_RDONLY);        /* -1: denied */
size_t need = stibnite_audit_json(NULL, 0);
```

### `stibnite eval`

`eval` replays a trace of calls against a policy file without running anything. You can use it to review a sandbox policy or to gate CI with `--fail-on-deny`, which sets exit code 2 when any call was denied.

```bash
zig build -Doptimize=ReleaseFast
./zig-out/bin/stibnite eval --policy examples/ci.policy --trace examples/ci.trace
./zig-out/bin/stibnite eval --policy examples/ci.policy --trace examples/ci.trace --json
./zig-out/bin/stibnite eval --policy examples/ci.policy --trace examples/ci.trace --fail-on-deny; echo $?   # prints 2
```

Text output for the bundled example:

```
policy  abi=linux network=deny filesystem=read-only tick_ms=10 cwd=/home/ci/project path_rules=3 net_rules=3
line  syscall        verdict  reason              target
   2  open           allow    default_policy      /etc/hosts
   3  open           allow    rule#0              /tmp/build.log
   4  open           allow    rule#1              /home/ci/project/zig-out/bin/app
   5  open           deny     read_only_fs        /home/ci/project/src/cache.bin
   6  openat         deny     rule#2              /home/ci/.ssh/id_ed25519
   7  connect        allow    rule#0              127.0.0.1:5432
   8  connect        allow    rule#0              127.0.0.1:6379
   9  connect        deny     network_blocked     93.184.216.34:443
  10  connect        allow    rule#2              [2001:4860:4860::8888]:53
  11  clock_gettime  allow    -                   1772928000.000000000
  12  clock_gettime  allow    -                   1772928000.010000000
summary events=11 allowed=8 denied=3 total_calls=11 blocked_calls=3
```

Policy directives, one per line (`#` starts a comment):

| Directive | Meaning |
| --- | --- |
| `network allow\|deny` | fallback for connect |
| `filesystem read-only\|read-write` | fallback for write-intent opens |
| `tick-ms N` / `epoch SECONDS` | virtual clock step and start |
| `cwd /abs/path` | base for relative paths |
| `abi linux\|darwin\|freebsd\|openbsd\|windows` | flag and sockaddr encoding |
| `allow\|deny read\|write\|any PATTERN` | path rule |
| `net allow\|deny RULE` | network rule |

Trace operations are `open PATH [FLAGS]`, `openat DIRFD|AT_FDCWD PATH [FLAGS]`, `connect ENDPOINT` (`a.b.c.d:port`, `[v6]:port`, `unix:/path`, `unix:@name`), `connect-fd FD` and `clock`. FLAGS can be symbolic (`O_WRONLY|O_CREAT|O_TRUNC`) or numeric (`0x241`), and is encoded in the policy's ABI. Tokens are separated by whitespace, so paths cannot contain spaces. Errors report `file:line`. With `--json`, the output contains the parsed policy, one object per event (`line`, `seq`, `syscall`, `target`, `verdict`, `reason`, `rule`, `write_intent`, `write_access`, `create`, `truncate`, `append`, `time_ns`) and a summary. For clock events, `time_ns` is the value returned and `seq` is 0, because clock reads are not recorded in the audit ring.

`stibnite` with no arguments, or `stibnite demo`, runs the original 0.1.0 demo. Its nanosecond field is now zero-padded (`1772928000.010000000s`), where 0.1.0 printed a signed value (`1772928000.+10000000s`).

## License

MIT License - Copyright (c) 2026 Jeong Hoon Kim
