# Changelog

All notable changes to this project will be documented in this file.

## [0.2.0] - 2026-11-20

### Added
- Path policy engine: lexical canonicalization (`.`/`..`/`//`, clamped at `/`, relative paths joined with a virtual cwd) and glob rules (`*`, `?`, whole-segment `**`) with read/write/any access and last-match-wins semantics. The matcher is greedy with O(pattern x path) worst-case cost, and differential tests check it against an exhaustive reference matcher.
- Per-ABI open(2) flag decoding for Linux, Darwin/BSD and the Windows CRT. `O_CREAT`, `O_TRUNC`, `O_APPEND` and Linux `O_TMPFILE` count as write intent.
- Network policy engine: raw `struct sockaddr` decoding for the Linux, Darwin, FreeBSD, OpenBSD/NetBSD and Windows layouts (AF_INET, AF_INET6, AF_UNIX including abstract sockets), and CIDR/port rules (`10.0.0.0/8`, `::1/128@8080`, `*@53`, `unix`). IPv4-mapped IPv6 destinations are normalized to IPv4.
- Audit trail: a 256-entry ring of decisions with sequence number, canonical target, verdict, reason code, deciding rule and flag bits, exported as JSON with snprintf-style sizing. Invalid UTF-8 in paths becomes U+FFFD.
- New C-ABI exports: `stibnite_version`, `stibnite_intercept_openat`, `stibnite_intercept_connect_addr`, `stibnite_add_path_rule`, `stibnite_clear_path_rules`, `stibnite_add_net_rule`, `stibnite_clear_net_rules`, `stibnite_set_cwd`, `stibnite_set_epoch`, `stibnite_audit_count`, `stibnite_audit_json` and `stibnite_audit_clear`, plus the header `include/stibnite.h` (installed with the library).
- `stibnite eval --policy FILE --trace FILE [--json] [--fail-on-deny]` replays a syscall trace against a policy file. Errors report `file:line`, and `--fail-on-deny` exits with 2. Example files are in `examples/`.
- `stibnite demo`, `stibnite version` and `stibnite help` subcommands.
- Tests: the suite grew from 3 to 44 Zig tests (property, differential and fuzz-style tests for canonicalization, globbing, sockaddr decoding, CIDR parsing, JSON escaping and policy/trace parsing, plus a multi-threaded counter test). A C program (`tests/abi_test.c`, 54 checks) links the shared library and uses the host's `fcntl.h` and socket structures.

### Fixed
- On Linux, `O_RDONLY|O_CREAT` (0x40) was not treated as a write, so a read-only sandbox let it create files. The 0.1.0 check used the Darwin value of `O_CREAT`.
- The 0.1.0 exports dereferenced NULL pointers. `stibnite_intercept_open` and `stibnite_intercept_clock_gettime` now return -1 instead. Their names and signatures are unchanged.
- Global state is now guarded by a spinlock, so concurrent callers no longer tear counters.
- The virtual clock saturates instead of wrapping on overflow.
- The demo printed signed nanoseconds (`1772928000.+10000000s`). It now zero-pads unsigned nanoseconds (`1772928000.010000000s`).
- CI pinned `mlugg/setup-zig` to a commit that does not exist. It now uses v2.2.1 (`d1434d0`), and CI also runs an `eval` smoke test and `zig fmt --check`.

## 0.1.0 - 2026-11-08

### Added
- Initial release of Stibnite C-ABI dynamic hooking and syscall boundary interceptor.
- Deterministic virtual time mocking for reproducible clock_gettime test harnesses.
- Granular network (connect) and filesystem (open/openat) policy enforcement.
- Cross-platform dynamic library target for LD_PRELOAD and DYLD_INSERT_LIBRARIES.
