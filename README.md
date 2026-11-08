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
```

## Building and Testing

```bash
# Run unit tests
zig build test

# Build native binary and interposition shared library
zig build -Doptimize=ReleaseFast
```

## License

MIT License - Copyright (c) 2026 Jeong Hoon Kim
