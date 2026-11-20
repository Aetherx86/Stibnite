# Stibnite

C-ABI 동적 후킹 및 시스템 콜 경계 인터셉터 (C-ABI Dynamic Hooking & Syscall Boundary Interceptor)

단일 소스 기반 트레이싱 하네스이자, `LD_PRELOAD` / `DYLD_INSERT_LIBRARIES`를 통해 네이티브 POSIX C-ABI 경계 사이에 주입되는 결정론적 모킹 런타임입니다.

[English Documentation](README.md)

## 아키텍처

- 시스템 콜 경계 가로채기: `open`, `openat`, `connect`, `clock_gettime`을 가로채어 결정론적 샌드박싱 정책을 강제하고 커널 경계 진입을 감사(audit)합니다.
- 결정론적 시간 모킹: 시간 쿼리를 가로채 가상 스텝 기반 에포크(epoch)를 따라 전진시킴으로써 회귀 테스트 스위트의 플래키(flakiness) 현상과 레이스 컨디션을 제거합니다.
- 아웃바운드 네트워크 격리: 외부 소켓 연결 시도를 선별 차단하고 목적지 엔드포인트를 실시간으로 기록합니다.
- 일급 C 상호 운용성: Zig의 네이티브 C 호출 규약(`export fn`)을 사용하여 구축되었으며, Linux, macOS, Windows 전반에 걸쳐 동적 공유 라이브러리로 원활하게 컴파일됩니다.

## 내보낸 C-ABI 인터페이스

```c
void stibnite_configure(int32_t block_net, int32_t read_only, uint32_t tick_ms);
uint64_t stibnite_get_total_calls(void);
uint64_t stibnite_get_blocked_calls(void);
void stibnite_reset(void);

int32_t stibnite_intercept_connect(int32_t sockfd);
int32_t stibnite_intercept_clock_gettime(int64_t* out_sec, int64_t* out_nsec);
int32_t stibnite_intercept_open(const char* path, int32_t flags);
```

## 빌드 및 테스트

```bash
# 단위 테스트 실행
zig build test

# 네이티브 바이너리 및 인터포지션 공유 라이브러리 빌드
zig build -Doptimize=ReleaseFast
```

## 0.2.0 변경 사항

- 경로 정책 엔진: `.`, `..`, `//`를 어휘적으로 정규화한 뒤(가상 작업 디렉터리 기준) 글롭 규칙(`*`, `?`, 세그먼트 단위 `**`)을 적용합니다. 규칙은 read/write/any 접근별로 지정하며, 마지막으로 일치한 규칙이 결정합니다. 따라서 `/tmp/../etc/shadow`는 `/etc/shadow`로 판정됩니다.
- open 플래그를 ABI별(Linux, Darwin/BSD, Windows CRT)로 해석합니다. 0.1.0에서는 Linux의 `O_RDONLY|O_CREAT`를 읽기로 취급했는데, 이제 쓰기로 판정합니다.
- 네트워크 정책 엔진: 여러 커널의 `struct sockaddr` 레이아웃을 해석하고 CIDR/포트 규칙(`10.0.0.0/8`, `::1/128@8080`, `*@53`, `unix`)을 적용합니다. IPv4 매핑 IPv6 주소는 IPv4로 정규화합니다.
- 감사 로그: 최근 256건의 판정을 링 버퍼에 기록하며, `stibnite_audit_json`으로 JSON을 내보낼 수 있습니다(snprintf 방식).
- 새 C-ABI 함수(`stibnite_intercept_openat`, `stibnite_intercept_connect_addr`, `stibnite_add_path_rule`, `stibnite_add_net_rule` 등)와 헤더 `include/stibnite.h`를 추가했습니다. 기존 함수의 이름과 시그니처는 그대로이며, NULL 포인터를 넘기면 -1을 반환합니다. 모든 함수는 스핀락으로 직렬화됩니다.
- CLI: `stibnite eval --policy examples/ci.policy --trace examples/ci.trace [--json] [--fail-on-deny]`로 트레이스를 정책에 대입해 각 판정을 출력합니다. `--fail-on-deny`를 지정하면 거부된 호출이 있을 때 종료 코드 2를 반환합니다.
- 테스트: Zig 테스트 44개(속성, 차등, 퍼즈 방식 포함)와, 공유 라이브러리를 링크해 실행하는 C 테스트(`tests/abi_test.c`, 검사 54개)를 추가했습니다.

## 라이선스

MIT License - Copyright (c) 2026 Jeong Hoon Kim
