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

## 라이선스

MIT License - Copyright (c) 2026 Jeong Hoon Kim
