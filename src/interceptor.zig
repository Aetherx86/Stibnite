// Copyright (c) 2026 jk9576. All rights reserved.
// Stibnite: C-ABI Dynamic Hooking & Syscall Boundary Interceptor
// Licensed under the MIT License.

const std = @import("std");

pub const AuditEvent = struct {
    syscall: []const u8,
    target: [256]u8,
    target_len: usize,
    allowed: bool,
    timestamp_ns: u64,
};

pub const HarnessState = struct {
    virtual_time_ns: u64,
    time_tick_ns: u64,
    block_network: bool,
    read_only_fs: bool,
    total_calls: u64,
    blocked_calls: u64,

    pub fn init() HarnessState {
        return HarnessState{
            .virtual_time_ns = 1772928000 * std.time.ns_per_s, // Fixed deterministic epoch: 2026-03-08T00:00:00Z
            .time_tick_ns = 10 * std.time.ns_per_ms, // 10ms tick per clock call
            .block_network = true, // Default strict hermetic sandbox
            .read_only_fs = false,
            .total_calls = 0,
            .blocked_calls = 0,
        };
    }

    pub fn getVirtualTime(self: *HarnessState) u64 {
        const t = self.virtual_time_ns;
        self.virtual_time_ns += self.time_tick_ns;
        self.total_calls += 1;
        return t;
    }

    pub fn auditConnect(self: *HarnessState, fd: i32) bool {
        _ = fd;
        self.total_calls += 1;
        if (self.block_network) {
            self.blocked_calls += 1;
            return false;
        }
        return true;
    }

    pub fn auditOpen(self: *HarnessState, path: []const u8, flags: i32) bool {
        self.total_calls += 1;
        // O_WRONLY = 0x0001, O_RDWR = 0x0002, O_CREAT = 0x0200
        const is_write = (flags & 0x0003) != 0 or (flags & 0x0200) != 0;
        if (self.read_only_fs and is_write) {
            self.blocked_calls += 1;
            return false;
        }
        _ = path;
        return true;
    }
};

// Global harness state for interposition
pub var global_state = HarnessState.init();

pub export fn stibnite_configure(block_net: i32, read_only: i32, tick_ms: u32) void {
    global_state.block_network = (block_net != 0);
    global_state.read_only_fs = (read_only != 0);
    global_state.time_tick_ns = @as(u64, tick_ms) * std.time.ns_per_ms;
}

pub export fn stibnite_get_total_calls() u64 {
    return global_state.total_calls;
}

pub export fn stibnite_get_blocked_calls() u64 {
    return global_state.blocked_calls;
}

pub export fn stibnite_reset() void {
    global_state = HarnessState.init();
}

// C-ABI Intercepted symbols (POSIX standard signatures)

pub export fn stibnite_intercept_connect(sockfd: i32) i32 {
    if (!global_state.auditConnect(sockfd)) {
        // Return ECONNREFUSED or EPERM
        return -1;
    }
    return 0;
}

pub export fn stibnite_intercept_clock_gettime(out_sec: *i64, out_nsec: *i64) i32 {
    const vt = global_state.getVirtualTime();
    out_sec.* = @intCast(vt / std.time.ns_per_s);
    out_nsec.* = @intCast(vt % std.time.ns_per_s);
    return 0;
}

pub export fn stibnite_intercept_open(path_ptr: [*:0]const u8, flags: i32) i32 {
    const path = std.mem.span(path_ptr);
    if (!global_state.auditOpen(path, flags)) {
        return -1; // EACCES / EROFS
    }
    return 3; // Simulated valid file descriptor
}
