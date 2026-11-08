// Copyright (c) 2026 jk9576. All rights reserved.
// Stibnite: C-ABI Dynamic Hooking & Syscall Boundary Interceptor
// Licensed under the MIT License.

const std = @import("std");
pub const interceptor = @import("interceptor.zig");

pub fn main() !void {
    std.debug.print("Stibnite: Deterministic C-ABI Hooking & Syscall Interceptor Runtime.\n", .{});
    interceptor.stibnite_configure(1, 1, 10); // Block net, Read-only FS, 10ms ticks

    var s: i64 = 0;
    var ns: i64 = 0;
    _ = interceptor.stibnite_intercept_clock_gettime(&s, &ns);
    std.debug.print("Virtual Clock T0: {d}.{d:0>9}s\n", .{ s, ns });

    _ = interceptor.stibnite_intercept_clock_gettime(&s, &ns);
    std.debug.print("Virtual Clock T1: {d}.{d:0>9}s (+10ms deterministic step)\n", .{ s, ns });

    const net_res = interceptor.stibnite_intercept_connect(4);
    std.debug.print("Rogue Socket Connect Attempt: {s} (Total Blocked: {d})\n", .{
        if (net_res == 0) "ALLOWED" else "DENIED_BY_POLICY",
        interceptor.stibnite_get_blocked_calls(),
    });
}

test "Deterministic virtual time ticks advance predictably" {
    interceptor.stibnite_reset();
    interceptor.stibnite_configure(1, 0, 25); // 25ms per tick

    var s1: i64 = 0;
    var ns1: i64 = 0;
    _ = interceptor.stibnite_intercept_clock_gettime(&s1, &ns1);

    var s2: i64 = 0;
    var ns2: i64 = 0;
    _ = interceptor.stibnite_intercept_clock_gettime(&s2, &ns2);

    try std.testing.expectEqual(s1, s2);
    try std.testing.expectEqual(ns1 + 25 * std.time.ns_per_ms, ns2);
}

test "Policy blocks network connections when enabled" {
    interceptor.stibnite_reset();
    interceptor.stibnite_configure(1, 0, 10);
    try std.testing.expectEqual(@as(i32, -1), interceptor.stibnite_intercept_connect(5));
    try std.testing.expectEqual(@as(u64, 1), interceptor.stibnite_get_blocked_calls());

    interceptor.stibnite_configure(0, 0, 10); // Allow net
    try std.testing.expectEqual(@as(i32, 0), interceptor.stibnite_intercept_connect(5));
}

test "Policy blocks file write operations on read-only sandbox" {
    interceptor.stibnite_reset();
    interceptor.stibnite_configure(0, 1, 10); // Read-only FS enabled

    // Open read-only (flags = 0)
    try std.testing.expect(interceptor.stibnite_intercept_open("/etc/hosts", 0) >= 0);

    // Open write (flags = 1) -> Blocked
    try std.testing.expectEqual(@as(i32, -1), interceptor.stibnite_intercept_open("/var/log/rogue.log", 1));
    try std.testing.expectEqual(@as(u64, 1), interceptor.stibnite_get_blocked_calls());
}
