// Copyright (c) 2026 jk9576. All rights reserved.
// Stibnite: C-ABI Dynamic Hooking & Syscall Boundary Interceptor
// Licensed under the MIT License.

const std = @import("std");
pub const pathpolicy = @import("pathpolicy.zig");
pub const netpolicy = @import("netpolicy.zig");
pub const audit = @import("audit.zig");

pub const version = "0.2.0";

pub const AuditEvent = audit.AuditEvent;
pub const Reason = audit.Reason;

/// Fixed deterministic epoch: 2026-03-08T00:00:00Z.
pub const default_epoch_sec: u64 = 1772928000;
/// AT_FDCWD is -100 on Linux and FreeBSD and -2 on Darwin. Both are invalid
/// descriptors everywhere, so either is accepted as "relative to cwd".
pub const at_fdcwd_linux: i32 = -100;
pub const at_fdcwd_darwin: i32 = -2;

/// Simulated descriptor returned by allowed open/openat calls.
pub const simulated_fd: i32 = 3;

pub const HarnessState = struct {
    virtual_time_ns: u64,
    time_tick_ns: u64,
    block_network: bool,
    read_only_fs: bool,
    total_calls: u64,
    blocked_calls: u64,

    flag_abi: pathpolicy.FlagAbi = .native,
    sock_abi: netpolicy.SockAbi = .native,
    cwd: [pathpolicy.max_path]u8 = undefined,
    cwd_len: usize = 1,
    path_rules: pathpolicy.PathRules = .{},
    net_rules: netpolicy.NetRules = .{},
    ring: audit.Ring = .{},

    pub fn init() HarnessState {
        var s = HarnessState{
            .virtual_time_ns = default_epoch_sec * std.time.ns_per_s,
            .time_tick_ns = 10 * std.time.ns_per_ms, // 10ms tick per clock call
            .block_network = true, // Default strict hermetic sandbox
            .read_only_fs = false,
            .total_calls = 0,
            .blocked_calls = 0,
        };
        s.cwd[0] = '/';
        return s;
    }

    /// Restore the initial configuration in place (no large temporary copy).
    pub fn reset(self: *HarnessState) void {
        self.virtual_time_ns = default_epoch_sec * std.time.ns_per_s;
        self.time_tick_ns = 10 * std.time.ns_per_ms;
        self.block_network = true;
        self.read_only_fs = false;
        self.total_calls = 0;
        self.blocked_calls = 0;
        self.flag_abi = .native;
        self.sock_abi = .native;
        self.cwd[0] = '/';
        self.cwd_len = 1;
        self.path_rules.clear();
        self.net_rules.clear();
        self.ring.clear();
    }

    pub fn cwdSlice(self: *const HarnessState) []const u8 {
        return self.cwd[0..self.cwd_len];
    }

    pub fn setCwd(self: *HarnessState, path: []const u8) error{ RelativeCwd, InvalidPath }!void {
        if (path.len == 0 or path[0] != '/') return error.RelativeCwd;
        var buf: [pathpolicy.max_path]u8 = undefined;
        const canon = pathpolicy.canonicalize("/", path, &buf) catch return error.InvalidPath;
        @memcpy(self.cwd[0..canon.len], canon);
        self.cwd_len = canon.len;
    }

    /// Set the virtual clock to `sec` seconds since the Unix epoch.
    pub fn setEpoch(self: *HarnessState, sec: i64) error{OutOfRange}!void {
        if (sec < 0) return error.OutOfRange;
        self.virtual_time_ns = std.math.mul(u64, @intCast(sec), std.time.ns_per_s) catch return error.OutOfRange;
    }

    pub fn getVirtualTime(self: *HarnessState) u64 {
        const t = self.virtual_time_ns;
        // Saturate instead of wrapping so time never runs backwards.
        self.virtual_time_ns +|= self.time_tick_ns;
        self.total_calls += 1;
        return t;
    }

    fn finish(self: *HarnessState, ev: *AuditEvent) void {
        self.total_calls += 1;
        if (!ev.allowed) self.blocked_calls += 1;
        ev.seq = self.ring.push(ev.*);
    }

    fn deny(ev: *AuditEvent, reason: Reason) void {
        ev.allowed = false;
        ev.reason = reason;
    }

    /// Decide an open(2) / openat(2). `path` is null when the caller passed a
    /// NULL pointer. `dirfd` is null for open(2).
    pub fn decideOpen(self: *HarnessState, path: ?[]const u8, flags: i32, dirfd: ?i32) AuditEvent {
        var ev = self.judgeOpen(path, flags, dirfd);
        self.finish(&ev);
        return ev;
    }

    fn judgeOpen(self: *const HarnessState, path: ?[]const u8, flags: i32, dirfd: ?i32) AuditEvent {
        var ev = AuditEvent.init(if (dirfd == null) .open else .openat, self.virtual_time_ns);
        ev.intent = pathpolicy.classifyFlags(self.flag_abi, flags);
        const p = path orelse {
            ev.setTarget("(null)");
            deny(&ev, .invalid_argument);
            return ev;
        };
        if (dirfd) |fd| {
            if (p.len > 0 and p[0] != '/' and fd != at_fdcwd_linux and fd != at_fdcwd_darwin) {
                var tmp: [audit.max_target]u8 = undefined;
                ev.setTarget(std.fmt.bufPrint(&tmp, "fd:{d}/{s}", .{ fd, p[0..@min(p.len, 200)] }) catch "fd:?");
                deny(&ev, .unresolved_dirfd);
                return ev;
            }
        }
        var buf: [pathpolicy.max_path]u8 = undefined;
        const canon = pathpolicy.canonicalize(self.cwdSlice(), p, &buf) catch |err| {
            ev.setTarget(p);
            deny(&ev, if (err == error.NameTooLong) .path_too_long else .invalid_argument);
            return ev;
        };
        ev.setTarget(canon);
        const is_write = ev.intent.isWrite();
        if (self.path_rules.evaluate(canon, is_write)) |m| {
            ev.rule = @intCast(m.index);
            ev.reason = .rule;
            ev.allowed = m.effect == .allow;
            return ev;
        }
        if (self.read_only_fs and is_write) deny(&ev, .read_only_fs);
        return ev;
    }

    /// Decide a connect(2) given the raw sockaddr bytes (null for NULL).
    pub fn decideConnect(self: *HarnessState, sockfd: i32, addr: ?[]const u8) AuditEvent {
        var ev = self.judgeConnect(sockfd, addr);
        self.finish(&ev);
        return ev;
    }

    fn judgeConnect(self: *const HarnessState, sockfd: i32, addr: ?[]const u8) AuditEvent {
        var ev = AuditEvent.init(.connect, self.virtual_time_ns);
        const bytes = addr orelse {
            var tmp: [32]u8 = undefined;
            ev.setTarget(std.fmt.bufPrint(&tmp, "fd:{d}", .{sockfd}) catch "fd:?");
            deny(&ev, .invalid_argument);
            return ev;
        };
        const ep = netpolicy.decodeSockaddr(self.sock_abi, bytes) catch {
            var tmp: [32]u8 = undefined;
            ev.setTarget(std.fmt.bufPrint(&tmp, "fd:{d}", .{sockfd}) catch "fd:?");
            deny(&ev, .unsupported_address);
            return ev;
        };
        var tmp: [audit.max_target]u8 = undefined;
        var w = std.Io.Writer.fixed(&tmp);
        ep.format(&w) catch {};
        ev.setTarget(w.buffered());
        if (self.net_rules.evaluate(ep)) |m| {
            ev.rule = @intCast(m.index);
            ev.reason = .rule;
            ev.allowed = m.effect == .allow;
            return ev;
        }
        if (self.block_network) deny(&ev, .network_blocked);
        return ev;
    }

    /// Legacy connect decision without a destination address: only the
    /// global block-network switch applies.
    pub fn auditConnect(self: *HarnessState, fd: i32) bool {
        var ev = AuditEvent.init(.connect, self.virtual_time_ns);
        var tmp: [32]u8 = undefined;
        ev.setTarget(std.fmt.bufPrint(&tmp, "fd:{d}", .{fd}) catch "fd:?");
        if (self.block_network) deny(&ev, .network_blocked);
        self.finish(&ev);
        return ev.allowed;
    }

    pub fn auditOpen(self: *HarnessState, path: []const u8, flags: i32) bool {
        return self.decideOpen(path, flags, null).allowed;
    }
};

// Global harness state for interposition, guarded by a spinlock so that
// multi-threaded hosts cannot tear counters, rules or the audit ring.
pub var global_state = HarnessState.init();
var state_lock = std.atomic.Value(u32).init(0);

fn lock() *HarnessState {
    while (state_lock.cmpxchgWeak(0, 1, .acquire, .monotonic) != null) std.atomic.spinLoopHint();
    return &global_state;
}

fn unlock() void {
    state_lock.store(0, .release);
}

fn cspan(p: ?[*:0]const u8) ?[]const u8 {
    return if (p) |ptr| std.mem.span(ptr) else null;
}

pub export fn stibnite_configure(block_net: i32, read_only: i32, tick_ms: u32) void {
    const s = lock();
    defer unlock();
    s.block_network = (block_net != 0);
    s.read_only_fs = (read_only != 0);
    s.time_tick_ns = @as(u64, tick_ms) * std.time.ns_per_ms;
}

pub export fn stibnite_get_total_calls() u64 {
    const s = lock();
    defer unlock();
    return s.total_calls;
}

pub export fn stibnite_get_blocked_calls() u64 {
    const s = lock();
    defer unlock();
    return s.blocked_calls;
}

pub export fn stibnite_reset() void {
    const s = lock();
    defer unlock();
    s.reset();
}

// C-ABI Intercepted symbols (POSIX standard signatures)

pub export fn stibnite_intercept_connect(sockfd: i32) i32 {
    const s = lock();
    defer unlock();
    return if (s.auditConnect(sockfd)) 0 else -1;
}

/// Returns 0 and the virtual time, or -1 (EFAULT) when either pointer is NULL.
pub export fn stibnite_intercept_clock_gettime(out_sec: ?*i64, out_nsec: ?*i64) i32 {
    const sec_ptr = out_sec orelse return -1;
    const nsec_ptr = out_nsec orelse return -1;
    const s = lock();
    defer unlock();
    const vt = s.getVirtualTime();
    sec_ptr.* = @intCast(vt / std.time.ns_per_s);
    nsec_ptr.* = @intCast(vt % std.time.ns_per_s);
    return 0;
}

pub export fn stibnite_intercept_open(path_ptr: ?[*:0]const u8, flags: i32) i32 {
    const s = lock();
    defer unlock();
    return if (s.decideOpen(cspan(path_ptr), flags, null).allowed) simulated_fd else -1;
}

// ---- 0.2.0 additions -------------------------------------------------------

pub export fn stibnite_version() [*:0]const u8 {
    return version;
}

pub export fn stibnite_intercept_openat(dirfd: i32, path_ptr: ?[*:0]const u8, flags: i32) i32 {
    const s = lock();
    defer unlock();
    return if (s.decideOpen(cspan(path_ptr), flags, dirfd).allowed) simulated_fd else -1;
}

/// connect(2) with the destination address: path through the CIDR / port
/// rules. Returns 0 when allowed, -1 when denied or the address is invalid.
pub export fn stibnite_intercept_connect_addr(sockfd: i32, addr: ?*const anyopaque, addrlen: u32) i32 {
    const bytes: ?[]const u8 = if (addr) |a| @as([*]const u8, @ptrCast(a))[0..addrlen] else null;
    const s = lock();
    defer unlock();
    return if (s.decideConnect(sockfd, bytes).allowed) 0 else -1;
}

/// Append a path rule. `allow` != 0 allows, 0 denies. `access`: 1 read,
/// 2 write, 3 any. Returns the rule index or -1 on an invalid pattern,
/// invalid access value or a full rule table.
pub export fn stibnite_add_path_rule(pattern: ?[*:0]const u8, allow: i32, access: i32) i32 {
    const pat = cspan(pattern) orelse return -1;
    const acc: pathpolicy.Access = switch (access) {
        1 => .read,
        2 => .write,
        3 => .any,
        else => return -1,
    };
    const s = lock();
    defer unlock();
    const idx = s.path_rules.add(pat, if (allow != 0) .allow else .deny, acc) catch return -1;
    return @intCast(idx);
}

pub export fn stibnite_clear_path_rules() void {
    const s = lock();
    defer unlock();
    s.path_rules.clear();
}

/// Append a network rule ("10.0.0.0/8", "::1/128@8080", "*@53", "unix").
/// Returns the rule index or -1 on a malformed rule or a full table.
pub export fn stibnite_add_net_rule(rule: ?[*:0]const u8, allow: i32) i32 {
    const text = cspan(rule) orelse return -1;
    const parsed = netpolicy.parseNetRule(text, if (allow != 0) .allow else .deny) catch return -1;
    const s = lock();
    defer unlock();
    const idx = s.net_rules.add(parsed) catch return -1;
    return @intCast(idx);
}

pub export fn stibnite_clear_net_rules() void {
    const s = lock();
    defer unlock();
    s.net_rules.clear();
}

/// Set the virtual working directory used to resolve relative paths.
/// Returns 0, or -1 if the path is NULL, relative or too long.
pub export fn stibnite_set_cwd(path: ?[*:0]const u8) i32 {
    const p = cspan(path) orelse return -1;
    const s = lock();
    defer unlock();
    s.setCwd(p) catch return -1;
    return 0;
}

/// Set the virtual clock to `sec` seconds since the Unix epoch. Returns 0,
/// or -1 if `sec` is negative or does not fit in 64-bit nanoseconds.
pub export fn stibnite_set_epoch(sec: i64) i32 {
    const s = lock();
    defer unlock();
    s.setEpoch(sec) catch return -1;
    return 0;
}

/// Number of decisions recorded since the last reset or audit clear,
/// including those the ring has since overwritten.
pub export fn stibnite_audit_count() u64 {
    const s = lock();
    defer unlock();
    return s.ring.total;
}

/// Render the retained audit events as JSON into `buf` (snprintf
/// semantics: at most `len - 1` bytes plus NUL). Returns the full length
/// required, excluding the NUL. Pass NULL / 0 to query the size.
pub export fn stibnite_audit_json(buf: ?[*]u8, len: usize) usize {
    const s = lock();
    defer unlock();
    const out: []u8 = if (buf) |b| b[0..len] else &.{};
    return s.ring.exportJson(out);
}

pub export fn stibnite_audit_clear() void {
    const s = lock();
    defer unlock();
    s.ring.clear();
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "open rules override read-only mode and record the deciding rule" {
    var s = HarnessState.init();
    s.flag_abi = .linux;
    s.read_only_fs = true;
    _ = try s.path_rules.add("/tmp/**", .allow, .write);
    _ = try s.path_rules.add("/etc/shadow", .deny, .any);
    const w = try pathpolicy.encodeFlags(.linux, "O_WRONLY|O_CREAT");
    try testing.expect(s.decideOpen("/tmp/out.log", w, null).allowed);
    const ev = s.decideOpen("/var/log/x", w, null);
    try testing.expect(!ev.allowed);
    try testing.expectEqual(Reason.read_only_fs, ev.reason);
    const shadow = s.decideOpen("/tmp/../etc/./shadow", 0, null);
    try testing.expect(!shadow.allowed);
    try testing.expectEqual(@as(i32, 1), shadow.rule);
    try testing.expectEqualStrings("/etc/shadow", shadow.targetSlice());
    try testing.expectEqual(@as(u64, 3), s.total_calls);
    try testing.expectEqual(@as(u64, 2), s.blocked_calls);
    // Returned events carry the same sequence number as the ring copy.
    try testing.expectEqual(@as(u64, 3), shadow.seq);
    try testing.expectEqual(@as(u64, 3), s.ring.get(2).seq);
}

test "Linux O_RDONLY|O_CREAT is a write (0.1.0 missed this)" {
    var s = HarnessState.init();
    s.flag_abi = .linux;
    s.read_only_fs = true;
    const ev = s.decideOpen("/data/new", 0o100, null);
    try testing.expect(!ev.allowed);
    try testing.expect(ev.intent.create);
}

test "openat resolves AT_FDCWD against the virtual cwd and fails closed otherwise" {
    var s = HarnessState.init();
    try s.setCwd("/home/ci/proj");
    _ = try s.path_rules.add("/home/ci/proj/**", .allow, .any);
    _ = try s.path_rules.add("/home/ci/proj/.git/**", .deny, .write);
    try testing.expect(s.decideOpen("src/a.zig", 1, at_fdcwd_linux).allowed);
    try testing.expect(s.decideOpen("src/a.zig", 1, at_fdcwd_darwin).allowed);
    const git = s.decideOpen(".git/config", 1, at_fdcwd_linux);
    try testing.expect(!git.allowed);
    try testing.expectEqualStrings("/home/ci/proj/.git/config", git.targetSlice());
    const unresolved = s.decideOpen("x", 0, 7);
    try testing.expectEqual(Reason.unresolved_dirfd, unresolved.reason);
    try testing.expectEqualStrings("fd:7/x", unresolved.targetSlice());
    // Absolute paths ignore dirfd, as in POSIX.
    try testing.expect(s.decideOpen("/home/ci/proj/a", 0, 7).allowed);
}

test "hostile open arguments are denied, never crash" {
    var s = HarnessState.init();
    try testing.expectEqual(Reason.invalid_argument, s.decideOpen(null, 0, null).reason);
    try testing.expectEqual(Reason.invalid_argument, s.decideOpen("", 0, null).reason);
    const long: [pathpolicy.max_path + 10]u8 = @splat('a');
    const ev = s.decideOpen(&long, 0, null);
    try testing.expectEqual(Reason.path_too_long, ev.reason);
    try testing.expect(ev.target_truncated);
    try testing.expectEqual(@as(u64, 3), s.blocked_calls);
}

test "connect rules: allow loopback and DNS, deny the rest" {
    var s = HarnessState.init();
    s.sock_abi = netpolicy.SockAbi.linux;
    _ = try s.net_rules.add(try netpolicy.parseNetRule("127.0.0.0/8", .allow));
    _ = try s.net_rules.add(try netpolicy.parseNetRule("*@53", .allow));
    var raw: [128]u8 = undefined;
    const cases = [_]struct { ep: []const u8, allowed: bool, reason: Reason }{
        .{ .ep = "127.0.0.1:8080", .allowed = true, .reason = .rule },
        .{ .ep = "1.1.1.1:53", .allowed = true, .reason = .rule },
        .{ .ep = "1.1.1.1:443", .allowed = false, .reason = .network_blocked },
        .{ .ep = "[::ffff:127.0.0.1]:22", .allowed = true, .reason = .rule },
        .{ .ep = "unix:/run/docker.sock", .allowed = false, .reason = .network_blocked },
    };
    for (cases) |c| {
        const n = try netpolicy.encodeSockaddr(s.sock_abi, try netpolicy.parseEndpoint(c.ep), &raw);
        const ev = s.decideConnect(4, raw[0..n]);
        try testing.expectEqual(c.allowed, ev.allowed);
        try testing.expectEqual(c.reason, ev.reason);
    }
    try testing.expectEqual(Reason.invalid_argument, s.decideConnect(4, null).reason);
    // A truncated AF_INET address (addrlen shorter than sockaddr_in).
    const n4 = try netpolicy.encodeSockaddr(s.sock_abi, try netpolicy.parseEndpoint("127.0.0.1:80"), &raw);
    try testing.expectEqual(Reason.unsupported_address, s.decideConnect(4, raw[0 .. n4 - 1]).reason);
    s.block_network = false;
    try testing.expect(s.decideConnect(4, raw[0..try netpolicy.encodeSockaddr(s.sock_abi, try netpolicy.parseEndpoint("9.9.9.9:443"), &raw)]).allowed);
}

test "epoch and clock saturation" {
    var s = HarnessState.init();
    try s.setEpoch(0);
    try testing.expectEqual(@as(u64, 0), s.getVirtualTime());
    try testing.expectError(error.OutOfRange, s.setEpoch(-1));
    try testing.expectError(error.OutOfRange, s.setEpoch(std.math.maxInt(i64)));
    s.virtual_time_ns = std.math.maxInt(u64) - 1;
    _ = s.getVirtualTime();
    try testing.expectEqual(std.math.maxInt(u64), s.getVirtualTime());
    try testing.expectEqual(std.math.maxInt(u64), s.virtual_time_ns);
}

test "C-ABI surface: legacy and new exports through the global state" {
    stibnite_reset();
    defer stibnite_reset();
    try testing.expectEqualStrings(version, std.mem.span(stibnite_version()));
    try testing.expectEqual(@as(i32, -1), stibnite_intercept_clock_gettime(null, null));
    try testing.expectEqual(@as(i32, -1), stibnite_intercept_open(null, 0));
    try testing.expectEqual(@as(i32, 0), stibnite_add_path_rule("/secret/**", 0, 3));
    try testing.expectEqual(@as(i32, -1), stibnite_add_path_rule("relative", 0, 3));
    try testing.expectEqual(@as(i32, -1), stibnite_add_path_rule("/x", 0, 9));
    try testing.expectEqual(@as(i32, -1), stibnite_intercept_open("/secret/key", 0));
    try testing.expectEqual(simulated_fd, stibnite_intercept_openat(at_fdcwd_linux, "/pub", 0));
    try testing.expectEqual(@as(i32, 0), stibnite_add_net_rule("10.0.0.0/8", 1));
    try testing.expectEqual(@as(i32, -1), stibnite_add_net_rule("10.0.0.0/99", 1));
    var raw: [32]u8 = undefined;
    const n = try netpolicy.encodeSockaddr(.native, try netpolicy.parseEndpoint("10.2.3.4:80"), &raw);
    try testing.expectEqual(@as(i32, 0), stibnite_intercept_connect_addr(5, &raw, @intCast(n)));
    try testing.expectEqual(@as(i32, -1), stibnite_intercept_connect_addr(5, null, 0));
    try testing.expectEqual(@as(i32, -1), stibnite_set_cwd("relative"));
    try testing.expectEqual(@as(i32, 0), stibnite_set_cwd("/srv"));
    try testing.expectEqual(@as(i32, -1), stibnite_intercept_open("../secret/x", 0));
    try testing.expectEqual(@as(u64, 6), stibnite_audit_count());
    const needed = stibnite_audit_json(null, 0);
    const buf = try testing.allocator.alloc(u8, needed + 1);
    defer testing.allocator.free(buf);
    try testing.expectEqual(needed, stibnite_audit_json(buf.ptr, buf.len));
    try testing.expect(try std.json.validate(testing.allocator, buf[0..needed]));
    try testing.expect(std.mem.find(u8, buf[0..needed], "\"target\":\"/secret/x\"") != null);
    stibnite_audit_clear();
    try testing.expectEqual(@as(u64, 0), stibnite_audit_count());
    stibnite_clear_path_rules();
    try testing.expectEqual(simulated_fd, stibnite_intercept_open("/secret/key", 0));
    stibnite_clear_net_rules();
    try testing.expectEqual(@as(i32, -1), stibnite_intercept_connect_addr(5, &raw, @intCast(n)));
    try testing.expectEqual(@as(i32, 0), stibnite_set_epoch(0));
    var sec: i64 = 1;
    var nsec: i64 = 1;
    try testing.expectEqual(@as(i32, 0), stibnite_intercept_clock_gettime(&sec, &nsec));
    try testing.expectEqual(@as(i64, 0), sec);
    try testing.expectEqual(@as(i64, 0), nsec);
}

test "concurrent callers keep counters consistent" {
    stibnite_reset();
    defer stibnite_reset();
    const per_thread = 2000;
    const Worker = struct {
        fn run() void {
            for (0..per_thread) |i| {
                if (i % 2 == 0) {
                    _ = stibnite_intercept_connect(3);
                } else {
                    var a: i64 = 0;
                    var b: i64 = 0;
                    _ = stibnite_intercept_clock_gettime(&a, &b);
                }
            }
        }
    };
    var threads: [4]std.Thread = undefined;
    for (&threads) |*t| t.* = try std.Thread.spawn(.{}, Worker.run, .{});
    for (threads) |t| t.join();
    try testing.expectEqual(@as(u64, 4 * per_thread), stibnite_get_total_calls());
    try testing.expectEqual(@as(u64, 4 * per_thread / 2), stibnite_get_blocked_calls());
    try testing.expectEqual(@as(u64, 4 * per_thread / 2), stibnite_audit_count());
}
