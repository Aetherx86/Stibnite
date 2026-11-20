// Copyright (c) 2026 jk9576. All rights reserved.
// Stibnite: C-ABI Dynamic Hooking & Syscall Boundary Interceptor
// Licensed under the MIT License.
//
// Text formats used by `stibnite eval`: a policy file that configures a
// HarnessState, and a trace file of syscalls replayed against it.

const std = @import("std");
const interceptor = @import("interceptor.zig");
const pathpolicy = interceptor.pathpolicy;
const netpolicy = interceptor.netpolicy;
const audit = interceptor.audit;

pub const Diag = struct {
    line: usize = 0,
    message: []const u8 = "",
};

pub const ScriptError = error{Invalid};

fn fail(diag: *Diag, line: usize, message: []const u8) ScriptError {
    diag.line = line;
    diag.message = message;
    return error.Invalid;
}

const LineIter = struct {
    it: std.mem.SplitIterator(u8, .scalar),
    number: usize = 0,

    fn init(text: []const u8) LineIter {
        return .{ .it = std.mem.splitScalar(u8, text, '\n') };
    }

    /// Next non-blank, non-comment line split into whitespace tokens.
    fn next(self: *LineIter, tokens: *[8][]const u8) ?[]const []const u8 {
        while (self.it.next()) |raw| {
            self.number += 1;
            const line = std.mem.trim(u8, raw, " \t\r");
            if (line.len == 0 or line[0] == '#') continue;
            var n: usize = 0;
            var tok = std.mem.tokenizeAny(u8, line, " \t");
            while (tok.next()) |t| {
                if (n == tokens.len) return tokens[0..0]; // signals "too many tokens"
                tokens[n] = t;
                n += 1;
            }
            return tokens[0..n];
        }
        return null;
    }
};

/// Apply a policy file to `state`. Directives, one per line (`#` comments):
///   network allow|deny                  default for connect(2)
///   filesystem read-only|read-write     default for write-intent opens
///   tick-ms N                           virtual clock step per clock_gettime
///   epoch SECONDS                       virtual clock start
///   cwd /abs/path                       base for relative paths
///   abi linux|darwin|freebsd|openbsd|windows
///   allow|deny read|write|any PATTERN   path rule (last match wins)
///   net allow|deny RULE                 network rule (last match wins)
pub fn applyPolicy(state: *interceptor.HarnessState, text: []const u8, diag: *Diag) ScriptError!void {
    var lines = LineIter.init(text);
    var tokens: [8][]const u8 = undefined;
    while (lines.next(&tokens)) |t| {
        const ln = lines.number;
        if (t.len == 0) return fail(diag, ln, "too many tokens");
        const d = t[0];
        if (std.mem.eql(u8, d, "network")) {
            if (t.len != 2) return fail(diag, ln, "usage: network allow|deny");
            if (std.mem.eql(u8, t[1], "allow")) state.block_network = false else if (std.mem.eql(u8, t[1], "deny")) state.block_network = true else return fail(diag, ln, "network expects allow or deny");
        } else if (std.mem.eql(u8, d, "filesystem")) {
            if (t.len != 2) return fail(diag, ln, "usage: filesystem read-only|read-write");
            if (std.mem.eql(u8, t[1], "read-only")) state.read_only_fs = true else if (std.mem.eql(u8, t[1], "read-write")) state.read_only_fs = false else return fail(diag, ln, "filesystem expects read-only or read-write");
        } else if (std.mem.eql(u8, d, "tick-ms")) {
            if (t.len != 2) return fail(diag, ln, "usage: tick-ms N");
            const ms = std.fmt.parseInt(u32, t[1], 10) catch return fail(diag, ln, "tick-ms expects an integer 0..4294967295");
            state.time_tick_ns = @as(u64, ms) * std.time.ns_per_ms;
        } else if (std.mem.eql(u8, d, "epoch")) {
            if (t.len != 2) return fail(diag, ln, "usage: epoch SECONDS");
            const sec = std.fmt.parseInt(i64, t[1], 10) catch return fail(diag, ln, "epoch expects an integer");
            state.setEpoch(sec) catch return fail(diag, ln, "epoch out of range");
        } else if (std.mem.eql(u8, d, "cwd")) {
            if (t.len != 2) return fail(diag, ln, "usage: cwd /absolute/path");
            state.setCwd(t[1]) catch return fail(diag, ln, "cwd must be an absolute path shorter than PATH_MAX");
        } else if (std.mem.eql(u8, d, "abi")) {
            if (t.len != 2) return fail(diag, ln, "usage: abi linux|darwin|freebsd|openbsd|windows");
            const sock = netpolicy.SockAbi.parse(t[1]) orelse return fail(diag, ln, "unknown abi");
            state.sock_abi = sock;
            state.flag_abi = if (std.mem.eql(u8, sock.name, "linux")) .linux else if (std.mem.eql(u8, sock.name, "windows")) .windows else .bsd;
        } else if (std.mem.eql(u8, d, "allow") or std.mem.eql(u8, d, "deny")) {
            if (t.len != 3) return fail(diag, ln, "usage: allow|deny read|write|any PATTERN");
            const access = pathpolicy.Access.parse(t[1]) orelse return fail(diag, ln, "access must be read, write or any");
            const effect: pathpolicy.Effect = if (d[0] == 'a') .allow else .deny;
            _ = state.path_rules.add(t[2], effect, access) catch |err| return fail(diag, ln, switch (err) {
                error.RelativePattern => "path pattern must be absolute",
                error.TooManyRules => "too many path rules (limit 64)",
                error.PatternTooLong => "path pattern longer than 255 bytes",
                else => "invalid path pattern",
            });
        } else if (std.mem.eql(u8, d, "net")) {
            if (t.len != 3) return fail(diag, ln, "usage: net allow|deny RULE");
            const effect: pathpolicy.Effect = if (std.mem.eql(u8, t[1], "allow")) .allow else if (std.mem.eql(u8, t[1], "deny")) .deny else return fail(diag, ln, "net expects allow or deny");
            const rule = netpolicy.parseNetRule(t[2], effect) catch return fail(diag, ln, "invalid network rule (expected CIDR[@port], *[@port] or unix)");
            _ = state.net_rules.add(rule) catch return fail(diag, ln, "too many network rules (limit 64)");
        } else {
            return fail(diag, ln, "unknown directive");
        }
    }
}

pub const Step = struct {
    line: usize,
    event: audit.AuditEvent,
};

/// Replay a trace against `state`. Lines (`#` comments):
///   open PATH [FLAGS]
///   openat DIRFD|AT_FDCWD PATH [FLAGS]
///   connect ADDR:PORT | [V6]:PORT | unix:/path | unix:@abstract
///   connect-fd FD                       legacy connect without an address
///   clock
/// FLAGS is `O_RDONLY|O_CREAT|...` in the policy's abi, or a number.
pub fn runTrace(
    gpa: std.mem.Allocator,
    state: *interceptor.HarnessState,
    text: []const u8,
    steps: *std.ArrayList(Step),
    diag: *Diag,
) (ScriptError || std.mem.Allocator.Error)!void {
    var lines = LineIter.init(text);
    var tokens: [8][]const u8 = undefined;
    while (lines.next(&tokens)) |t| {
        const ln = lines.number;
        if (t.len == 0) return fail(diag, ln, "too many tokens");
        const op = t[0];
        var ev: audit.AuditEvent = undefined;
        if (std.mem.eql(u8, op, "open")) {
            if (t.len < 2 or t.len > 3) return fail(diag, ln, "usage: open PATH [FLAGS]");
            const flags = try parseFlags(state, if (t.len == 3) t[2] else "O_RDONLY", diag, ln);
            ev = state.decideOpen(t[1], flags, null);
        } else if (std.mem.eql(u8, op, "openat")) {
            if (t.len < 3 or t.len > 4) return fail(diag, ln, "usage: openat DIRFD|AT_FDCWD PATH [FLAGS]");
            const dirfd: i32 = if (std.mem.eql(u8, t[1], "AT_FDCWD"))
                (if (std.mem.eql(u8, state.sock_abi.name, "darwin")) interceptor.at_fdcwd_darwin else interceptor.at_fdcwd_linux)
            else
                std.fmt.parseInt(i32, t[1], 10) catch return fail(diag, ln, "dirfd must be an integer or AT_FDCWD");
            const flags = try parseFlags(state, if (t.len == 4) t[3] else "O_RDONLY", diag, ln);
            ev = state.decideOpen(t[2], flags, dirfd);
        } else if (std.mem.eql(u8, op, "connect")) {
            if (t.len != 2) return fail(diag, ln, "usage: connect ENDPOINT");
            const ep = netpolicy.parseEndpoint(t[1]) catch return fail(diag, ln, "invalid endpoint (expected a.b.c.d:port, [v6]:port or unix:/path)");
            var raw: [128]u8 = undefined;
            const n = netpolicy.encodeSockaddr(state.sock_abi, ep, &raw) catch return fail(diag, ln, "endpoint does not fit in a sockaddr");
            ev = state.decideConnect(3, raw[0..n]);
        } else if (std.mem.eql(u8, op, "connect-fd")) {
            if (t.len != 2) return fail(diag, ln, "usage: connect-fd FD");
            const fd = std.fmt.parseInt(i32, t[1], 10) catch return fail(diag, ln, "fd must be an integer");
            const allowed = state.auditConnect(fd);
            ev = state.ring.get(state.ring.retained() - 1).*;
            std.debug.assert(ev.allowed == allowed);
        } else if (std.mem.eql(u8, op, "clock")) {
            if (t.len != 1) return fail(diag, ln, "usage: clock");
            const now = state.getVirtualTime();
            ev = audit.AuditEvent.init(.clock_gettime, now);
            ev.seq = 0;
        } else {
            return fail(diag, ln, "unknown trace operation");
        }
        try steps.append(gpa, .{ .line = ln, .event = ev });
    }
}

fn parseFlags(state: *const interceptor.HarnessState, text: []const u8, diag: *Diag, ln: usize) ScriptError!i32 {
    return pathpolicy.encodeFlags(state.flag_abi, text) catch |err| fail(diag, ln, switch (err) {
        error.UnknownFlag => "unknown open flag (O_RDONLY, O_WRONLY, O_RDWR, O_CREAT, O_TRUNC, O_APPEND, O_EXCL, O_TMPFILE)",
        error.InvalidNumber => "invalid numeric flags",
    });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

const sample_policy =
    \\# CI sandbox
    \\abi linux
    \\network deny
    \\filesystem read-only
    \\tick-ms 5
    \\epoch 1700000000
    \\cwd /home/ci/proj
    \\allow write /tmp/**
    \\deny any /home/*/.ssh/**
    \\net allow 127.0.0.0/8
    \\net allow *@53
;

const sample_trace =
    \\open /etc/hosts
    \\open /tmp/out.log O_WRONLY|O_CREAT|O_TRUNC
    \\open build/cache.bin O_RDONLY|O_CREAT
    \\openat AT_FDCWD ../../ci/.ssh/id_ed25519
    \\connect 127.0.0.1:5432
    \\connect 93.184.216.34:443
    \\connect [2001:4860:4860::8888]:53
    \\clock
    \\clock
;

test "policy and trace end to end" {
    var state = interceptor.HarnessState.init();
    var diag: Diag = .{};
    try applyPolicy(&state, sample_policy, &diag);
    try testing.expect(state.read_only_fs and state.block_network);
    try testing.expectEqual(@as(usize, 2), state.path_rules.count);
    var steps: std.ArrayList(Step) = .empty;
    defer steps.deinit(testing.allocator);
    try runTrace(testing.allocator, &state, sample_trace, &steps, &diag);
    const want = [_]bool{ true, true, false, false, true, false, true, true, true };
    try testing.expectEqual(want.len, steps.items.len);
    for (want, steps.items) |w, s| try testing.expectEqual(w, s.event.allowed);
    try testing.expectEqualStrings("/home/ci/proj/build/cache.bin", steps.items[2].event.targetSlice());
    try testing.expectEqual(audit.Reason.read_only_fs, steps.items[2].event.reason);
    try testing.expectEqualStrings("/home/ci/.ssh/id_ed25519", steps.items[3].event.targetSlice());
    try testing.expectEqual(@as(i32, 1), steps.items[3].event.rule);
    try testing.expectEqual(@as(u64, 1700000000 * std.time.ns_per_s), steps.items[7].event.timestamp_ns);
    try testing.expectEqual(@as(u64, 1700000000 * std.time.ns_per_s + 5 * std.time.ns_per_ms), steps.items[8].event.timestamp_ns);
    try testing.expectEqual(@as(u64, 3), state.blocked_calls);
}

test "policy errors carry line numbers" {
    const bad = [_]struct { text: []const u8, line: usize }{
        .{ .text = "network maybe", .line = 1 },
        .{ .text = "\n\n# c\nallow read relative/*", .line = 4 },
        .{ .text = "net allow 10.0.0.0/40", .line = 1 },
        .{ .text = "tick-ms -1", .line = 1 },
        .{ .text = "abi plan9", .line = 1 },
        .{ .text = "cwd rel", .line = 1 },
        .{ .text = "epoch -5", .line = 1 },
        .{ .text = "frobnicate", .line = 1 },
        .{ .text = "allow read /a b c d e f g h i", .line = 1 },
    };
    for (bad) |b| {
        var state = interceptor.HarnessState.init();
        var diag: Diag = .{};
        try testing.expectError(error.Invalid, applyPolicy(&state, b.text, &diag));
        try testing.expectEqual(b.line, diag.line);
    }
}

test "trace errors carry line numbers" {
    const bad = [_][]const u8{ "open", "open /a O_NOPE", "connect example.com:80", "openat x y", "clock now", "jump" };
    for (bad) |b| {
        var state = interceptor.HarnessState.init();
        var steps: std.ArrayList(Step) = .empty;
        defer steps.deinit(testing.allocator);
        var diag: Diag = .{};
        try testing.expectError(error.Invalid, runTrace(testing.allocator, &state, b, &steps, &diag));
        try testing.expectEqual(@as(usize, 1), diag.line);
    }
}

test "random garbage policy and trace text never crashes" {
    var prng = std.Random.DefaultPrng.init(0x5eed_0301);
    const r = prng.random();
    const words = [_][]const u8{ "open", "openat", "connect", "clock", "allow", "deny", "net", "read", "any", "/", "/a/**", "..", "O_CREAT", "|", "1.2.3.4:5", "[::1]:2", "unix:/s", "@", "*", "\n", " ", "\t", "#", "network", "cwd", "-100", "AT_FDCWD", "\xff" };
    var buf: [512]u8 = undefined;
    for (0..3000) |_| {
        var len: usize = 0;
        while (len < 400) {
            const w = words[r.uintLessThan(usize, words.len)];
            @memcpy(buf[len .. len + w.len], w);
            len += w.len;
            if (r.uintLessThan(u8, 3) == 0) {
                buf[len] = ' ';
                len += 1;
            }
        }
        var state = interceptor.HarnessState.init();
        var diag: Diag = .{};
        applyPolicy(&state, buf[0..len], &diag) catch {};
        var steps: std.ArrayList(Step) = .empty;
        defer steps.deinit(testing.allocator);
        runTrace(testing.allocator, &state, buf[0..len], &steps, &diag) catch {};
    }
}
