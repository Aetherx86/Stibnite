// Copyright (c) 2026 jk9576. All rights reserved.
// Stibnite: C-ABI Dynamic Hooking & Syscall Boundary Interceptor
// Licensed under the MIT License.

const std = @import("std");
pub const interceptor = @import("interceptor.zig");
pub const script = @import("script.zig");

const max_input_bytes = 16 * 1024 * 1024;

pub fn main(init: std.process.Init) !u8 {
    const gpa = init.arena.allocator();
    const io = init.io;

    var out_buf: [8192]u8 = undefined;
    var stdout_writer = std.Io.File.stdout().writerStreaming(io, &out_buf);
    const out = &stdout_writer.interface;
    var err_buf: [2048]u8 = undefined;
    var stderr_writer = std.Io.File.stderr().writerStreaming(io, &err_buf);
    const err = &stderr_writer.interface;

    const argv = try init.minimal.args.toSlice(gpa);
    const args: []const []const u8 = if (argv.len > 1) argv[1..] else &.{};
    const code = dispatch(io, gpa, out, err, args) catch |e| blk: {
        try err.print("error: {s}\n", .{@errorName(e)});
        break :blk 1;
    };
    try out.flush();
    try err.flush();
    return code;
}

fn printUsage(w: *std.Io.Writer) !void {
    try w.writeAll(
        \\Stibnite: deterministic C-ABI hooking and syscall boundary interceptor
        \\
        \\Usage:
        \\  stibnite demo
        \\  stibnite eval --policy FILE --trace FILE [--json] [--fail-on-deny]
        \\  stibnite version
        \\  stibnite help
        \\
        \\eval replays a trace of open/openat/connect/clock calls against a policy
        \\file and prints each decision. With --fail-on-deny the exit code is 2
        \\when any call was denied.
        \\
    );
}

pub fn dispatch(io: std.Io, gpa: std.mem.Allocator, out: *std.Io.Writer, err: *std.Io.Writer, args: []const []const u8) !u8 {
    if (args.len == 0 or std.mem.eql(u8, args[0], "demo")) {
        try runDemo(out);
        return 0;
    }
    const cmd = args[0];
    if (std.mem.eql(u8, cmd, "help") or std.mem.eql(u8, cmd, "--help") or std.mem.eql(u8, cmd, "-h")) {
        try printUsage(out);
        return 0;
    }
    if (std.mem.eql(u8, cmd, "version") or std.mem.eql(u8, cmd, "--version")) {
        try out.print("stibnite {s}\n", .{interceptor.version});
        return 0;
    }
    if (std.mem.eql(u8, cmd, "eval")) return runEval(io, gpa, out, err, args[1..]);
    try err.print("error: unknown command '{s}'\n\n", .{cmd});
    try printUsage(err);
    return 1;
}

fn runDemo(out: *std.Io.Writer) !void {
    try out.writeAll("Stibnite: Deterministic C-ABI Hooking & Syscall Interceptor Runtime.\n");
    interceptor.stibnite_reset();
    defer interceptor.stibnite_reset();
    interceptor.stibnite_configure(1, 1, 10); // Block net, Read-only FS, 10ms ticks

    var s: i64 = 0;
    var ns: i64 = 0;
    _ = interceptor.stibnite_intercept_clock_gettime(&s, &ns);
    try out.print("Virtual Clock T0: {d}.{d:0>9}s\n", .{ s, @as(u64, @intCast(ns)) });
    _ = interceptor.stibnite_intercept_clock_gettime(&s, &ns);
    try out.print("Virtual Clock T1: {d}.{d:0>9}s (+10ms deterministic step)\n", .{ s, @as(u64, @intCast(ns)) });

    const net_res = interceptor.stibnite_intercept_connect(4);
    try out.print("Rogue Socket Connect Attempt: {s} (Total Blocked: {d})\n", .{
        if (net_res == 0) "ALLOWED" else "DENIED_BY_POLICY",
        interceptor.stibnite_get_blocked_calls(),
    });
}

const EvalOptions = struct {
    policy: ?[]const u8 = null,
    trace: ?[]const u8 = null,
    json: bool = false,
    fail_on_deny: bool = false,
};

fn runEval(io: std.Io, gpa: std.mem.Allocator, out: *std.Io.Writer, err: *std.Io.Writer, args: []const []const u8) !u8 {
    var opts: EvalOptions = .{};
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "--json")) {
            opts.json = true;
        } else if (std.mem.eql(u8, a, "--fail-on-deny")) {
            opts.fail_on_deny = true;
        } else if (std.mem.eql(u8, a, "--policy") or std.mem.eql(u8, a, "--trace")) {
            if (i + 1 >= args.len) {
                try err.print("error: {s} needs a file argument\n", .{a});
                return 1;
            }
            i += 1;
            if (a[2] == 'p') opts.policy = args[i] else opts.trace = args[i];
        } else {
            try err.print("error: unknown eval option '{s}'\n", .{a});
            return 1;
        }
    }
    const policy_path = opts.policy orelse {
        try err.writeAll("error: eval requires --policy FILE\n");
        return 1;
    };
    const trace_path = opts.trace orelse {
        try err.writeAll("error: eval requires --trace FILE\n");
        return 1;
    };
    const cwd = std.Io.Dir.cwd();
    const policy_text = cwd.readFileAlloc(io, policy_path, gpa, .limited(max_input_bytes)) catch |e| {
        try err.print("error: cannot read policy '{s}': {s}\n", .{ policy_path, @errorName(e) });
        return 1;
    };
    const trace_text = cwd.readFileAlloc(io, trace_path, gpa, .limited(max_input_bytes)) catch |e| {
        try err.print("error: cannot read trace '{s}': {s}\n", .{ trace_path, @errorName(e) });
        return 1;
    };

    const state = try gpa.create(interceptor.HarnessState);
    state.* = interceptor.HarnessState.init();
    var diag: script.Diag = .{};
    script.applyPolicy(state, policy_text, &diag) catch {
        try err.print("error: {s}:{d}: {s}\n", .{ policy_path, diag.line, diag.message });
        return 1;
    };
    var steps: std.ArrayList(script.Step) = .empty;
    script.runTrace(gpa, state, trace_text, &steps, &diag) catch |e| switch (e) {
        error.Invalid => {
            try err.print("error: {s}:{d}: {s}\n", .{ trace_path, diag.line, diag.message });
            return 1;
        },
        else => return e,
    };

    var denied: usize = 0;
    for (steps.items) |s| {
        if (!s.event.allowed) denied += 1;
    }
    if (opts.json) try writeEvalJson(out, state, steps.items, denied) else try writeEvalText(out, state, steps.items, denied);
    return if (opts.fail_on_deny and denied > 0) 2 else 0;
}

fn flagAbiName(state: *const interceptor.HarnessState) []const u8 {
    return state.sock_abi.name;
}

fn writeEvalText(out: *std.Io.Writer, state: *const interceptor.HarnessState, steps: []const script.Step, denied: usize) !void {
    try out.print("policy  abi={s} network={s} filesystem={s} tick_ms={d} cwd={s} path_rules={d} net_rules={d}\n", .{
        flagAbiName(state),
        if (state.block_network) "deny" else "allow",
        if (state.read_only_fs) "read-only" else "read-write",
        state.time_tick_ns / std.time.ns_per_ms,
        state.cwdSlice(),
        state.path_rules.count,
        state.net_rules.count,
    });
    try out.writeAll("line  syscall        verdict  reason              target\n");
    for (steps) |s| {
        const ev = &s.event;
        var reason_buf: [32]u8 = undefined;
        const reason: []const u8 = if (ev.kind == .clock_gettime)
            "-"
        else if (ev.reason == .rule)
            try std.fmt.bufPrint(&reason_buf, "rule#{d}", .{ev.rule})
        else
            @tagName(ev.reason);
        try out.print("{d:>4}  {s:<13}  {s:<7}  {s:<18}  ", .{ s.line, ev.syscall, ev.verdictName(), reason });
        if (ev.kind == .clock_gettime) {
            try out.print("{d}.{d:0>9}\n", .{ ev.timestamp_ns / std.time.ns_per_s, ev.timestamp_ns % std.time.ns_per_s });
        } else {
            try out.print("{s}{s}\n", .{ ev.targetSlice(), if (ev.target_truncated) "..." else "" });
        }
    }
    try out.print("summary events={d} allowed={d} denied={d} total_calls={d} blocked_calls={d}\n", .{
        steps.len, steps.len - denied, denied, state.total_calls, state.blocked_calls,
    });
}

fn writeEvalJson(out: *std.Io.Writer, state: *const interceptor.HarnessState, steps: []const script.Step, denied: usize) !void {
    const audit = interceptor.audit;
    try out.print("{{\"version\":\"{s}\",\"policy\":{{\"abi\":\"{s}\",\"network\":\"{s}\",\"filesystem\":\"{s}\",\"tick_ms\":{d},\"cwd\":", .{
        interceptor.version,
        flagAbiName(state),
        if (state.block_network) "deny" else "allow",
        if (state.read_only_fs) "read-only" else "read-write",
        state.time_tick_ns / std.time.ns_per_ms,
    });
    try audit.writeJsonString(out, state.cwdSlice());
    try out.writeAll(",\"path_rules\":[");
    for (state.path_rules.items[0..state.path_rules.count], 0..) |*r, idx| {
        if (idx != 0) try out.writeByte(',');
        try out.print("{{\"index\":{d},\"effect\":\"{s}\",\"access\":\"{s}\",\"pattern\":", .{ idx, r.effect.name(), @tagName(r.access) });
        try audit.writeJsonString(out, r.slice());
        try out.writeByte('}');
    }
    try out.writeAll("],\"net_rules\":[");
    for (state.net_rules.items[0..state.net_rules.count], 0..) |r, idx| {
        if (idx != 0) try out.writeByte(',');
        try out.print("{{\"index\":{d},\"effect\":\"{s}\",\"rule\":\"{f}\"}}", .{ idx, r.effect.name(), r });
    }
    try out.writeAll("]},\"events\":[");
    for (steps, 0..) |s, idx| {
        if (idx != 0) try out.writeByte(',');
        try out.print("{{\"line\":{d},", .{s.line});
        try s.event.writeJsonFields(out);
        try out.writeByte('}');
    }
    try out.print("],\"summary\":{{\"events\":{d},\"allowed\":{d},\"denied\":{d},\"total_calls\":{d},\"blocked_calls\":{d}}}}}\n", .{
        steps.len, steps.len - denied, denied, state.total_calls, state.blocked_calls,
    });
}

test {
    _ = interceptor;
    _ = script;
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

fn runCli(args: []const []const u8, out_buf: []u8, err_buf: []u8) !struct { code: u8, out: []const u8, err: []const u8 } {
    var out = std.Io.Writer.fixed(out_buf);
    var err = std.Io.Writer.fixed(err_buf);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const code = try dispatch(std.testing.io, arena.allocator(), &out, &err, args);
    return .{ .code = code, .out = out.buffered(), .err = err.buffered() };
}

test "CLI demo prints zero-padded unsigned nanoseconds" {
    var ob: [1024]u8 = undefined;
    var eb: [256]u8 = undefined;
    const r = try runCli(&.{"demo"}, &ob, &eb);
    try std.testing.expectEqual(@as(u8, 0), r.code);
    try std.testing.expect(std.mem.find(u8, r.out, "T0: 1772928000.000000000s") != null);
    try std.testing.expect(std.mem.find(u8, r.out, "T1: 1772928000.010000000s") != null);
    // 0.1.0 printed the signed nanoseconds with a sign: "1772928000.+10000000s".
    try std.testing.expect(std.mem.find(u8, r.out, ".+") == null);
}

test "CLI eval reports usage errors" {
    var ob: [1024]u8 = undefined;
    var eb: [1024]u8 = undefined;
    try std.testing.expectEqual(@as(u8, 1), (try runCli(&.{ "eval", "--policy" }, &ob, &eb)).code);
    try std.testing.expectEqual(@as(u8, 1), (try runCli(&.{ "eval", "--trace", "x" }, &ob, &eb)).code);
    try std.testing.expectEqual(@as(u8, 1), (try runCli(&.{ "eval", "--policy", "/nonexistent/p", "--trace", "/nonexistent/t" }, &ob, &eb)).code);
    try std.testing.expectEqual(@as(u8, 1), (try runCli(&.{"bogus"}, &ob, &eb)).code);
    const v = try runCli(&.{"version"}, &ob, &eb);
    try std.testing.expectEqualStrings("stibnite 0.2.0\n", v.out);
}
