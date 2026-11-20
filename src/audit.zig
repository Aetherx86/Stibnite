// Copyright (c) 2026 jk9576. All rights reserved.
// Stibnite: C-ABI Dynamic Hooking & Syscall Boundary Interceptor
// Licensed under the MIT License.
//
// Audit trail: fixed-capacity ring of policy decisions with JSON rendering.
// No allocation, so it is safe to use from inside an interposed libc call.

const std = @import("std");
const pathpolicy = @import("pathpolicy.zig");

pub const max_target = 256;
pub const ring_capacity = 256;

pub const Syscall = enum { open, openat, connect, clock_gettime };

pub const Reason = enum {
    /// No rule matched; the global read-only / block-network switches allowed it.
    default_policy,
    /// A path or network rule decided (see `rule`).
    rule,
    /// Write intent while the filesystem is configured read-only.
    read_only_fs,
    /// Network access while outbound connections are blocked.
    network_blocked,
    /// NULL pointer, empty path, or malformed argument.
    invalid_argument,
    /// Path longer than PATH_MAX after joining with the working directory.
    path_too_long,
    /// openat(2) with a relative path and a directory descriptor whose path is unknown.
    unresolved_dirfd,
    /// Socket address family other than AF_INET, AF_INET6 or AF_UNIX, or a truncated address.
    unsupported_address,
};

pub const AuditEvent = struct {
    /// Name of the intercepted call ("open", "openat", "connect", "clock_gettime").
    syscall: []const u8,
    /// Canonical path, endpoint text or `fd:N`, truncated to `max_target` bytes.
    target: [max_target]u8 = undefined,
    target_len: usize = 0,
    allowed: bool,
    /// Virtual clock value when the decision was made (does not advance the clock).
    timestamp_ns: u64,

    seq: u64 = 0,
    kind: Syscall,
    reason: Reason,
    /// Index of the deciding rule, or -1.
    rule: i32 = -1,
    intent: pathpolicy.Intent = .{},
    target_truncated: bool = false,

    pub fn init(kind: Syscall, timestamp_ns: u64) AuditEvent {
        return .{
            .syscall = @tagName(kind),
            .allowed = true,
            .timestamp_ns = timestamp_ns,
            .kind = kind,
            .reason = .default_policy,
        };
    }

    pub fn setTarget(self: *AuditEvent, text: []const u8) void {
        const n = @min(text.len, max_target);
        @memcpy(self.target[0..n], text[0..n]);
        self.target_len = n;
        self.target_truncated = n < text.len;
    }

    pub fn targetSlice(self: *const AuditEvent) []const u8 {
        return self.target[0..self.target_len];
    }

    pub fn verdictName(self: *const AuditEvent) []const u8 {
        return if (self.allowed) "allow" else "deny";
    }

    pub fn writeJson(self: *const AuditEvent, w: *std.Io.Writer) std.Io.Writer.Error!void {
        try w.writeByte('{');
        try self.writeJsonFields(w);
        try w.writeByte('}');
    }

    /// The object members without the surrounding braces, so callers can
    /// prepend their own keys.
    pub fn writeJsonFields(self: *const AuditEvent, w: *std.Io.Writer) std.Io.Writer.Error!void {
        try w.print("\"seq\":{d},\"syscall\":\"{s}\",\"target\":", .{ self.seq, self.syscall });
        try writeJsonString(w, self.targetSlice());
        try w.print(
            ",\"target_truncated\":{},\"verdict\":\"{s}\",\"reason\":\"{s}\",\"rule\":{d}," ++
                "\"write_intent\":{},\"write_access\":{},\"create\":{},\"truncate\":{},\"append\":{},\"time_ns\":{d}",
            .{
                self.target_truncated, self.verdictName(),       @tagName(self.reason), self.rule,
                self.intent.isWrite(), self.intent.write_access, self.intent.create,    self.intent.truncate,
                self.intent.append,    self.timestamp_ns,
            },
        );
    }
};

/// Writes `bytes` as a JSON string literal. Control characters, quotes and
/// backslashes are escaped. Paths are arbitrary bytes, so every byte that is
/// not part of a well-formed UTF-8 sequence (stray continuation bytes,
/// truncated, overlong or surrogate encodings) becomes U+FFFD while valid
/// sequences pass through; the output is always valid JSON.
pub fn writeJsonString(w: *std.Io.Writer, bytes: []const u8) std.Io.Writer.Error!void {
    try w.writeByte('"');
    var i: usize = 0;
    while (i < bytes.len) {
        const c = bytes[i];
        if (c >= 0x80) {
            const n = std.unicode.utf8ByteSequenceLength(c) catch 0;
            if (n > 1 and i + n <= bytes.len and std.unicode.utf8ValidateSlice(bytes[i .. i + n])) {
                try w.writeAll(bytes[i .. i + n]);
                i += n;
            } else {
                try w.writeAll("\\ufffd");
                i += 1;
            }
            continue;
        }
        switch (c) {
            '"' => try w.writeAll("\\\""),
            '\\' => try w.writeAll("\\\\"),
            '\n' => try w.writeAll("\\n"),
            '\r' => try w.writeAll("\\r"),
            '\t' => try w.writeAll("\\t"),
            0...8, 11, 12, 14...0x1f, 0x7f => try w.print("\\u{x:0>4}", .{c}),
            else => try w.writeByte(c),
        }
        i += 1;
    }
    try w.writeByte('"');
}

pub const Ring = struct {
    items: [ring_capacity]AuditEvent = undefined,
    total: u64 = 0,

    pub fn push(self: *Ring, ev: AuditEvent) u64 {
        var e = ev;
        e.seq = self.total + 1;
        self.items[@intCast(self.total % ring_capacity)] = e;
        self.total += 1;
        return e.seq;
    }

    pub fn clear(self: *Ring) void {
        self.total = 0;
    }

    pub fn retained(self: *const Ring) usize {
        return @intCast(@min(self.total, ring_capacity));
    }

    pub fn dropped(self: *const Ring) u64 {
        return self.total - self.retained();
    }

    /// i = 0 is the oldest retained event.
    pub fn get(self: *const Ring, i: usize) *const AuditEvent {
        const first = self.total - self.retained();
        return &self.items[@intCast((first + i) % ring_capacity)];
    }

    pub fn writeJson(self: *const Ring, w: *std.Io.Writer) std.Io.Writer.Error!void {
        try w.print("{{\"total\":{d},\"dropped\":{d},\"events\":[", .{ self.total, self.dropped() });
        for (0..self.retained()) |i| {
            if (i != 0) try w.writeByte(',');
            try self.get(i).writeJson(w);
        }
        try w.writeAll("]}");
    }

    /// snprintf-style export: writes at most `out.len - 1` bytes plus a NUL
    /// terminator and returns the full length the JSON document needs
    /// (excluding the NUL), so callers can size a buffer and retry.
    pub fn exportJson(self: *const Ring, out: []u8) usize {
        var scratch: [256]u8 = undefined;
        var counter = std.Io.Writer.Discarding.init(&scratch);
        self.writeJson(&counter.writer) catch {};
        const needed: usize = @intCast(counter.fullCount());
        if (out.len == 0) return needed;
        var fw = std.Io.Writer.fixed(out[0 .. out.len - 1]);
        self.writeJson(&fw) catch {};
        out[fw.end] = 0;
        return needed;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn sampleEvent(target: []const u8, allowed: bool) AuditEvent {
    var ev = AuditEvent.init(.open, 42);
    ev.setTarget(target);
    ev.allowed = allowed;
    ev.reason = if (allowed) .default_policy else .rule;
    return ev;
}

test "JSON strings escape control characters and invalid UTF-8" {
    var buf: [256]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try writeJsonString(&w, "a\"b\\c\n\x01\x7f");
    try testing.expectEqualStrings("\"a\\\"b\\\\c\\n\\u0001\\u007f\"", w.buffered());
    w = std.Io.Writer.fixed(&buf);
    try writeJsonString(&w, "caf\xc3\xa9");
    try testing.expectEqualStrings("\"caf\xc3\xa9\"", w.buffered());
    w = std.Io.Writer.fixed(&buf);
    try writeJsonString(&w, "bad\xff\xfe");
    try testing.expectEqualStrings("\"bad\\ufffd\\ufffd\"", w.buffered());
    // Valid sequences survive next to invalid bytes.
    w = std.Io.Writer.fixed(&buf);
    try writeJsonString(&w, "caf\xc3\xa9\xff\xc3");
    try testing.expectEqualStrings("\"caf\xc3\xa9\\ufffd\\ufffd\"", w.buffered());
    // Overlong encoding of '/' and a UTF-16 surrogate are rejected.
    w = std.Io.Writer.fixed(&buf);
    try writeJsonString(&w, "\xc0\xaf\xed\xa0\x80");
    try testing.expectEqualStrings("\"\\ufffd\\ufffd\\ufffd\\ufffd\\ufffd\"", w.buffered());
}

test "ring keeps the newest events and reports drops" {
    var ring = Ring{};
    for (0..ring_capacity + 10) |i| {
        var name: [16]u8 = undefined;
        _ = ring.push(sampleEvent(try std.fmt.bufPrint(&name, "/f{d}", .{i}), true));
    }
    try testing.expectEqual(@as(usize, ring_capacity), ring.retained());
    try testing.expectEqual(@as(u64, 10), ring.dropped());
    try testing.expectEqualStrings("/f10", ring.get(0).targetSlice());
    try testing.expectEqual(@as(u64, 11), ring.get(0).seq);
    try testing.expectEqual(@as(u64, ring_capacity + 10), ring.get(ring_capacity - 1).seq);
}

test "ring JSON export is valid JSON under random hostile targets" {
    var prng = std.Random.DefaultPrng.init(0x5eed_0201);
    const r = prng.random();
    var ring = Ring{};
    for (0..300) |_| {
        var t: [300]u8 = undefined;
        const n = r.uintLessThan(usize, t.len);
        r.bytes(t[0..n]);
        _ = ring.push(sampleEvent(t[0..n], r.boolean()));
    }
    const needed = ring.exportJson(&.{});
    const buf = try testing.allocator.alloc(u8, needed + 1);
    defer testing.allocator.free(buf);
    try testing.expectEqual(needed, ring.exportJson(buf));
    try testing.expectEqual(@as(u8, 0), buf[needed]);
    try testing.expect(try std.json.validate(testing.allocator, buf[0..needed]));
}

test "ring JSON export truncates like snprintf" {
    var ring = Ring{};
    _ = ring.push(sampleEvent("/etc/hosts", true));
    var big: [1024]u8 = undefined;
    const needed = ring.exportJson(&big);
    var small: [10]u8 = undefined;
    try testing.expectEqual(needed, ring.exportJson(&small));
    try testing.expectEqual(@as(u8, 0), small[9]);
    try testing.expectEqualStrings(big[0..9], small[0..9]);
}

test "long targets are truncated and flagged" {
    const long: [400]u8 = @splat('x');
    const ev = sampleEvent(&long, false);
    try testing.expect(ev.target_truncated);
    try testing.expectEqual(@as(usize, max_target), ev.target_len);
}
