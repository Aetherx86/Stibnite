// Copyright (c) 2026 jk9576. All rights reserved.
// Stibnite: C-ABI Dynamic Hooking & Syscall Boundary Interceptor
// Licensed under the MIT License.
//
// Network policy engine: raw sockaddr decoding for several kernel ABIs and
// CIDR / port allow-deny rules for connect(2) destinations.

const std = @import("std");
const builtin = @import("builtin");
const net = std.Io.net;

pub const max_rules = 64;
const native_endian = builtin.cpu.arch.endian();

/// Layout differences of `struct sockaddr` between kernels. The BSD family
/// (including Darwin) prefixes the address with a one byte `sa_len` and stores
/// the family in one byte; Linux and Windows store a 16-bit family. The
/// numeric value of AF_INET6 also differs between all of them.
pub const SockAbi = struct {
    name: []const u8,
    len_prefix: bool,
    af_unix: u16 = 1,
    af_inet: u16 = 2,
    af_inet6: u16,

    pub const linux: SockAbi = .{ .name = "linux", .len_prefix = false, .af_inet6 = 10 };
    pub const darwin: SockAbi = .{ .name = "darwin", .len_prefix = true, .af_inet6 = 30 };
    pub const freebsd: SockAbi = .{ .name = "freebsd", .len_prefix = true, .af_inet6 = 28 };
    pub const openbsd: SockAbi = .{ .name = "openbsd", .len_prefix = true, .af_inet6 = 24 };
    pub const windows: SockAbi = .{ .name = "windows", .len_prefix = false, .af_inet6 = 23 };

    pub const native: SockAbi = switch (builtin.os.tag) {
        .linux => linux,
        .windows => windows,
        .macos, .ios, .tvos, .watchos, .visionos => darwin,
        .freebsd, .dragonfly => freebsd,
        .netbsd, .openbsd => openbsd,
        else => linux,
    };

    pub fn parse(text: []const u8) ?SockAbi {
        inline for (.{ linux, darwin, freebsd, openbsd, windows }) |abi| {
            if (std.mem.eql(u8, text, abi.name)) return abi;
        }
        if (std.mem.eql(u8, text, "macos") or std.mem.eql(u8, text, "bsd")) return darwin;
        if (std.mem.eql(u8, text, "netbsd")) return openbsd;
        return null;
    }
};

pub const sockaddr_in_size = 16;
pub const sockaddr_in6_size = 28;
pub const max_unix_path = 108;

pub const Endpoint = union(enum) {
    ip4: struct { addr: [4]u8, port: u16 },
    ip6: struct { addr: [16]u8, port: u16 },
    /// `path` borrows from the decoded sockaddr. Linux abstract sockets begin
    /// with a NUL byte; for them `abstract` is set and `path` omits that byte.
    unix: struct { path: []const u8, abstract: bool },

    /// Writes `a.b.c.d:port`, `[v6]:port` or `unix:<path>` (`unix:@name` for
    /// abstract sockets).
    pub fn format(self: Endpoint, w: *std.Io.Writer) std.Io.Writer.Error!void {
        switch (self) {
            .ip4 => |v| {
                const a: net.Ip4Address = .{ .bytes = v.addr, .port = v.port };
                try a.format(w);
            },
            .ip6 => |v| {
                const a: net.Ip6Address = .{ .bytes = v.addr, .port = v.port };
                try a.format(w);
            },
            .unix => |v| {
                try w.writeAll(if (v.abstract) "unix:@" else "unix:");
                try w.writeAll(v.path);
            },
        }
    }
};

pub const DecodeError = error{ Truncated, UnsupportedFamily };

const v4_mapped_prefix = [12]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };

/// Decode a raw `struct sockaddr` as passed to connect(2). Lengths are checked
/// against `bytes.len` (the caller's addrlen), never trusted from the
/// BSD `sa_len` byte. IPv4-mapped IPv6 destinations (::ffff:a.b.c.d) are
/// normalised to IPv4 so that IPv4 deny rules cannot be bypassed through a
/// dual-stack socket.
pub fn decodeSockaddr(abi: SockAbi, bytes: []const u8) DecodeError!Endpoint {
    if (bytes.len < 2) return error.Truncated;
    const family: u16 = if (abi.len_prefix) bytes[1] else std.mem.readInt(u16, bytes[0..2], native_endian);
    if (family == abi.af_inet) {
        if (bytes.len < sockaddr_in_size) return error.Truncated;
        return .{ .ip4 = .{ .addr = bytes[4..8].*, .port = std.mem.readInt(u16, bytes[2..4], .big) } };
    }
    if (family == abi.af_inet6) {
        if (bytes.len < sockaddr_in6_size) return error.Truncated;
        const addr: [16]u8 = bytes[8..24].*;
        const port = std.mem.readInt(u16, bytes[2..4], .big);
        if (std.mem.eql(u8, addr[0..12], &v4_mapped_prefix)) {
            return .{ .ip4 = .{ .addr = addr[12..16].*, .port = port } };
        }
        return .{ .ip6 = .{ .addr = addr, .port = port } };
    }
    if (family == abi.af_unix) {
        const raw = bytes[2..@min(bytes.len, 2 + max_unix_path)];
        if (raw.len > 0 and raw[0] == 0) {
            // Linux abstract namespace: the name is the remaining bytes, NULs included.
            return .{ .unix = .{ .path = raw[1..], .abstract = true } };
        }
        const end = std.mem.findScalar(u8, raw, 0) orelse raw.len;
        return .{ .unix = .{ .path = raw[0..end], .abstract = false } };
    }
    return error.UnsupportedFamily;
}

/// Encode an endpoint as the raw sockaddr bytes `abi` expects. Returns the
/// addrlen to pass to connect(2).
pub fn encodeSockaddr(abi: SockAbi, ep: Endpoint, out: []u8) error{NoSpace}!usize {
    const size: usize = switch (ep) {
        .ip4 => sockaddr_in_size,
        .ip6 => sockaddr_in6_size,
        .unix => |u| 2 + @as(usize, @intFromBool(u.abstract)) + u.path.len + @as(usize, @intFromBool(!u.abstract)),
    };
    if (size > out.len or (ep == .unix and size > 2 + max_unix_path)) return error.NoSpace;
    @memset(out[0..size], 0);
    const family: u16 = switch (ep) {
        .ip4 => abi.af_inet,
        .ip6 => abi.af_inet6,
        .unix => abi.af_unix,
    };
    if (abi.len_prefix) {
        out[0] = @intCast(size);
        out[1] = @intCast(family);
    } else {
        std.mem.writeInt(u16, out[0..2], family, native_endian);
    }
    switch (ep) {
        .ip4 => |v| {
            std.mem.writeInt(u16, out[2..4], v.port, .big);
            @memcpy(out[4..8], &v.addr);
        },
        .ip6 => |v| {
            std.mem.writeInt(u16, out[2..4], v.port, .big);
            @memcpy(out[8..24], &v.addr);
        },
        .unix => |u| {
            const off: usize = if (u.abstract) 3 else 2;
            @memcpy(out[off .. off + u.path.len], u.path);
        },
    }
    return size;
}

/// Parse `a.b.c.d:port`, `[v6]:port` or `unix:<path>` / `unix:@name`.
pub fn parseEndpoint(text: []const u8) error{InvalidEndpoint}!Endpoint {
    if (std.mem.startsWith(u8, text, "unix:")) {
        const rest = text[5..];
        if (rest.len == 0 or rest.len >= max_unix_path) return error.InvalidEndpoint;
        if (rest[0] == '@') return .{ .unix = .{ .path = rest[1..], .abstract = true } };
        return .{ .unix = .{ .path = rest, .abstract = false } };
    }
    const colon = std.mem.findScalarLast(u8, text, ':') orelse return error.InvalidEndpoint;
    const port = std.fmt.parseInt(u16, text[colon + 1 ..], 10) catch return error.InvalidEndpoint;
    const host = text[0..colon];
    if (host.len >= 2 and host[0] == '[' and host[host.len - 1] == ']') {
        const a = net.Ip6Address.parse(host[1 .. host.len - 1], port) catch return error.InvalidEndpoint;
        return .{ .ip6 = .{ .addr = a.bytes, .port = port } };
    }
    const a = net.Ip4Address.parse(host, port) catch return error.InvalidEndpoint;
    return .{ .ip4 = .{ .addr = a.bytes, .port = port } };
}

pub const Effect = @import("pathpolicy.zig").Effect;

pub const NetRule = struct {
    pub const Kind = enum { ip4, ip6, any_ip, unix };
    kind: Kind,
    addr: [16]u8 = @splat(0),
    prefix: u8 = 0,
    port: ?u16 = null,
    effect: Effect,

    pub fn matches(self: *const NetRule, ep: Endpoint) bool {
        switch (ep) {
            .unix => return self.kind == .unix,
            .ip4 => |v| {
                if (self.kind != .ip4 and self.kind != .any_ip) return false;
                if (self.port) |p| if (p != v.port) return false;
                return self.kind == .any_ip or prefixEql(self.addr[0..4], &v.addr, self.prefix);
            },
            .ip6 => |v| {
                if (self.kind != .ip6 and self.kind != .any_ip) return false;
                if (self.port) |p| if (p != v.port) return false;
                return self.kind == .any_ip or prefixEql(&self.addr, &v.addr, self.prefix);
            },
        }
    }

    /// Canonical text form, as accepted by `parseNetRule`.
    pub fn format(self: NetRule, w: *std.Io.Writer) std.Io.Writer.Error!void {
        switch (self.kind) {
            .unix => return w.writeAll("unix"),
            .any_ip => try w.writeAll("*"),
            .ip4 => {
                const a: net.Ip4Address = .{ .bytes = self.addr[0..4].*, .port = 0 };
                var tmp: [32]u8 = undefined;
                var fw = std.Io.Writer.fixed(&tmp);
                a.format(&fw) catch unreachable;
                const s = fw.buffered();
                try w.print("{s}/{d}", .{ s[0 .. std.mem.findScalarLast(u8, s, ':') orelse s.len], self.prefix });
            },
            .ip6 => {
                const a: net.Ip6Address = .{ .bytes = self.addr, .port = 0 };
                var tmp: [64]u8 = undefined;
                var fw = std.Io.Writer.fixed(&tmp);
                a.format(&fw) catch unreachable;
                const s = fw.buffered();
                const close = std.mem.findScalarLast(u8, s, ']') orelse s.len;
                try w.print("{s}/{d}", .{ s[1..close], self.prefix });
            },
        }
        if (self.port) |p| try w.print("@{d}", .{p});
    }
};

fn prefixEql(a: []const u8, b: []const u8, prefix: u8) bool {
    const full = prefix / 8;
    if (!std.mem.eql(u8, a[0..full], b[0..full])) return false;
    const rem: u3 = @intCast(prefix % 8);
    if (rem == 0) return true;
    const mask: u8 = @as(u8, 0xff) << @intCast(8 - @as(u4, rem));
    return (a[full] & mask) == (b[full] & mask);
}

pub const RuleParseError = error{InvalidRule};

/// Rule syntax:
///   unix                      any AF_UNIX destination
///   *[@port]                  any IPv4 or IPv6 destination
///   a.b.c.d[/len][@port]      IPv4 CIDR (len 0..32, default 32)
///   v6addr[/len][@port]       IPv6 CIDR (len 0..128, default 128)
/// Host bits below the prefix must be zero (`10.1.0.0/8` is rejected as
/// ambiguous). IPv4-mapped IPv6 rules with len >= 96 become IPv4 rules.
pub fn parseNetRule(text: []const u8, effect: Effect) RuleParseError!NetRule {
    if (std.mem.eql(u8, text, "unix")) return .{ .kind = .unix, .effect = effect };
    var body = text;
    var port: ?u16 = null;
    if (std.mem.findScalarLast(u8, text, '@')) |at| {
        port = std.fmt.parseInt(u16, text[at + 1 ..], 10) catch return error.InvalidRule;
        body = text[0..at];
    }
    if (std.mem.eql(u8, body, "*")) return .{ .kind = .any_ip, .port = port, .effect = effect };
    var addr_text = body;
    var prefix: ?u8 = null;
    if (std.mem.findScalar(u8, body, '/')) |slash| {
        prefix = std.fmt.parseInt(u8, body[slash + 1 ..], 10) catch return error.InvalidRule;
        addr_text = body[0..slash];
    }
    var rule = NetRule{ .kind = .ip4, .port = port, .effect = effect };
    if (net.Ip4Address.parse(addr_text, 0)) |a| {
        const p = prefix orelse 32;
        if (p > 32) return error.InvalidRule;
        @memcpy(rule.addr[0..4], &a.bytes);
        rule.prefix = p;
    } else |_| {
        const a = net.Ip6Address.parse(addr_text, 0) catch return error.InvalidRule;
        const p = prefix orelse 128;
        if (p > 128) return error.InvalidRule;
        if (p >= 96 and std.mem.eql(u8, a.bytes[0..12], &v4_mapped_prefix)) {
            @memcpy(rule.addr[0..4], a.bytes[12..16]);
            rule.prefix = p - 96;
        } else {
            rule.kind = .ip6;
            rule.addr = a.bytes;
            rule.prefix = p;
        }
    }
    const width: usize = if (rule.kind == .ip4) 4 else 16;
    var masked = rule.addr;
    maskTo(masked[0..width], rule.prefix);
    if (!std.mem.eql(u8, masked[0..width], rule.addr[0..width])) return error.InvalidRule;
    return rule;
}

fn maskTo(bytes: []u8, prefix: u8) void {
    for (bytes, 0..) |*b, i| {
        const bit_start = i * 8;
        if (bit_start + 8 <= prefix) continue;
        if (bit_start >= prefix) {
            b.* = 0;
        } else {
            const keep: u4 = @intCast(prefix - bit_start);
            b.* &= @as(u8, 0xff) << @intCast(8 - keep);
        }
    }
}

pub const Match = struct { index: usize, effect: Effect };

/// Ordered rule list; the last matching rule decides.
pub const NetRules = struct {
    items: [max_rules]NetRule = undefined,
    count: usize = 0,

    pub fn add(self: *NetRules, rule: NetRule) error{TooManyRules}!usize {
        if (self.count >= max_rules) return error.TooManyRules;
        self.items[self.count] = rule;
        self.count += 1;
        return self.count - 1;
    }

    pub fn clear(self: *NetRules) void {
        self.count = 0;
    }

    pub fn evaluate(self: *const NetRules, ep: Endpoint) ?Match {
        var i = self.count;
        while (i > 0) {
            i -= 1;
            if (self.items[i].matches(ep)) return .{ .index = i, .effect = self.items[i].effect };
        }
        return null;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;
const all_abis = [_]SockAbi{ SockAbi.linux, SockAbi.darwin, SockAbi.freebsd, SockAbi.openbsd, SockAbi.windows };

fn fmtEndpoint(ep: Endpoint, buf: []u8) []const u8 {
    var w = std.Io.Writer.fixed(buf);
    ep.format(&w) catch unreachable;
    return w.buffered();
}

test "sockaddr round-trips across every ABI" {
    const samples = [_][]const u8{ "127.0.0.1:80", "[2001:db8::1]:443", "unix:/run/app.sock", "unix:@abstract" };
    var raw: [128]u8 = undefined;
    var t1: [128]u8 = undefined;
    for (all_abis) |abi| {
        for (samples) |s| {
            const ep = try parseEndpoint(s);
            const n = try encodeSockaddr(abi, ep, &raw);
            const back = try decodeSockaddr(abi, raw[0..n]);
            try testing.expectEqualStrings(s, fmtEndpoint(back, &t1));
        }
    }
}

test "sockaddr layout matches the kernel definitions" {
    var raw: [32]u8 = undefined;
    const ep = try parseEndpoint("10.1.2.3:8080");
    try testing.expectEqual(@as(usize, 16), try encodeSockaddr(SockAbi.darwin, ep, &raw));
    try testing.expectEqual(@as(u8, 16), raw[0]); // sa_len
    try testing.expectEqual(@as(u8, 2), raw[1]); // AF_INET
    try testing.expectEqualSlices(u8, &.{ 0x1f, 0x90, 10, 1, 2, 3 }, raw[2..8]);
    const ep6 = try parseEndpoint("[::1]:22");
    _ = try encodeSockaddr(SockAbi.linux, ep6, &raw);
    try testing.expectEqual(@as(u16, 10), std.mem.readInt(u16, raw[0..2], native_endian));
    try testing.expectEqual(@as(u8, 1), raw[23]);
}

test "decoder rejects truncated and unknown sockaddrs" {
    var raw: [32]u8 = undefined;
    const n = try encodeSockaddr(SockAbi.linux, try parseEndpoint("1.2.3.4:5"), &raw);
    try testing.expectError(error.Truncated, decodeSockaddr(SockAbi.linux, raw[0 .. n - 1]));
    try testing.expectError(error.Truncated, decodeSockaddr(SockAbi.linux, raw[0..1]));
    try testing.expectError(error.Truncated, decodeSockaddr(SockAbi.linux, raw[0..0]));
    std.mem.writeInt(u16, raw[0..2], 999, native_endian);
    try testing.expectError(error.UnsupportedFamily, decodeSockaddr(SockAbi.linux, raw[0..16]));
    // A Darwin sa_len that lies about the size is ignored; addrlen rules.
    _ = try encodeSockaddr(SockAbi.darwin, try parseEndpoint("[::2]:1"), &raw);
    raw[0] = 255;
    try testing.expectError(error.Truncated, decodeSockaddr(SockAbi.darwin, raw[0..20]));
}

test "IPv4-mapped IPv6 destinations are normalised to IPv4" {
    var raw: [32]u8 = undefined;
    const ep = try parseEndpoint("[::ffff:10.0.0.7]:443");
    const n = try encodeSockaddr(SockAbi.linux, ep, &raw);
    const d = try decodeSockaddr(SockAbi.linux, raw[0..n]);
    try testing.expect(d == .ip4);
    try testing.expectEqualSlices(u8, &.{ 10, 0, 0, 7 }, &d.ip4.addr);
    var rules = NetRules{};
    _ = try rules.add(try parseNetRule("*", .allow));
    _ = try rules.add(try parseNetRule("10.0.0.0/8", .deny));
    try testing.expectEqual(Effect.deny, rules.evaluate(d).?.effect);
}

test "decoder survives random hostile bytes" {
    var prng = std.Random.DefaultPrng.init(0x5eed_0101);
    const r = prng.random();
    var raw: [140]u8 = undefined;
    var fmt_buf: [512]u8 = undefined;
    var decoded: usize = 0;
    for (0..50000) |_| {
        const n = r.uintLessThan(usize, raw.len);
        r.bytes(raw[0..n]);
        // Bias the family field toward valid values so all branches run.
        if (n >= 2 and r.boolean()) raw[1] = @intCast(r.intRangeAtMost(u8, 0, 31));
        for (all_abis) |abi| {
            if (decodeSockaddr(abi, raw[0..n])) |ep| {
                decoded += 1;
                _ = fmtEndpoint(ep, &fmt_buf);
            } else |_| {}
        }
    }
    try testing.expect(decoded > 0);
}

test "CIDR rules: prefixes, ports and canonical text" {
    const cases = [_]struct { rule: []const u8, canon: []const u8 }{
        .{ .rule = "127.0.0.0/8", .canon = "127.0.0.0/8" },
        .{ .rule = "10.1.2.3", .canon = "10.1.2.3/32" },
        .{ .rule = "0.0.0.0/0@53", .canon = "0.0.0.0/0@53" },
        .{ .rule = "::1", .canon = "::1/128" },
        .{ .rule = "2001:db8::/32@443", .canon = "2001:db8::/32@443" },
        .{ .rule = "::ffff:192.168.0.0/112", .canon = "192.168.0.0/16" },
        .{ .rule = "*@8080", .canon = "*@8080" },
        .{ .rule = "unix", .canon = "unix" },
        .{ .rule = "172.16.0.0/12", .canon = "172.16.0.0/12" },
    };
    var buf: [128]u8 = undefined;
    for (cases) |c| {
        const rule = try parseNetRule(c.rule, .allow);
        var w = std.Io.Writer.fixed(&buf);
        try rule.format(&w);
        try testing.expectEqualStrings(c.canon, w.buffered());
        // Canonical text parses back to the same rule.
        const again = try parseNetRule(w.buffered(), .allow);
        try testing.expectEqual(rule.kind, again.kind);
        try testing.expectEqual(rule.prefix, again.prefix);
        try testing.expectEqualSlices(u8, &rule.addr, &again.addr);
    }
    const r12 = try parseNetRule("172.16.0.0/12", .deny);
    try testing.expect(r12.matches(try parseEndpoint("172.31.255.255:1")));
    try testing.expect(!r12.matches(try parseEndpoint("172.32.0.0:1")));
    const p = try parseNetRule("*@53", .allow);
    try testing.expect(p.matches(try parseEndpoint("8.8.8.8:53")));
    try testing.expect(p.matches(try parseEndpoint("[2001:4860::8888]:53")));
    try testing.expect(!p.matches(try parseEndpoint("8.8.8.8:443")));
    try testing.expect(!p.matches(try parseEndpoint("unix:/x")));
}

test "CIDR rule parser rejects hostile text" {
    const bad = [_][]const u8{
        "",         "10.0.0.0/33", "::/129",      "10.1.0.0/8", "1.2.3.4@",     "1.2.3.4@70000",
        "01.2.3.4", "1.2.3",       "1.2.3.4/",    "1.2.3.4/-1", "fe80::1%eth0", "*@x",
        "unixx",    "/8",          "1.2.3.4/8/8",
    };
    for (bad) |b| {
        if (parseNetRule(b, .deny)) |_| {
            std.debug.print("accepted bad rule '{s}'\n", .{b});
            return error.TestUnexpectedResult;
        } else |_| {}
    }
}

test "prefix comparison property agrees with a bitwise reference" {
    var prng = std.Random.DefaultPrng.init(0x5eed_0102);
    const r = prng.random();
    for (0..20000) |_| {
        var a: [16]u8 = undefined;
        var b: [16]u8 = undefined;
        r.bytes(&a);
        b = a;
        if (r.boolean()) b[r.uintLessThan(usize, 16)] ^= @as(u8, 1) << @intCast(r.uintLessThan(u8, 8));
        const prefix = r.uintLessThan(u8, 129);
        var want = true;
        for (0..prefix) |bit| {
            const ab = (a[bit / 8] >> @intCast(7 - bit % 8)) & 1;
            const bb = (b[bit / 8] >> @intCast(7 - bit % 8)) & 1;
            if (ab != bb) want = false;
        }
        try testing.expectEqual(want, prefixEql(&a, &b, prefix));
    }
}

test "endpoint text parser rejects malformed input" {
    const bad = [_][]const u8{ "", "1.2.3.4", "1.2.3.4:", "1.2.3.4:99999", "[::1:80", "::1:80", "unix:", "host.example:80" };
    for (bad) |b| try testing.expectError(error.InvalidEndpoint, parseEndpoint(b));
}
