// Copyright (c) 2026 jk9576. All rights reserved.
// Stibnite: C-ABI Dynamic Hooking & Syscall Boundary Interceptor
// Licensed under the MIT License.
//
// Filesystem policy engine: lexical path canonicalization, glob rules and
// per-ABI decoding of open(2) flags.

const std = @import("std");
const builtin = @import("builtin");

/// PATH_MAX on Linux and Darwin, including the terminating NUL.
pub const max_path = 4096;
pub const max_pattern = 255;
pub const max_rules = 64;

pub const CanonError = error{ EmptyPath, NameTooLong, RelativeBase };

/// Lexically canonicalize `path` against the absolute, canonical `cwd`.
/// Collapses repeated slashes, drops `.` segments and resolves `..` segments,
/// clamping at the root the same way the kernel resolves `/..`. Symlinks are
/// not consulted: the result describes what the caller asked for, so a
/// `/tmp/../etc/shadow` request is judged as `/etc/shadow`.
/// The result is always absolute and has no trailing slash (except `/`).
pub fn canonicalize(cwd: []const u8, path: []const u8, out: []u8) CanonError![]const u8 {
    if (path.len == 0) return error.EmptyPath;
    if (path.len >= max_path) return error.NameTooLong;
    if (out.len == 0) return error.NameTooLong;

    var len: usize = 0;
    if (path[0] != '/') {
        if (cwd.len == 0 or cwd[0] != '/') return error.RelativeBase;
        // cwd is canonical already, but run it through the same segment loop so
        // that a non-canonical cwd can never leak `..` into the result.
        len = try appendSegments(out, 0, cwd);
    }
    len = try appendSegments(out, len, path);
    if (len == 0) {
        out[0] = '/';
        len = 1;
    }
    return out[0..len];
}

fn appendSegments(out: []u8, start_len: usize, path: []const u8) CanonError!usize {
    var len = start_len;
    var it = std.mem.splitScalar(u8, path, '/');
    while (it.next()) |seg| {
        if (seg.len == 0 or std.mem.eql(u8, seg, ".")) continue;
        if (std.mem.eql(u8, seg, "..")) {
            // Pop the last segment; at the root this is a no-op.
            while (len > 0 and out[len - 1] != '/') len -= 1;
            if (len > 0) len -= 1;
            continue;
        }
        if (len + 1 + seg.len > out.len) return error.NameTooLong;
        out[len] = '/';
        @memcpy(out[len + 1 .. len + 1 + seg.len], seg);
        len += 1 + seg.len;
    }
    return len;
}

/// Match one path segment against a segment pattern supporting `*` (any run of
/// characters) and `?` (exactly one character). Greedy with single
/// backtracking point, so the cost is O(len(pattern) * len(name)).
pub fn matchSegment(pattern: []const u8, name: []const u8) bool {
    var p: usize = 0;
    var n: usize = 0;
    var star_p: ?usize = null;
    var star_n: usize = 0;
    while (n < name.len) {
        if (p < pattern.len and pattern[p] == '*') {
            star_p = p + 1;
            star_n = n;
            p += 1;
        } else if (p < pattern.len and (pattern[p] == '?' or pattern[p] == name[n])) {
            p += 1;
            n += 1;
        } else if (star_p) |sp| {
            star_n += 1;
            n = star_n;
            p = sp;
        } else {
            return false;
        }
    }
    while (p < pattern.len and pattern[p] == '*') p += 1;
    return p == pattern.len;
}

fn segEnd(s: []const u8, start: usize) usize {
    return std.mem.findScalarPos(u8, s, start, '/') orelse s.len;
}

fn segNext(s: []const u8, start: usize) usize {
    const e = segEnd(s, start);
    return if (e < s.len) e + 1 else s.len;
}

fn isGlobstar(s: []const u8, start: usize) bool {
    return std.mem.eql(u8, s[start..segEnd(s, start)], "**");
}

/// Match a canonical absolute path against a canonical absolute pattern.
/// A whole `**` segment matches zero or more path segments, so `/tmp/**`
/// matches `/tmp` itself and everything beneath it. Segment-level matching
/// uses the same greedy single-backtrack scheme as `matchSegment`.
pub fn matchPath(pattern: []const u8, path: []const u8) bool {
    if (pattern.len == 0 or path.len == 0 or pattern[0] != '/' or path[0] != '/') return false;
    const pat = pattern[1..];
    const s = path[1..];
    var p: usize = 0;
    var i: usize = 0;
    var star_p: ?usize = null;
    var star_i: usize = 0;
    while (i < s.len) {
        if (p < pat.len and isGlobstar(pat, p)) {
            p = segNext(pat, p);
            star_p = p;
            star_i = i;
        } else if (p < pat.len and matchSegment(pat[p..segEnd(pat, p)], s[i..segEnd(s, i)])) {
            p = segNext(pat, p);
            i = segNext(s, i);
        } else if (star_p) |sp| {
            star_i = segNext(s, star_i);
            i = star_i;
            p = sp;
        } else {
            return false;
        }
    }
    while (p < pat.len and isGlobstar(pat, p)) p = segNext(pat, p);
    return p >= pat.len;
}

/// Which open(2) flag encoding to decode. Flag bits differ between kernels:
/// O_CREAT is 0x40 on Linux but 0x200 on Darwin and the BSDs, and 0x100 in the
/// Windows CRT.
pub const FlagAbi = enum {
    linux,
    bsd,
    windows,

    pub const native: FlagAbi = switch (builtin.os.tag) {
        .linux => .linux,
        .windows => .windows,
        .macos, .ios, .tvos, .watchos, .visionos, .freebsd, .netbsd, .openbsd, .dragonfly => .bsd,
        else => .linux,
    };

    pub fn parse(text: []const u8) ?FlagAbi {
        if (std.mem.eql(u8, text, "linux")) return .linux;
        if (std.mem.eql(u8, text, "bsd") or std.mem.eql(u8, text, "darwin") or std.mem.eql(u8, text, "macos")) return .bsd;
        if (std.mem.eql(u8, text, "windows")) return .windows;
        return null;
    }
};

pub const FlagBits = struct {
    rdonly: i32 = 0,
    wronly: i32 = 1,
    rdwr: i32 = 2,
    creat: i32,
    trunc: i32,
    append: i32,
    excl: i32,
    /// Linux O_TMPFILE (always creates an unnamed file); 0 elsewhere.
    tmpfile: i32 = 0,
};

pub fn flagBits(abi: FlagAbi) FlagBits {
    return switch (abi) {
        .linux => .{ .creat = 0o100, .trunc = 0o1000, .append = 0o2000, .excl = 0o200, .tmpfile = 0o20000000 },
        .bsd => .{ .creat = 0x200, .trunc = 0x400, .append = 0x8, .excl = 0x800 },
        .windows => .{ .creat = 0x100, .trunc = 0x200, .append = 0x8, .excl = 0x400 },
    };
}

/// Decoded effect of an open(2) flag word.
pub const Intent = struct {
    write_access: bool = false,
    create: bool = false,
    truncate: bool = false,
    append: bool = false,

    /// Any bit that can modify the filesystem. Linux honours O_TRUNC even
    /// with O_RDONLY, and O_CREAT creates files in read-only mode too, so both
    /// count as writes regardless of the access mode.
    pub fn isWrite(self: Intent) bool {
        return self.write_access or self.create or self.truncate or self.append;
    }
};

pub fn classifyFlags(abi: FlagAbi, flags: i32) Intent {
    const b = flagBits(abi);
    // The access mode is the low two bits on every supported ABI. Mode 3 is
    // invalid on Linux and Darwin; treat it as a write so it fails closed.
    const accmode = flags & 3;
    return .{
        .write_access = accmode != 0,
        .create = (flags & b.creat) != 0 or (b.tmpfile != 0 and (flags & b.tmpfile) == b.tmpfile),
        .truncate = (flags & b.trunc) != 0,
        .append = (flags & b.append) != 0,
    };
}

/// Encode a `|`-separated list of symbolic flag names (O_RDONLY, O_WRONLY,
/// O_RDWR, O_CREAT, O_TRUNC, O_APPEND, O_EXCL, O_TMPFILE) or a decimal / 0x
/// hexadecimal number into the numeric flag word of `abi`.
pub fn encodeFlags(abi: FlagAbi, text: []const u8) error{ UnknownFlag, InvalidNumber }!i32 {
    if (text.len > 0 and std.ascii.isDigit(text[0])) {
        return std.fmt.parseInt(i32, text, 0) catch error.InvalidNumber;
    }
    const b = flagBits(abi);
    var flags: i32 = 0;
    var it = std.mem.splitScalar(u8, text, '|');
    while (it.next()) |raw| {
        const name = std.mem.trim(u8, raw, " \t");
        const bit: i32 = if (std.mem.eql(u8, name, "O_RDONLY"))
            b.rdonly
        else if (std.mem.eql(u8, name, "O_WRONLY"))
            b.wronly
        else if (std.mem.eql(u8, name, "O_RDWR"))
            b.rdwr
        else if (std.mem.eql(u8, name, "O_CREAT"))
            b.creat
        else if (std.mem.eql(u8, name, "O_TRUNC"))
            b.trunc
        else if (std.mem.eql(u8, name, "O_APPEND"))
            b.append
        else if (std.mem.eql(u8, name, "O_EXCL"))
            b.excl
        else if (std.mem.eql(u8, name, "O_TMPFILE") and b.tmpfile != 0)
            // O_TMPFILE requires O_DIRECTORY in its bit pattern; include it.
            b.tmpfile | 0o200000
        else
            return error.UnknownFlag;
        flags |= bit;
    }
    return flags;
}

pub const Effect = enum(u1) {
    deny = 0,
    allow = 1,

    pub fn name(self: Effect) []const u8 {
        return @tagName(self);
    }
};

pub const Access = enum(u2) {
    read = 1,
    write = 2,
    any = 3,

    pub fn covers(self: Access, is_write: bool) bool {
        return switch (self) {
            .any => true,
            .read => !is_write,
            .write => is_write,
        };
    }

    pub fn parse(text: []const u8) ?Access {
        if (std.mem.eql(u8, text, "read")) return .read;
        if (std.mem.eql(u8, text, "write")) return .write;
        if (std.mem.eql(u8, text, "any")) return .any;
        return null;
    }
};

pub const PathRule = struct {
    pattern: [max_pattern]u8 = undefined,
    len: u8 = 0,
    effect: Effect,
    access: Access,

    pub fn slice(self: *const PathRule) []const u8 {
        return self.pattern[0..self.len];
    }
};

pub const RuleError = error{ EmptyPattern, RelativePattern, PatternTooLong, TooManyRules, InvalidPattern };

pub const Match = struct {
    index: usize,
    effect: Effect,
};

/// Ordered rule list; the last rule that matches a request decides it.
pub const PathRules = struct {
    items: [max_rules]PathRule = undefined,
    count: usize = 0,

    pub fn add(self: *PathRules, pattern: []const u8, effect: Effect, access: Access) RuleError!usize {
        if (pattern.len == 0) return error.EmptyPattern;
        if (pattern[0] != '/') return error.RelativePattern;
        if (std.mem.findScalar(u8, pattern, 0) != null) return error.InvalidPattern;
        if (self.count >= max_rules) return error.TooManyRules;
        var buf: [max_path]u8 = undefined;
        const canon = canonicalize("/", pattern, &buf) catch return error.PatternTooLong;
        if (canon.len > max_pattern) return error.PatternTooLong;
        var rule = PathRule{ .effect = effect, .access = access };
        @memcpy(rule.pattern[0..canon.len], canon);
        rule.len = @intCast(canon.len);
        self.items[self.count] = rule;
        self.count += 1;
        return self.count - 1;
    }

    pub fn clear(self: *PathRules) void {
        self.count = 0;
    }

    pub fn evaluate(self: *const PathRules, canonical_path: []const u8, is_write: bool) ?Match {
        var i = self.count;
        while (i > 0) {
            i -= 1;
            const r = &self.items[i];
            if (r.access.covers(is_write) and matchPath(r.slice(), canonical_path)) {
                return .{ .index = i, .effect = r.effect };
            }
        }
        return null;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn expectCanon(cwd: []const u8, path: []const u8, want: []const u8) !void {
    var buf: [max_path]u8 = undefined;
    try testing.expectEqualStrings(want, try canonicalize(cwd, path, &buf));
}

test "canonicalize collapses dot, dot-dot and repeated slashes" {
    try expectCanon("/", "/etc/hosts", "/etc/hosts");
    try expectCanon("/", "//etc///hosts/", "/etc/hosts");
    try expectCanon("/", "/tmp/../etc/./shadow", "/etc/shadow");
    try expectCanon("/", "/../../..", "/");
    try expectCanon("/", "/..", "/");
    try expectCanon("/", "/", "/");
    try expectCanon("/home/ci/proj", "src/main.zig", "/home/ci/proj/src/main.zig");
    try expectCanon("/home/ci/proj", "../../../../etc/passwd", "/etc/passwd");
    try expectCanon("/home/ci/proj", ".", "/home/ci/proj");
    try expectCanon("/home/ci", "a/b/../../..", "/home");
    try expectCanon("/", "/a/.../b", "/a/.../b");
}

test "canonicalize rejects hostile inputs" {
    var buf: [max_path]u8 = undefined;
    try testing.expectError(error.EmptyPath, canonicalize("/", "", &buf));
    try testing.expectError(error.RelativeBase, canonicalize("rel", "x", &buf));
    const long: [max_path]u8 = @splat('a');
    try testing.expectError(error.NameTooLong, canonicalize("/", &long, &buf));
    // cwd + relative path that overflows the output buffer.
    var small: [8]u8 = undefined;
    try testing.expectError(error.NameTooLong, canonicalize("/abcdef", "ghijk", &small));
}

test "canonicalize property: output is absolute, dot-free and idempotent" {
    var prng = std.Random.DefaultPrng.init(0x5eed_0002);
    const r = prng.random();
    const alphabet = "ab./";
    var input: [64]u8 = undefined;
    var buf: [max_path]u8 = undefined;
    var buf2: [max_path]u8 = undefined;
    for (0..5000) |_| {
        const n = r.intRangeAtMost(usize, 1, input.len);
        for (input[0..n]) |*c| c.* = alphabet[r.uintLessThan(usize, alphabet.len)];
        const cwd = if (r.boolean()) "/w/x" else "/";
        const out = try canonicalize(cwd, input[0..n], &buf);
        try testing.expect(out[0] == '/');
        try testing.expect(out.len == 1 or out[out.len - 1] != '/');
        try testing.expect(std.mem.find(u8, out, "//") == null);
        var it = std.mem.splitScalar(u8, out[1..], '/');
        while (it.next()) |seg| {
            try testing.expect(!std.mem.eql(u8, seg, "."));
            try testing.expect(!std.mem.eql(u8, seg, ".."));
        }
        try testing.expectEqualStrings(out, try canonicalize("/", out, &buf2));
    }
}

test "segment glob semantics" {
    try testing.expect(matchSegment("*", ""));
    try testing.expect(matchSegment("*.log", "app.log"));
    try testing.expect(!matchSegment("*.log", "app.txt"));
    try testing.expect(matchSegment("a?c", "abc"));
    try testing.expect(!matchSegment("a?c", "ac"));
    try testing.expect(matchSegment("*a*b*", "xxaxxbxx"));
    try testing.expect(!matchSegment("*a*b", "xxbxxa"));
    try testing.expect(matchSegment("", ""));
    try testing.expect(!matchSegment("", "x"));
}

test "path glob semantics" {
    try testing.expect(matchPath("/tmp/**", "/tmp"));
    try testing.expect(matchPath("/tmp/**", "/tmp/a/b/c"));
    try testing.expect(!matchPath("/tmp/**", "/tmpfoo"));
    try testing.expect(matchPath("/**", "/"));
    try testing.expect(matchPath("/**", "/etc/shadow"));
    try testing.expect(matchPath("/etc/*", "/etc/hosts"));
    try testing.expect(!matchPath("/etc/*", "/etc/ssl/cert.pem"));
    try testing.expect(matchPath("/home/*/.ssh/**", "/home/ci/.ssh/id_ed25519"));
    try testing.expect(matchPath("/**/*.pem", "/etc/ssl/certs/root.pem"));
    try testing.expect(matchPath("/**/*.pem", "/root.pem"));
    try testing.expect(!matchPath("/**/*.pem", "/etc/ssl/root.key"));
    try testing.expect(matchPath("/a/**/b/**/c", "/a/x/b/y/z/c"));
    try testing.expect(!matchPath("/a/**/b/**/c", "/a/x/c"));
    try testing.expect(!matchPath("relative", "/x"));
    try testing.expect(!matchPath("/x", "relative"));
}

/// Reference matcher: exhaustive recursion over segment lists. Exponential in
/// the worst case, which is why the production matcher does not use it.
fn naiveMatchPath(pat_segs: []const []const u8, path_segs: []const []const u8) bool {
    if (pat_segs.len == 0) return path_segs.len == 0;
    if (std.mem.eql(u8, pat_segs[0], "**")) {
        var k: usize = 0;
        while (k <= path_segs.len) : (k += 1) {
            if (naiveMatchPath(pat_segs[1..], path_segs[k..])) return true;
        }
        return false;
    }
    if (path_segs.len == 0) return false;
    return naiveMatchSegment(pat_segs[0], path_segs[0]) and naiveMatchPath(pat_segs[1..], path_segs[1..]);
}

fn naiveMatchSegment(p: []const u8, n: []const u8) bool {
    if (p.len == 0) return n.len == 0;
    if (p[0] == '*') {
        var k: usize = 0;
        while (k <= n.len) : (k += 1) {
            if (naiveMatchSegment(p[1..], n[k..])) return true;
        }
        return false;
    }
    if (n.len == 0) return false;
    return (p[0] == '?' or p[0] == n[0]) and naiveMatchSegment(p[1..], n[1..]);
}

fn splitSegs(s: []const u8, out: [][]const u8) [][]const u8 {
    var n: usize = 0;
    var it = std.mem.splitScalar(u8, s[1..], '/');
    if (s.len == 1) return out[0..0];
    while (it.next()) |seg| {
        out[n] = seg;
        n += 1;
    }
    return out[0..n];
}

test "differential: greedy glob matcher agrees with exhaustive reference" {
    var prng = std.Random.DefaultPrng.init(0x5eed_0001);
    const r = prng.random();
    const pat_seg_choices = [_][]const u8{ "**", "*", "a", "b", "a*", "*b", "?", "a?b", "*a*" };
    const path_seg_choices = [_][]const u8{ "a", "b", "ab", "ba", "aab", "x", "axb" };
    var pbuf: [128]u8 = undefined;
    var sbuf: [128]u8 = undefined;
    var pseg_store: [16][]const u8 = undefined;
    var sseg_store: [16][]const u8 = undefined;
    var checked: usize = 0;
    for (0..20000) |_| {
        var plen: usize = 0;
        for (0..r.intRangeAtMost(usize, 1, 5)) |_| {
            const seg = pat_seg_choices[r.uintLessThan(usize, pat_seg_choices.len)];
            pbuf[plen] = '/';
            @memcpy(pbuf[plen + 1 .. plen + 1 + seg.len], seg);
            plen += 1 + seg.len;
        }
        var slen: usize = 0;
        const nseg = r.uintLessThan(usize, 6);
        for (0..nseg) |_| {
            const seg = path_seg_choices[r.uintLessThan(usize, path_seg_choices.len)];
            sbuf[slen] = '/';
            @memcpy(sbuf[slen + 1 .. slen + 1 + seg.len], seg);
            slen += 1 + seg.len;
        }
        if (slen == 0) {
            sbuf[0] = '/';
            slen = 1;
        }
        const pat = pbuf[0..plen];
        const path = sbuf[0..slen];
        const want = naiveMatchPath(splitSegs(pat, &pseg_store), splitSegs(path, &sseg_store));
        const got = matchPath(pat, path);
        if (want != got) {
            std.debug.print("mismatch pattern={s} path={s} want={} got={}\n", .{ pat, path, want, got });
            return error.TestUnexpectedResult;
        }
        checked += 1;
    }
    try testing.expectEqual(@as(usize, 20000), checked);
}

test "differential: segment matcher agrees with exhaustive reference" {
    var prng = std.Random.DefaultPrng.init(0x5eed_0003);
    const r = prng.random();
    const pa = "ab*?";
    const na = "abc";
    var p: [10]u8 = undefined;
    var n: [10]u8 = undefined;
    for (0..20000) |_| {
        const pl = r.uintLessThan(usize, p.len);
        const nl = r.uintLessThan(usize, n.len);
        for (p[0..pl]) |*c| c.* = pa[r.uintLessThan(usize, pa.len)];
        for (n[0..nl]) |*c| c.* = na[r.uintLessThan(usize, na.len)];
        try testing.expectEqual(naiveMatchSegment(p[0..pl], n[0..nl]), matchSegment(p[0..pl], n[0..nl]));
    }
}

test "glob matcher stays fast on adversarial backtracking input" {
    // A naive backtracking matcher takes exponential time here.
    const pattern = "/**/a/**/a/**/a/**/a/**/a/**/a/**/b";
    var buf: [2 * 400 + 1]u8 = undefined;
    var len: usize = 0;
    for (0..400) |_| {
        buf[len] = '/';
        buf[len + 1] = 'a';
        len += 2;
    }
    try testing.expect(!matchPath(pattern, buf[0..len]));
    const seg_pat = "*a*a*a*a*a*a*a*a*b";
    const name: [3000]u8 = @splat('a');
    try testing.expect(!matchSegment(seg_pat, &name));
}

test "open flag decoding differs per ABI" {
    // Linux O_RDONLY|O_CREAT creates a file: it must count as a write.
    const linux_creat = classifyFlags(.linux, 0o100);
    try testing.expect(linux_creat.create and linux_creat.isWrite());
    try testing.expect(!linux_creat.write_access);
    // The same numeric value is a harmless bit on Darwin.
    try testing.expect(!classifyFlags(.bsd, 0o100).isWrite());
    try testing.expect(classifyFlags(.bsd, 0x200).create);
    try testing.expect(classifyFlags(.bsd, 0x8).append);
    try testing.expect(classifyFlags(.linux, 0o1000).truncate);
    try testing.expect(classifyFlags(.linux, 0o2000).append);
    try testing.expect(classifyFlags(.windows, 0x100).create);
    try testing.expect(classifyFlags(.linux, 0o20200000 | 2).create);
    try testing.expect(classifyFlags(.linux, 3).write_access);
    try testing.expect(!classifyFlags(.linux, 0).isWrite());
    try testing.expect(classifyFlags(.linux, 1).write_access);
    try testing.expect(classifyFlags(.bsd, 2).write_access);
}

test "symbolic flag encoding round-trips through the decoder" {
    inline for (.{ FlagAbi.linux, FlagAbi.bsd, FlagAbi.windows }) |abi| {
        const f = try encodeFlags(abi, "O_WRONLY|O_CREAT|O_TRUNC");
        const intent = classifyFlags(abi, f);
        try testing.expect(intent.write_access and intent.create and intent.truncate and !intent.append);
        try testing.expectEqual(@as(i32, 0), try encodeFlags(abi, "O_RDONLY"));
        try testing.expect(classifyFlags(abi, try encodeFlags(abi, "O_RDONLY|O_APPEND")).append);
    }
    try testing.expectEqual(@as(i32, 0x241), try encodeFlags(.linux, "0x241"));
    try testing.expectEqual(@as(i32, 577), try encodeFlags(.linux, "577"));
    try testing.expectError(error.UnknownFlag, encodeFlags(.linux, "O_BOGUS"));
    try testing.expectError(error.UnknownFlag, encodeFlags(.bsd, "O_TMPFILE"));
    try testing.expectError(error.InvalidNumber, encodeFlags(.linux, "0xZZ"));
}

test "rules: last match wins and access filters apply" {
    var rules = PathRules{};
    _ = try rules.add("/**", .deny, .write);
    _ = try rules.add("/tmp/**", .allow, .write);
    _ = try rules.add("/tmp/secret/**", .deny, .any);
    try testing.expectEqual(Effect.deny, rules.evaluate("/etc/hosts", true).?.effect);
    try testing.expect(rules.evaluate("/etc/hosts", false) == null);
    try testing.expectEqual(Effect.allow, rules.evaluate("/tmp/build.log", true).?.effect);
    const m = rules.evaluate("/tmp/secret/key", false).?;
    try testing.expectEqual(Effect.deny, m.effect);
    try testing.expectEqual(@as(usize, 2), m.index);
}

test "rules reject invalid patterns and enforce capacity" {
    var rules = PathRules{};
    try testing.expectError(error.EmptyPattern, rules.add("", .deny, .any));
    try testing.expectError(error.RelativePattern, rules.add("etc/*", .deny, .any));
    try testing.expectError(error.InvalidPattern, rules.add("/a\x00b", .deny, .any));
    const long = "/" ++ @as([300]u8, @splat('x'));
    try testing.expectError(error.PatternTooLong, rules.add(long, .deny, .any));
    // Patterns are canonicalized on insertion.
    const idx = try rules.add("/tmp/../etc//**", .deny, .any);
    try testing.expectEqualStrings("/etc/**", rules.items[idx].slice());
    for (1..max_rules) |_| _ = try rules.add("/x", .allow, .read);
    try testing.expectError(error.TooManyRules, rules.add("/y", .allow, .read));
    rules.clear();
    try testing.expect(rules.evaluate("/etc/a", true) == null);
}
