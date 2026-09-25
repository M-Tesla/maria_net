const std = @import("std");

pub const Verdict = enum { allow, blocked, transient };

pub fn classify4(octets: [4]u8, allow_loopback: bool) Verdict {
    const a = octets[0];
    const b = octets[1];
    if (a == 127) return if (allow_loopback) .allow else .blocked;
    if (a == 0 or a >= 224) return .blocked;
    if (a == 10) return .blocked;
    if (a == 169 and b == 254) return .blocked;
    if (a == 172 and b >= 16 and b <= 31) return .blocked;
    if (a == 192 and b == 168) return .blocked;
    if (a == 100 and b >= 64 and b <= 127) return .blocked;
    if (a == 192 and b == 0 and octets[2] == 0) return .blocked;
    if (a == 198 and (b == 18 or b == 19)) return .blocked;
    return .allow;
}

pub fn classify6(octets: [16]u8, allow_loopback: bool) Verdict {
    if (std.mem.eql(u8, octets[0..12], &.{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff })) {
        return classify4(octets[12..16].*, allow_loopback);
    }
    const loopback = std.mem.eql(u8, &octets, &.{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 });
    if (loopback) return if (allow_loopback) .allow else .blocked;
    const unspecified = std.mem.allEqual(u8, &octets, 0);
    if (unspecified) return .blocked;
    if (std.mem.allEqual(u8, octets[0..12], 0)) return classify4(octets[12..16].*, allow_loopback);
    if (octets[0] == 0x20 and octets[1] == 0x02) {
        return classify4(.{ octets[2], octets[3], octets[4], octets[5] }, allow_loopback);
    }
    if (octets[0] == 0x20 and octets[1] == 0x01 and octets[2] == 0 and octets[3] == 0) {
        return classify4(.{
            octets[12] ^ 0xff,
            octets[13] ^ 0xff,
            octets[14] ^ 0xff,
            octets[15] ^ 0xff,
        }, allow_loopback);
    }
    if (octets[0] == 0x00 and octets[1] == 0x64 and octets[2] == 0xff and octets[3] == 0x9b and octets[4] == 0 and octets[5] <= 1) {
        return classify4(octets[12..16].*, allow_loopback);
    }
    if (octets[0] & 0xfe == 0xfc) return .blocked;
    if (octets[0] == 0xfe and (octets[1] & 0xc0) == 0x80) return .blocked;
    if (octets[0] == 0xfe and (octets[1] & 0xc0) == 0xc0) return .blocked;
    if (octets[0] == 0xff) return .blocked;
    return .allow;
}

fn blockedName(host: []const u8) bool {
    var name = host;
    if (name.len > 1 and name[name.len - 1] == '.') name = name[0 .. name.len - 1];
    const names = [_][]const u8{
        "localhost",
        "localhost.localdomain",
        "metadata.google.internal",
        "metadata.google.com",
    };
    for (names) |item| {
        if (std.ascii.eqlIgnoreCase(name, item)) return true;
    }
    const suffixes = [_][]const u8{ ".local", ".localhost", ".localdomain", ".internal" };
    for (suffixes) |suffix| {
        if (name.len > suffix.len and std.ascii.endsWithIgnoreCase(name, suffix)) return true;
    }
    return false;
}

fn bareHost(host: []const u8) []const u8 {
    var name = host;
    if (name.len > 1 and name[name.len - 1] == '.') name = name[0 .. name.len - 1];
    if (name.len >= 2 and name[0] == '[' and name[name.len - 1] == ']') name = name[1 .. name.len - 1];
    return name;
}

fn exoticHost(host: []const u8) bool {
    for (host) |ch| {
        if (ch < 0x20 or ch >= 0x7f or ch == '%' or ch == '\\' or ch == '@' or ch == '/' or ch == '#' or ch == ' ') return true;
    }
    return false;
}

fn curlNumeric(host: []const u8) bool {
    var digit = false;
    for (host) |ch| {
        if (std.ascii.isDigit(ch)) {
            digit = true;
            continue;
        }
        const ok = ch == '.' or ch == 'x' or ch == 'X' or std.ascii.isHex(ch);
        if (!ok) return false;
    }
    return digit;
}

pub const Resolved = struct {
    host: []const u8,
    port: u16,
    ip: []u8,
};

pub const ResolveError = error{
    Blocked,
    BadUrl,
    Transient,
    OutOfMemory,
};

pub fn checkUrl(allocator: std.mem.Allocator, raw: []const u8, allow_loopback: bool) ResolveError!Resolved {
    const uri = std.Uri.parse(raw) catch return error.BadUrl;
    if (uri.user != null or uri.password != null) return error.BadUrl;
    const scheme = uri.scheme;
    const https = std.ascii.eqlIgnoreCase(scheme, "https");
    const http = std.ascii.eqlIgnoreCase(scheme, "http");
    if (!https and !http) return error.BadUrl;
    const host_component = uri.host orelse return error.BadUrl;
    const encoded = switch (host_component) {
        .percent_encoded => |text| std.mem.indexOfScalar(u8, text, '%') != null,
        .raw => false,
    };
    const host_view = host_component.toRawMaybeAlloc(allocator) catch return error.OutOfMemory;
    defer if (encoded) allocator.free(host_view);
    const decoded = try allocator.dupe(u8, host_view);
    const trimmed = bareHost(decoded);
    const host = if (trimmed.len == decoded.len) decoded else blk: {
        const copy = allocator.dupe(u8, trimmed) catch {
            allocator.free(decoded);
            return error.OutOfMemory;
        };
        allocator.free(decoded);
        break :blk copy;
    };
    errdefer allocator.free(host);
    if (host.len == 0 or host.len > 253 or blockedName(host) or exoticHost(host)) return error.Blocked;
    const port = uri.port orelse if (https) @as(u16, 443) else @as(u16, 80);
    if (std.Io.net.IpAddress.parse(host, port)) |literal| {
        const verdict: Verdict = switch (literal) {
            .ip4 => |ip4| classify4(ip4.bytes, allow_loopback),
            .ip6 => |ip6| classify6(ip6.bytes, allow_loopback),
        };
        if (verdict != .allow) return error.Blocked;
        const ip = try renderIp(allocator, literal);
        return .{ .host = host, .port = port, .ip = ip };
    } else |_| {}
    if (curlNumeric(host) or std.mem.indexOfScalar(u8, host, ':') != null) return error.Blocked;

    const looked = lookup(host) catch return error.Transient;
    defer freeaddrinfo(looked);
    var cursor: ?*AddrInfo = looked;
    var chosen: ?std.Io.net.IpAddress = null;
    while (cursor) |ai| : (cursor = ai.next) {
        const parsed = ipFromSock(ai) orelse continue;
        const verdict: Verdict = switch (parsed) {
            .ip4 => |ip4| classify4(ip4.bytes, allow_loopback),
            .ip6 => |ip6| classify6(ip6.bytes, allow_loopback),
        };
        if (verdict == .blocked) return error.Blocked;
        if (chosen == null) chosen = parsed;
    }
    const addr = chosen orelse return error.Transient;
    const ip = try renderIp(allocator, addr);
    return .{ .host = host, .port = port, .ip = ip };
}

const AddrInfo = extern struct {
    flags: c_int,
    family: c_int,
    socktype: c_int,
    protocol: c_int,
    addrlen: u32,
    addr: ?*std.posix.sockaddr,
    canonname: ?[*]u8,
    next: ?*AddrInfo,
};

extern "c" fn getaddrinfo(
    node: [*:0]const u8,
    service: ?[*:0]const u8,
    hints: *const AddrInfo,
    res: *?*AddrInfo,
) c_int;
extern "c" fn freeaddrinfo(res: *AddrInfo) void;

fn lookup(host: []const u8) error{Transient}!*AddrInfo {
    var name_buf: [254]u8 = undefined;
    if (host.len >= name_buf.len) return error.Transient;
    @memcpy(name_buf[0..host.len], host);
    name_buf[host.len] = 0;
    var hints: AddrInfo = .{
        .flags = 0,
        .family = std.posix.AF.UNSPEC,
        .socktype = std.posix.SOCK.STREAM,
        .protocol = 0,
        .addrlen = 0,
        .addr = null,
        .canonname = null,
        .next = null,
    };
    var out: ?*AddrInfo = null;
    const rc = getaddrinfo(@ptrCast(&name_buf), null, &hints, &out);
    if (rc != 0 or out == null) return error.Transient;
    return out.?;
}

fn ipFromSock(ai: *AddrInfo) ?std.Io.net.IpAddress {
    const addr = ai.addr orelse return null;
    if (ai.family == std.posix.AF.INET) {
        const in: *const std.posix.sockaddr.in = @ptrCast(@alignCast(addr));
        const bytes = std.mem.asBytes(&in.addr);
        return .{ .ip4 = .{ .bytes = bytes.*, .port = 0 } };
    }
    if (ai.family == std.posix.AF.INET6) {
        const in6: *const std.posix.sockaddr.in6 = @ptrCast(@alignCast(addr));
        return .{ .ip6 = .{ .bytes = in6.addr, .port = 0 } };
    }
    return null;
}

fn renderIp(allocator: std.mem.Allocator, ip: std.Io.net.IpAddress) ![]u8 {
    return switch (ip) {
        .ip4 => |v| try std.fmt.allocPrint(allocator, "{d}.{d}.{d}.{d}", .{ v.bytes[0], v.bytes[1], v.bytes[2], v.bytes[3] }),
        .ip6 => |v| try std.fmt.allocPrint(allocator, "{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}", .{
            v.bytes[0],  v.bytes[1],  v.bytes[2],  v.bytes[3],
            v.bytes[4],  v.bytes[5],  v.bytes[6],  v.bytes[7],
            v.bytes[8],  v.bytes[9],  v.bytes[10], v.bytes[11],
            v.bytes[12], v.bytes[13], v.bytes[14], v.bytes[15],
        }),
    };
}

pub fn resolveLine(allocator: std.mem.Allocator, host: []const u8, port: u16, ip: []const u8) ![]u8 {
    if (std.mem.indexOfScalar(u8, ip, ':') != null) {
        return std.fmt.allocPrint(allocator, "{s}:{d}:[{s}]", .{ host, port, ip });
    }
    return std.fmt.allocPrint(allocator, "{s}:{d}:{s}", .{ host, port, ip });
}

test "private and metadata addresses are blocked" {
    try std.testing.expectEqual(Verdict.blocked, classify4(.{ 169, 254, 169, 254 }, false));
    try std.testing.expectEqual(Verdict.blocked, classify4(.{ 10, 1, 2, 3 }, false));
    try std.testing.expectEqual(Verdict.blocked, classify4(.{ 192, 168, 0, 8 }, false));
    try std.testing.expectEqual(Verdict.blocked, classify4(.{ 172, 16, 0, 1 }, false));
    try std.testing.expectEqual(Verdict.blocked, classify4(.{ 127, 0, 0, 1 }, false));
    try std.testing.expectEqual(Verdict.allow, classify4(.{ 127, 0, 0, 1 }, true));
    try std.testing.expectEqual(Verdict.allow, classify4(.{ 1, 1, 1, 1 }, false));
    try std.testing.expectEqual(Verdict.blocked, classify6(.{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 169, 254, 169, 254 }, false));
    try std.testing.expectEqual(Verdict.blocked, classify6(.{ 0x20, 0x02, 10, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, false));
    try std.testing.expectEqual(Verdict.allow, classify6(.{ 0x20, 0x02, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, false));
    try std.testing.expectEqual(Verdict.blocked, classify6(.{ 0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255 - 10, 255, 255, 255 }, false));
    try std.testing.expectEqual(Verdict.blocked, classify6(.{ 0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 169, 254, 169, 254 }, false));
    try std.testing.expectEqual(Verdict.blocked, classify4(.{ 192, 0, 0, 1 }, false));
    try std.testing.expectEqual(Verdict.blocked, classify4(.{ 198, 18, 0, 1 }, false));
}

test "url policy rejects loopback, userinfo and metadata names" {
    const gpa = std.testing.allocator;
    const blocked = checkUrl(gpa, "http://169.254.169.254/latest", false);
    try std.testing.expectError(error.Blocked, blocked);
    const loopback = checkUrl(gpa, "http://127.0.0.1/hook", false);
    try std.testing.expectError(error.Blocked, loopback);
    const allowed = try checkUrl(gpa, "http://127.0.0.1:9/hook", true);
    defer {
        gpa.free(allowed.host);
        gpa.free(allowed.ip);
    }
    try std.testing.expectEqual(@as(u16, 9), allowed.port);
    try std.testing.expectError(error.BadUrl, checkUrl(gpa, "http://user:pass@1.1.1.1/", false));
    try std.testing.expectError(error.Blocked, checkUrl(gpa, "http://metadata.google.internal/", false));
    try std.testing.expectError(error.Blocked, checkUrl(gpa, "http://foo.internal/latest", false));
    try std.testing.expectError(error.BadUrl, checkUrl(gpa, "ftp://1.1.1.1/", false));
}

test "curl address tricks and rebinding names stay blocked" {
    const gpa = std.testing.allocator;
    const urls = [_][]const u8{
        "http://2130706433/",
        "http://0x7f000001/",
        "http://0177.0.0.1/",
        "http://127.1/",
        "http://127.0.1/",
        "http://0x7f.0.0.1/",
        "http://0x7f.0x0.0x0.0x1/",
        "http://0/",
        "http://0.0.0.0/",
        "http://0xA9FEA9FE/",
        "http://2852039166/",
        "http://025177524776/",
        "http://[::1]/",
        "http://[::]/",
        "http://[::ffff:127.0.0.1]/",
        "http://[::ffff:7f00:1]/",
        "http://[::ffff:169.254.169.254]/",
        "http://[0:0:0:0:0:ffff:169.254.169.254]/",
        "http://[::ffff:a9fe:a9fe]/",
        "http://[fd00:ec2::254]/",
        "http://[fe80::1%25eth0]/",
        "http://127。0。0。1/",
        "http://example.com%23@127.0.0.1/",
        "http://1.1.1.1%5C@127.0.0.1/",
        "http://127.0.0.1.nip.io/",
        "http://169.254.169.254.nip.io/",
        "http://10.0.0.1.nip.io/",
        "http://localtest.me/",
        "http://spoofed.burpcollaborator.net/",
        "http://customer1.app.localhost.localdomain/",
        "http://0x7f.1/",
        "http://0177.1/",
        "http://10.1/",
        "http://10.0.1/",
        "http://172.16.1/",
        "http://192.168.1/",
        "http://017700000001/",
        "http://0x0a000001/",
        "http://0xA9.0xFE.0xA9.0xFE/",
        "http://127.0.0.1./",
        "http://127.00.00.01/",
        "http://127.0.0.01/",
        "http://[::ffff:10.0.0.1]/",
        "http://[::ffff:a00:1]/",
        "http://[::ffff:c0a8:1]/",
        "http://[2002:7f00:1::]/",
        "http://[2002:a9fe:a9fe::]/",
        "http://[64:ff9b::169.254.169.254]/",
        "http://[64:ff9b::a9fe:a9fe]/",
        "http://[fd00::1]/",
        "http://[fc00::1]/",
        "http://[fec0::1]/",
        "http://[0:0:0:0:0:0:0:1]/",
        "http://127%2e0%2e0%2e1/",
        "http://127.0.0.1%00/",
        "http://1.1.1.1%00.127.0.0.1/",
        "http://127.0.0.1%23@1.1.1.1/",
        "http://1.1.1.1%3f@127.0.0.1/",
        "http://localhost./",
        "http://foo.local/",
        "http://metadata.google.internal./",
        "http://127｡0｡0｡1/",
        "http://127．0．0．1/",
        "http://127․0․0․1/",
        "https://127.0.0.1/",
        "http://0300.0250.0.1/",
        "http://0x7f.0.1/",
        "file:///etc/passwd",
        "gopher://127.0.0.1:70/",
        "dict://127.0.0.1:2628/",
        "http://127.0.0.1#.example.com/",
        "http://127.0.0.1?.example.com/",
        "http://127.0.0.1:80\\@1.1.1.1/",
        "http://1.1.1.1:80\\@127.0.0.1/",
        "http://①②⑦.0.0.1/",
        "http://127.0.0.1%E3%80%82/",
        "http://0.0.0.0.nip.io/",
        "http://[::ffff:0:127.0.0.1]/",
    };
    for (urls) |url| {
        const result = checkUrl(gpa, url, false);
        if (result) |resolved| {
            gpa.free(resolved.host);
            gpa.free(resolved.ip);
            std.debug.print("allowed {s}\n", .{url});
            return error.Allowed;
        } else |err| {
            try std.testing.expect(err == error.Blocked or err == error.BadUrl);
        }
    }
    const public_literal = try checkUrl(gpa, "http://1.1.1.1/hook", false);
    defer {
        gpa.free(public_literal.host);
        gpa.free(public_literal.ip);
    }
    try std.testing.expectEqualStrings("1.1.1.1", public_literal.ip);
}
