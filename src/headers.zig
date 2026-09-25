const std = @import("std");

pub const Pair = struct { key: []const u8, value: []const u8 };

pub fn parse(allocator: std.mem.Allocator, raw: []const u8) ![]Pair {
    var i: usize = 0;
    while (i < raw.len and std.ascii.isWhitespace(raw[i])) i += 1;
    if (i >= raw.len or raw[i] != '{') return error.BadJson;
    i += 1;
    var pairs: std.ArrayList(Pair) = .empty;
    errdefer {
        for (pairs.items) |pair| {
            allocator.free(pair.key);
            allocator.free(pair.value);
        }
        pairs.deinit(allocator);
    }
    while (i < raw.len) {
        while (i < raw.len and std.ascii.isWhitespace(raw[i])) i += 1;
        if (i < raw.len and raw[i] == '}') {
            return try pairs.toOwnedSlice(allocator);
        }
        if (pairs.items.len != 0) {
            if (i >= raw.len or raw[i] != ',') return error.BadJson;
            i += 1;
            while (i < raw.len and std.ascii.isWhitespace(raw[i])) i += 1;
        }
        const key = try parseString(allocator, raw, &i);
        errdefer allocator.free(key);
        while (i < raw.len and std.ascii.isWhitespace(raw[i])) i += 1;
        if (i >= raw.len or raw[i] != ':') return error.BadJson;
        i += 1;
        while (i < raw.len and std.ascii.isWhitespace(raw[i])) i += 1;
        const value = try parseString(allocator, raw, &i);
        try pairs.append(allocator, .{ .key = key, .value = value });
    }
    return error.BadJson;
}

fn parseString(allocator: std.mem.Allocator, raw: []const u8, i: *usize) ![]u8 {
    if (i.* >= raw.len or raw[i.*] != '"') return error.BadJson;
    i.* += 1;
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    while (i.* < raw.len) {
        const ch = raw[i.*];
        i.* += 1;
        if (ch == '"') return try out.toOwnedSlice(allocator);
        if (ch == '\\') {
            if (i.* >= raw.len) return error.BadJson;
            const esc = raw[i.*];
            i.* += 1;
            switch (esc) {
                '"', '\\', '/' => try out.append(allocator, esc),
                'n' => try out.append(allocator, '\n'),
                'r' => try out.append(allocator, '\r'),
                't' => try out.append(allocator, '\t'),
                else => return error.BadJson,
            }
        } else {
            if (ch < 0x20) return error.BadJson;
            try out.append(allocator, ch);
        }
    }
    return error.BadJson;
}

pub fn reserved(key: []const u8) bool {
    const names = [_][]const u8{ "host", "content-length", "transfer-encoding", "x-maria-signature", "x-request-id", "x-maria-timestamp" };
    for (names) |name| if (std.ascii.eqlIgnoreCase(key, name)) return true;
    return false;
}

pub fn safePair(key: []const u8, value: []const u8) bool {
    if (key.len == 0 or key.len > 64 or value.len > 1024) return false;
    for (key) |ch| {
        const ok = std.ascii.isAlphanumeric(ch) or ch == '-' or ch == '_';
        if (!ok) return false;
    }
    for (value) |ch| {
        if (ch < 0x20 or ch == 0x7f) return false;
    }
    return true;
}

test "header object parses and keeps string values" {
    const pairs = try parse(std.testing.allocator, "{\"X-App\":\"demo\",\"N\":\"1\"}");
    defer {
        for (pairs) |pair| {
            std.testing.allocator.free(pair.key);
            std.testing.allocator.free(pair.value);
        }
        std.testing.allocator.free(pairs);
    }
    try std.testing.expectEqual(@as(usize, 2), pairs.len);
    try std.testing.expectEqualStrings("demo", pairs[0].value);
    try std.testing.expect(reserved("Host"));
    try std.testing.expect(!reserved("X-App"));
}
