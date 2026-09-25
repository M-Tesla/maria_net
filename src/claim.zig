const std = @import("std");
const db = @import("db.zig");

pub const Row = struct {
    id: u64,
    webhook_id: u64,
    method: []u8,
    url: []u8,
    headers_json: ?[]u8,
    body: []u8,
    timeout_ms: u32,
    attempts: u32,
    max_attempts: u32,
    secret: []u8,
    missing_webhook: bool,

    pub fn deinit(self: *Row, allocator: std.mem.Allocator) void {
        allocator.free(self.method);
        allocator.free(self.url);
        if (self.headers_json) |value| allocator.free(value);
        allocator.free(self.body);
        allocator.free(self.secret);
    }
};

pub fn reclaimStale(database: *db.Db) !u64 {
    try database.exec(
        \\UPDATE net.http_request_queue
        \\SET status = 'pending', claim_token = NULL, locked_at = NULL
        \\WHERE status = 'processing'
        \\  AND locked_at IS NOT NULL
        \\  AND TIMESTAMPDIFF(MICROSECOND, locked_at, NOW(3)) > CAST(timeout_ms AS SIGNED) * 1000 + 30000000
    );
    return database.affected();
}

pub fn claim(database: *db.Db, allocator: std.mem.Allocator, limit: u32, token: []const u8) ![]Row {
    if (!hexToken(token) or limit == 0 or limit > 64) return error.BadClaim;
    try database.exec("START TRANSACTION");
    var open = true;
    errdefer if (open) database.exec("ROLLBACK") catch {};
    const picked = try pickIds(database, allocator, limit);
    defer allocator.free(picked);
    if (picked.len == 0) {
        try database.exec("COMMIT");
        open = false;
        return allocator.alloc(Row, 0);
    }

    var in_list: std.ArrayList(u8) = .empty;
    defer in_list.deinit(allocator);
    for (picked, 0..) |id, i| {
        if (i != 0) try in_list.append(allocator, ',');
        const piece = try std.fmt.allocPrint(allocator, "{d}", .{id});
        defer allocator.free(piece);
        try in_list.appendSlice(allocator, piece);
    }
    const token_sql = try db.sqlString(allocator, token);
    defer allocator.free(token_sql);
    const update = try std.fmt.allocPrint(allocator,
        \\UPDATE net.http_request_queue
        \\SET status = 'processing', claim_token = {s}, locked_at = NOW(3)
        \\WHERE id IN ({s})
        \\  AND status = 'pending'
        \\  AND available_at <= NOW(3)
    , .{ token_sql, in_list.items });
    defer allocator.free(update);
    try database.exec(update);
    database.exec("COMMIT") catch |err| {
        const errno = database.errno;
        open = false;
        database.exec("ROLLBACK") catch {};
        if (errno == db.commit_conflict or errno == db.lock_deadlock) return allocator.alloc(Row, 0);
        return err;
    };
    open = false;

    const selected = try std.fmt.allocPrint(allocator,
        \\SELECT q.id, q.webhook_id, q.method, q.url, q.headers, q.body,
        \\       q.timeout_ms, q.attempts, q.max_attempts, HEX(w.secret)
        \\FROM net.http_request_queue q
        \\LEFT JOIN net.webhook w ON w.id = q.webhook_id
        \\WHERE q.claim_token = {s} AND q.status = 'processing'
    , .{token_sql});
    defer allocator.free(selected);
    var rows_result = try database.query(allocator, selected);
    defer rows_result.deinit();
    var rows: std.ArrayList(Row) = .empty;
    errdefer {
        for (rows.items) |*row| row.deinit(allocator);
        rows.deinit(allocator);
    }
    while (rows_result.next()) |row| {
        const secret_hex = row.text(9);
        const secret = if (secret_hex) |hex| try decodeHex(allocator, hex) else try allocator.alloc(u8, 0);
        errdefer allocator.free(secret);
        try rows.append(allocator, .{
            .id = row.int(0) orelse 0,
            .webhook_id = row.int(1) orelse 0,
            .method = try allocator.dupe(u8, row.text(2) orelse ""),
            .url = try allocator.dupe(u8, row.text(3) orelse ""),
            .headers_json = if (row.text(4)) |value| try allocator.dupe(u8, value) else null,
            .body = try allocator.dupe(u8, row.text(5) orelse ""),
            .timeout_ms = @intCast(row.int(6) orelse 5000),
            .attempts = @intCast(row.int(7) orelse 0),
            .max_attempts = @intCast(row.int(8) orelse 5),
            .secret = secret,
            .missing_webhook = secret_hex == null,
        });
    }
    return try rows.toOwnedSlice(allocator);
}

fn pickIds(database: *db.Db, allocator: std.mem.Allocator, limit: u32) ![]u64 {
    const pick = try std.fmt.allocPrint(allocator,
        \\SELECT id FROM net.http_request_queue
        \\WHERE status = 'pending' AND available_at <= NOW(3)
        \\ORDER BY id
        \\LIMIT {d}
    , .{limit});
    defer allocator.free(pick);
    var ids_result = try database.query(allocator, pick);
    defer ids_result.deinit();
    var ids: std.ArrayList(u64) = .empty;
    errdefer ids.deinit(allocator);
    while (ids_result.next()) |row| {
        try ids.append(allocator, row.int(0) orelse continue);
    }
    return try ids.toOwnedSlice(allocator);
}

pub fn freeRows(allocator: std.mem.Allocator, rows: []Row) void {
    for (rows) |*row| row.deinit(allocator);
    allocator.free(rows);
}

pub fn finish(
    database: *db.Db,
    allocator: std.mem.Allocator,
    row: Row,
    token: []const u8,
    outcome: []const u8,
    status_code: ?u32,
    latency_ms: u32,
    error_text: []const u8,
    response_body: []const u8,
    retry_delay_ms: ?u64,
) !void {
    if (!hexToken(token)) return error.BadClaim;
    const token_sql = try db.sqlString(allocator, token);
    defer allocator.free(token_sql);
    const outcome_sql = try db.sqlString(allocator, outcome);
    defer allocator.free(outcome_sql);
    const err_sql = if (error_text.len == 0)
        try allocator.dupe(u8, "NULL")
    else
        try db.sqlString(allocator, error_text[0..@min(error_text.len, 480)]);
    defer allocator.free(err_sql);
    const body_sql = try db.sqlString(allocator, response_body[0..@min(response_body.len, 65536)]);
    defer allocator.free(body_sql);
    const status_sql = if (status_code) |code|
        try std.fmt.allocPrint(allocator, "{d}", .{code})
    else
        try allocator.dupe(u8, "NULL");
    defer allocator.free(status_sql);
    const attempt = row.attempts + 1;
    const insert = try std.fmt.allocPrint(allocator,
        \\INSERT INTO net.http_response
        \\  (request_id, webhook_id, attempt, outcome, status_code, latency_ms, error, body)
        \\VALUES ({d}, {d}, {d}, {s}, {s}, {d}, {s}, {s})
    , .{ row.id, row.webhook_id, attempt, outcome_sql, status_sql, latency_ms, err_sql, body_sql });
    defer allocator.free(insert);

    var tries: u8 = 0;
    while (tries < 20) : (tries += 1) {
        try database.exec("START TRANSACTION");
        errdefer database.exec("ROLLBACK") catch {};
        try database.exec(insert);
        if (retry_delay_ms) |delay| {
            const update = try std.fmt.allocPrint(allocator,
                \\UPDATE net.http_request_queue
                \\SET status = 'pending', claim_token = NULL, locked_at = NULL,
                \\    attempts = attempts + 1,
                \\    available_at = DATE_ADD(NOW(3), INTERVAL {d} MICROSECOND),
                \\    last_error = {s}
                \\WHERE id = {d} AND claim_token = {s} AND status = 'processing'
            , .{ delay * 1000, err_sql, row.id, token_sql });
            defer allocator.free(update);
            try database.exec(update);
        } else {
            const delete_sql = try std.fmt.allocPrint(allocator,
                \\DELETE FROM net.http_request_queue
                \\WHERE id = {d} AND claim_token = {s} AND status = 'processing'
            , .{ row.id, token_sql });
            defer allocator.free(delete_sql);
            try database.exec(delete_sql);
        }
        database.exec("COMMIT") catch |err| {
            const errno = database.errno;
            database.exec("ROLLBACK") catch {};
            if (errno == db.commit_conflict or errno == db.lock_deadlock) {
                var pause = std.os.linux.timespec{ .sec = 0, .nsec = 2_000_000 * @as(isize, tries + 1) };
                _ = std.os.linux.nanosleep(&pause, null);
                continue;
            }
            return err;
        };
        return;
    }
    return error.Busy;
}

pub fn hexToken(token: []const u8) bool {
    if (token.len != 32) return false;
    for (token) |ch| {
        const ok = std.ascii.isDigit(ch) or (ch >= 'a' and ch <= 'f');
        if (!ok) return false;
    }
    return true;
}

pub fn newToken() [32]u8 {
    var bytes: [16]u8 = undefined;
    const n = std.os.linux.getrandom(&bytes, bytes.len, 0);
    if (@as(isize, @bitCast(n)) != bytes.len) @panic("getrandom");
    return std.fmt.bytesToHex(bytes, .lower);
}

fn decodeHex(allocator: std.mem.Allocator, hex: []const u8) ![]u8 {
    if (hex.len % 2 != 0) return error.BadSecret;
    const out = try allocator.alloc(u8, hex.len / 2);
    errdefer allocator.free(out);
    _ = std.fmt.hexToBytes(out, hex) catch return error.BadSecret;
    return out;
}

test "claim token is 32 hex chars" {
    const token = newToken();
    try std.testing.expect(hexToken(&token));
    try std.testing.expect(!hexToken("nope"));
}
