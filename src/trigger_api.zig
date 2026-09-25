const std = @import("std");
const db = @import("db.zig");
const headers = @import("headers.zig");

pub const Event = enum { insert, update, delete };

pub const Spec = struct {
    schema: []const u8,
    table: []const u8,
    events: []const Event,
    method: []const u8,
    url: []const u8,
    headers_json: ?[]const u8,
    timeout_ms: u32,
    max_attempts: u32,
    secret: []const u8,
};

pub fn validate(spec: Spec) !void {
    if (!db.validIdent(spec.schema) or !db.validIdent(spec.table)) return error.InvalidIdentifier;
    if (std.ascii.eqlIgnoreCase(spec.schema, "net")) return error.ReservedSchema;
    if (spec.events.len == 0) return error.NoEvents;
    if (!validMethod(spec.method)) return error.BadMethod;
    if (spec.url.len == 0 or spec.url.len > 2048) return error.BadUrl;
    if (spec.timeout_ms == 0 or spec.timeout_ms > 300_000) return error.BadTimeout;
    if (spec.max_attempts == 0 or spec.max_attempts > 20) return error.BadAttempts;
    if (spec.secret.len == 0 or spec.secret.len > 128) return error.BadSecret;
    if (spec.headers_json) |raw| {
        var scratch: [8192]u8 = undefined;
        var fba = std.heap.FixedBufferAllocator.init(&scratch);
        const pairs = headers.parse(fba.allocator(), raw) catch return error.BadHeaders;
        if (pairs.len > 32) return error.BadHeaders;
    }
}

fn validMethod(method: []const u8) bool {
    const names = [_][]const u8{ "GET", "POST", "PUT", "PATCH", "DELETE" };
    for (names) |name| if (std.mem.eql(u8, method, name)) return true;
    return false;
}

pub fn triggerSql(
    allocator: std.mem.Allocator,
    spec: Spec,
    webhook_id: u64,
    columns: []const []const u8,
    event: Event,
) ![]u8 {
    try validate(spec);
    for (columns) |column| if (!db.validIdent(column)) return error.InvalidIdentifier;
    const suffix = switch (event) {
        .insert => "ai",
        .update => "au",
        .delete => "ad",
    };
    const when = switch (event) {
        .insert => "INSERT",
        .update => "UPDATE",
        .delete => "DELETE",
    };
    const schema_sql = try db.sqlString(allocator, spec.schema);
    defer allocator.free(schema_sql);
    const table_sql = try db.sqlString(allocator, spec.table);
    defer allocator.free(table_sql);
    const method_sql = try db.sqlString(allocator, spec.method);
    defer allocator.free(method_sql);
    const url_sql = try db.sqlString(allocator, spec.url);
    defer allocator.free(url_sql);
    const headers_sql = if (spec.headers_json) |raw|
        try db.sqlString(allocator, raw)
    else
        try allocator.dupe(u8, "NULL");
    defer allocator.free(headers_sql);
    const record = try rowObject(allocator, columns, "NEW");
    defer allocator.free(record);
    const old = try rowObject(allocator, columns, "OLD");
    defer allocator.free(old);
    const body_record = if (event == .delete) "NULL" else record;
    const body_old = if (event == .insert) "NULL" else old;
    const schema_ident = try db.quoteIdent(allocator, spec.schema);
    defer allocator.free(schema_ident);
    const table_ident = try db.quoteIdent(allocator, spec.table);
    defer allocator.free(table_ident);

    return std.fmt.allocPrint(allocator,
        \\CREATE TRIGGER {s}.`net_wh_{d}_{s}` AFTER {s} ON {s}.{s}
        \\FOR EACH ROW
        \\INSERT INTO net.http_request_queue
        \\  (webhook_id, method, url, headers, body, timeout_ms, max_attempts)
        \\VALUES (
        \\  {d},
        \\  {s},
        \\  {s},
        \\  {s},
        \\  JSON_OBJECT('type','{s}','schema',{s},'table',{s},'record',{s},'old_record',{s}),
        \\  {d},
        \\  {d}
        \\)
    , .{
        schema_ident,
        webhook_id,
        suffix,
        when,
        schema_ident,
        table_ident,
        webhook_id,
        method_sql,
        url_sql,
        headers_sql,
        when,
        schema_sql,
        table_sql,
        body_record,
        body_old,
        spec.timeout_ms,
        spec.max_attempts,
    });
}

fn appendSqlLiteral(out: *std.ArrayList(u8), allocator: std.mem.Allocator, value: []const u8) !void {
    try out.append(allocator, '\'');
    for (value) |ch| {
        if (ch == 0) return error.BadColumn;
        if (ch == '\'' or ch == '\\') try out.append(allocator, '\\');
        try out.append(allocator, ch);
    }
    try out.append(allocator, '\'');
}

fn appendIdent(out: *std.ArrayList(u8), allocator: std.mem.Allocator, value: []const u8) !void {
    try out.append(allocator, '`');
    for (value) |ch| {
        if (ch == 0) return error.BadColumn;
        if (ch == '`') try out.append(allocator, '`');
        try out.append(allocator, ch);
    }
    try out.append(allocator, '`');
}

fn rowObject(allocator: std.mem.Allocator, columns: []const []const u8, prefix: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try out.appendSlice(allocator, "JSON_OBJECT(");
    for (columns, 0..) |column, i| {
        if (column.len == 0 or column.len > 64) return error.BadColumn;
        if (i != 0) try out.append(allocator, ',');
        try appendSqlLiteral(&out, allocator, column);
        try out.append(allocator, ',');
        try out.appendSlice(allocator, prefix);
        try out.append(allocator, '.');
        try appendIdent(&out, allocator, column);
    }
    try out.append(allocator, ')');
    return try out.toOwnedSlice(allocator);
}

fn hexLower(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    const alphabet = "0123456789abcdef";
    const out = try allocator.alloc(u8, bytes.len * 2);
    for (bytes, 0..) |byte, i| {
        out[i * 2] = alphabet[byte >> 4];
        out[i * 2 + 1] = alphabet[byte & 0xf];
    }
    return out;
}

pub fn dropTriggerSql(allocator: std.mem.Allocator, schema_name: []const u8, webhook_id: u64, event: Event) ![]u8 {
    if (!db.validIdent(schema_name)) return error.InvalidIdentifier;
    const suffix = switch (event) {
        .insert => "ai",
        .update => "au",
        .delete => "ad",
    };
    const schema_ident = try db.quoteIdent(allocator, schema_name);
    defer allocator.free(schema_ident);
    return std.fmt.allocPrint(allocator, "DROP TRIGGER IF EXISTS {s}.`net_wh_{d}_{s}`", .{ schema_ident, webhook_id, suffix });
}

pub fn createWebhook(database: *db.Db, allocator: std.mem.Allocator, spec: Spec) !u64 {
    try validate(spec);
    const columns = try loadColumns(database, allocator, spec.schema, spec.table);
    defer {
        for (columns) |column| allocator.free(column);
        allocator.free(columns);
    }
    const secret_hex = try hexLower(allocator, spec.secret);
    defer allocator.free(secret_hex);
    const schema_sql = try db.sqlString(allocator, spec.schema);
    defer allocator.free(schema_sql);
    const table_sql = try db.sqlString(allocator, spec.table);
    defer allocator.free(table_sql);
    const events_sql = try db.sqlString(allocator, eventsText(spec.events));
    defer allocator.free(events_sql);
    const method_sql = try db.sqlString(allocator, spec.method);
    defer allocator.free(method_sql);
    const url_sql = try db.sqlString(allocator, spec.url);
    defer allocator.free(url_sql);
    const headers_sql = if (spec.headers_json) |raw|
        try db.sqlString(allocator, raw)
    else
        try allocator.dupe(u8, "NULL");
    defer allocator.free(headers_sql);
    const insert = try std.fmt.allocPrint(allocator,
        \\INSERT INTO net.webhook
        \\  (table_schema, table_name, events, method, url, headers, secret, timeout_ms, max_attempts)
        \\VALUES ({s}, {s}, {s}, {s}, {s}, {s}, UNHEX('{s}'), {d}, {d})
    , .{
        schema_sql,
        table_sql,
        events_sql,
        method_sql,
        url_sql,
        headers_sql,
        secret_hex,
        spec.timeout_ms,
        spec.max_attempts,
    });
    defer allocator.free(insert);
    try database.exec(insert);
    const id = database.insertId();
    errdefer {
        for (spec.events) |event| {
            const drop_sql = dropTriggerSql(allocator, spec.schema, id, event) catch continue;
            defer allocator.free(drop_sql);
            database.exec(drop_sql) catch {};
        }
        if (std.fmt.allocPrint(allocator, "DELETE FROM net.webhook WHERE id = {d}", .{id})) |cleanup| {
            defer allocator.free(cleanup);
            database.exec(cleanup) catch {};
        } else |_| {}
    }
    for (spec.events) |event| {
        const sql = try triggerSql(allocator, spec, id, columns, event);
        defer allocator.free(sql);
        try database.exec(sql);
    }
    return id;
}

pub fn deleteWebhook(database: *db.Db, allocator: std.mem.Allocator, id: u64) !void {
    const lookup = try std.fmt.allocPrint(allocator, "SELECT table_schema FROM net.webhook WHERE id = {d}", .{id});
    defer allocator.free(lookup);
    var rows = try database.query(allocator, lookup);
    defer rows.deinit();
    const row = rows.next() orelse return error.NotFound;
    const schema_name = row.text(0) orelse return error.NotFound;
    const schema_copy = try allocator.dupe(u8, schema_name);
    defer allocator.free(schema_copy);
    rows.deinit();
    const events = [_]Event{ .insert, .update, .delete };
    for (events) |event| {
        const sql = try dropTriggerSql(allocator, schema_copy, id, event);
        defer allocator.free(sql);
        try database.exec(sql);
    }
    const drop_pending = try std.fmt.allocPrint(allocator, "DELETE FROM net.http_request_queue WHERE webhook_id = {d} AND status <> 'processing'", .{id});
    defer allocator.free(drop_pending);
    try database.exec(drop_pending);
    const drop_hook = try std.fmt.allocPrint(allocator, "DELETE FROM net.webhook WHERE id = {d}", .{id});
    defer allocator.free(drop_hook);
    try database.exec(drop_hook);
}

fn loadColumns(database: *db.Db, allocator: std.mem.Allocator, schema_name: []const u8, table: []const u8) ![][]u8 {
    const schema_sql = try db.sqlString(allocator, schema_name);
    defer allocator.free(schema_sql);
    const table_sql = try db.sqlString(allocator, table);
    defer allocator.free(table_sql);
    const sql = try std.fmt.allocPrint(allocator,
        \\SELECT COLUMN_NAME FROM information_schema.COLUMNS
        \\WHERE TABLE_SCHEMA = {s} AND TABLE_NAME = {s}
        \\ORDER BY ORDINAL_POSITION
    , .{ schema_sql, table_sql });
    defer allocator.free(sql);
    var rows = try database.query(allocator, sql);
    defer rows.deinit();
    var columns: std.ArrayList([]u8) = .empty;
    errdefer {
        for (columns.items) |column| allocator.free(column);
        columns.deinit(allocator);
    }
    while (rows.next()) |row| {
        const name = row.text(0) orelse continue;
        try columns.append(allocator, try allocator.dupe(u8, name));
    }
    if (columns.items.len == 0) return error.TableNotFound;
    return try columns.toOwnedSlice(allocator);
}

fn eventsText(events: []const Event) []const u8 {
    var insert = false;
    var update = false;
    var delete = false;
    for (events) |event| switch (event) {
        .insert => insert = true,
        .update => update = true,
        .delete => delete = true,
    };
    if (insert and update and delete) return "INSERT,UPDATE,DELETE";
    if (insert and update) return "INSERT,UPDATE";
    if (insert and delete) return "INSERT,DELETE";
    if (update and delete) return "UPDATE,DELETE";
    if (insert) return "INSERT";
    if (update) return "UPDATE";
    return "DELETE";
}

pub fn parseEvents(text: []const u8) ![]const Event {
    if (std.mem.eql(u8, text, "INSERT")) return &.{.insert};
    if (std.mem.eql(u8, text, "UPDATE")) return &.{.update};
    if (std.mem.eql(u8, text, "DELETE")) return &.{.delete};
    if (std.mem.eql(u8, text, "INSERT,UPDATE")) return &.{ .insert, .update };
    if (std.mem.eql(u8, text, "INSERT,DELETE")) return &.{ .insert, .delete };
    if (std.mem.eql(u8, text, "UPDATE,DELETE")) return &.{ .update, .delete };
    if (std.mem.eql(u8, text, "INSERT,UPDATE,DELETE")) return &.{ .insert, .update, .delete };
    return error.BadEvents;
}

test "trigger inserts the queue row and does not embed the secret" {
    const spec = Spec{
        .schema = "app",
        .table = "events",
        .events = &.{.insert},
        .method = "POST",
        .url = "https://example.com/hook",
        .headers_json = null,
        .timeout_ms = 5000,
        .max_attempts = 5,
        .secret = "top-secret",
    };
    const sql = try triggerSql(std.testing.allocator, spec, 7, &.{ "id", "name" }, .insert);
    defer std.testing.allocator.free(sql);
    try std.testing.expect(std.mem.indexOf(u8, sql, "INSERT INTO net.http_request_queue") != null);
    try std.testing.expect(std.mem.indexOf(u8, sql, "NEW.`id`") != null);
    try std.testing.expect(std.mem.indexOf(u8, sql, "NEW.`name`") != null);
    try std.testing.expect(std.mem.indexOf(u8, sql, "'old_record',NULL") != null);
    try std.testing.expect(std.mem.indexOf(u8, sql, "top-secret") == null);
    const injected = "a',(SELECT 'PWNED' INTO @maria_net_pwn),'b";
    const body = try rowObject(std.testing.allocator, &.{injected}, "NEW");
    defer std.testing.allocator.free(body);
    try std.testing.expect(std.mem.indexOf(u8, body, "'a',(SELECT") == null);
    const backtick = "a`,(SELECT 1),`b";
    const ident = try rowObject(std.testing.allocator, &.{backtick}, "NEW");
    defer std.testing.allocator.free(ident);
    try std.testing.expect(std.mem.indexOf(u8, ident, "NEW.`a`,(SELECT") == null);
    try std.testing.expectError(error.ReservedSchema, validate(.{
        .schema = "net",
        .table = "http_response",
        .events = &.{.insert},
        .method = "POST",
        .url = "https://example.com/hook",
        .headers_json = null,
        .timeout_ms = 5000,
        .max_attempts = 5,
        .secret = "top-secret",
    }));
}
