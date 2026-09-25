const std = @import("std");
const claim = @import("claim.zig");
const daemon = @import("daemon.zig");
const db = @import("db.zig");
const schema = @import("schema.zig");
const trigger_api = @import("trigger_api.zig");

const linux = std.os.linux;

// pg_net's pytest suite, mapped onto the trigger and the queue.
// Shared contract: the SQL call returns before HTTP, rollback drops the
// request, GET/POST/DELETE/headers/body arrive, a timeout or a refused
// connection becomes an error row, and the worker still accepts the next
// request. Redirects and HTTP 500 stay on this side of the comparison:
// pg_net follows redirects and stores 500 as SUCCESS; this daemon does neither.

pub var gate: std.atomic.Mutex = .unlocked;

pub fn lockGate() void {
    while (!gate.tryLock()) {
        var req = linux.timespec{ .sec = 0, .nsec = 1_000_000 };
        _ = linux.nanosleep(&req, null);
    }
}

pub fn unlockGate() void {
    gate.unlock();
}

fn lockMutex(mu: *std.atomic.Mutex) void {
    while (!mu.tryLock()) {
        var req = linux.timespec{ .sec = 0, .nsec = 1_000_000 };
        _ = linux.nanosleep(&req, null);
    }
}

const Probe = struct {
    mu: std.atomic.Mutex = .unlocked,
    stop: std.atomic.Value(bool) = .init(false),
    hits: std.atomic.Value(u32) = .init(0),
    finals: std.atomic.Value(u32) = .init(0),
    head: [2048]u8 = undefined,
    head_len: usize = 0,
    req_body: [1024]u8 = undefined,
    req_body_len: usize = 0,
};

const Listener = struct {
    fd: i32,
    port: u16,

    fn close(self: *Listener) void {
        _ = linux.close(self.fd);
    }
};

const Saved = struct {
    outcome: []u8,
    status: ?u64,
    body: []u8,
    err: []u8,

    fn deinit(self: *Saved, allocator: std.mem.Allocator) void {
        allocator.free(self.outcome);
        allocator.free(self.body);
        allocator.free(self.err);
    }
};

pub fn run(
    allocator: std.mem.Allocator,
    io: std.Io,
    host: [:0]const u8,
    user: [:0]const u8,
    password: [:0]const u8,
    port: u16,
) !void {
    var database = try db.Db.open(allocator, host, user, password, null, port);
    defer database.deinit();
    try schema.requireAvailable(&database);
    try database.execScript(schema.sql);
    try daemon.installSwitch(&database);
    try database.exec("DROP DATABASE IF EXISTS app");
    try database.exec("CREATE DATABASE app");
    const create = try std.fmt.allocPrint(allocator, "CREATE TABLE app.events (id INT NOT NULL PRIMARY KEY, name VARCHAR(64) NOT NULL) {s}", .{schema.table_options});
    defer allocator.free(create);
    try database.exec(create);
    try clearNet(&database);

    var listener = try listenLoopback();
    defer listener.close();
    var probe = Probe{};
    const server = try std.Thread.spawn(.{}, serve, .{ &listener, &probe });
    defer {
        probe.stop.store(true, .seq_cst);
        _ = linux.shutdown(listener.fd, linux.SHUT.RDWR);
        server.join();
    }

    const ok_url = try std.fmt.allocPrint(allocator, "http://127.0.0.1:{d}/ok", .{listener.port});
    defer allocator.free(ok_url);
    const hook = try trigger_api.createWebhook(&database, allocator, .{
        .schema = "app",
        .table = "events",
        .events = &.{.insert},
        .method = "GET",
        .url = ok_url,
        .headers_json = null,
        .timeout_ms = 2000,
        .max_attempts = 1,
        .secret = "pg-net-secret",
    });

    try requestIdBeforeHttp(&database, allocator, &probe, host, user, password, port);
    try rollbackDropsRequest(&database, allocator, &probe);
    try collectGetAfterCommit(&database, allocator, &probe, io, host, user, password, port);
    try trigger_api.deleteWebhook(&database, allocator, hook);

    const carrier = try trigger_api.createWebhook(&database, allocator, .{
        .schema = "app",
        .table = "events",
        .events = &.{.insert},
        .method = "POST",
        .url = "http://127.0.0.1/unused",
        .headers_json = null,
        .timeout_ms = 2000,
        .max_attempts = 1,
        .secret = "pg-net-secret",
    });
    defer trigger_api.deleteWebhook(&database, allocator, carrier) catch {};

    try postBodyIsDelivered(&database, allocator, &probe, carrier, listener.port, io, host, user, password, port);
    try deleteMethodHeaderAndQuery(&database, allocator, &probe, carrier, listener.port, io, host, user, password, port);
    try customHeaderArrives(&database, allocator, &probe, carrier, listener.port, io, host, user, password, port);
    try nullHeadersStillSucceed(&database, allocator, &probe, carrier, listener.port, io, host, user, password, port);
    try timeoutThenWorkerStillSucceeds(&database, allocator, &probe, carrier, listener.port, io, host, user, password, port);
    try refusedConnectionsDoNotKillWorker(&database, allocator, &probe, carrier, listener.port, io, host, user, password, port);
    try emptyReplyDoesNotKillWorker(&database, allocator, &probe, carrier, listener.port, io, host, user, password, port);
    try redirectIsNotFollowed(&database, allocator, &probe, carrier, listener.port, io, host, user, password, port);
    try non2xxIsDeadLetter(&database, allocator, carrier, listener.port, io, host, user, password, port);
    try responseTimestampsDiffer(&database, allocator, carrier, listener.port, io, host, user, password, port);
    try badUrlBecomesDeadLetter(&database, allocator, carrier, listener.port, io, host, user, password, port);
    try std.testing.expectError(error.BadUrl, trigger_api.createWebhook(&database, allocator, .{
        .schema = "app",
        .table = "events",
        .events = &.{.insert},
        .method = "GET",
        .url = "",
        .headers_json = null,
        .timeout_ms = 2000,
        .max_attempts = 1,
        .secret = "pg-net-secret",
    }));
}

fn requestIdBeforeHttp(
    database: *db.Db,
    allocator: std.mem.Allocator,
    probe: *Probe,
    host: [:0]const u8,
    user: [:0]const u8,
    password: [:0]const u8,
    port: u16,
) !void {
    const before = probe.hits.load(.seq_cst);
    try database.exec("START TRANSACTION");
    try database.exec("INSERT INTO app.events VALUES (1, 'id')");
    const request_id = try scalar(database, allocator, "SELECT id FROM net.http_request_queue");
    try std.testing.expect(request_id != 0);
    try std.testing.expectEqual(@as(u64, 0), try scalar(database, allocator, "SELECT COUNT(*) FROM net.http_response"));
    var worker = try db.Db.open(allocator, host, user, password, "net", port);
    defer worker.deinit();
    try std.testing.expectEqual(@as(u64, 0), try scalar(&worker, allocator, "SELECT COUNT(*) FROM net.http_request_queue"));
    const token = claim.newToken();
    const rows = try claim.claim(&worker, allocator, 8, &token);
    defer claim.freeRows(allocator, rows);
    try std.testing.expectEqual(@as(usize, 0), rows.len);
    try std.testing.expectEqual(before, probe.hits.load(.seq_cst));
    try database.exec("ROLLBACK");
    try std.testing.expectEqual(@as(u64, 0), try scalar(database, allocator, "SELECT COUNT(*) FROM net.http_request_queue"));
}

fn rollbackDropsRequest(database: *db.Db, allocator: std.mem.Allocator, probe: *Probe) !void {
    const before = probe.hits.load(.seq_cst);
    try database.exec("START TRANSACTION");
    try database.exec("INSERT INTO app.events VALUES (2, 'rollback')");
    try std.testing.expectEqual(@as(u64, 1), try scalar(database, allocator, "SELECT COUNT(*) FROM net.http_request_queue"));
    try database.exec("ROLLBACK");
    try std.testing.expectEqual(@as(u64, 0), try scalar(database, allocator, "SELECT COUNT(*) FROM net.http_request_queue"));
    try std.testing.expectEqual(before, probe.hits.load(.seq_cst));
}

fn collectGetAfterCommit(
    database: *db.Db,
    allocator: std.mem.Allocator,
    probe: *Probe,
    io: std.Io,
    host: [:0]const u8,
    user: [:0]const u8,
    password: [:0]const u8,
    port: u16,
) !void {
    try clearNet(database);
    const before = probe.hits.load(.seq_cst);
    try database.exec("INSERT INTO app.events VALUES (3, 'commit')");
    try std.testing.expectEqual(@as(u64, 1), try scalar(database, allocator, "SELECT COUNT(*) FROM net.http_request_queue"));
    try std.testing.expectEqual(@as(u64, 0), try scalar(database, allocator, "SELECT COUNT(*) FROM net.http_response"));
    try std.testing.expectEqual(before, probe.hits.load(.seq_cst));
    try pump(allocator, io, host, user, password, port);
    try std.testing.expect(probe.hits.load(.seq_cst) > before);
    try std.testing.expectEqual(@as(u64, 0), try scalar(database, allocator, "SELECT COUNT(*) FROM net.http_request_queue"));
    var saved = try latest(database, allocator);
    defer saved.deinit(allocator);
    try std.testing.expectEqualStrings("success", saved.outcome);
    try std.testing.expectEqual(@as(?u64, 200), saved.status);
    try std.testing.expect(std.mem.indexOf(u8, saved.body, "Hello world") != null);
}

fn postBodyIsDelivered(
    database: *db.Db,
    allocator: std.mem.Allocator,
    probe: *Probe,
    hook: u64,
    listen_port: u16,
    io: std.Io,
    host: [:0]const u8,
    user: [:0]const u8,
    password: [:0]const u8,
    port: u16,
) !void {
    try clearNet(database);
    const url = try std.fmt.allocPrint(allocator, "http://127.0.0.1:{d}/post", .{listen_port});
    defer allocator.free(url);
    try enqueue(database, allocator, hook, "POST", url, null, "{\"hello\": \"world\"}", 2000, 1);
    try pump(allocator, io, host, user, password, port);
    var saved = try latest(database, allocator);
    defer saved.deinit(allocator);
    try std.testing.expectEqualStrings("success", saved.outcome);
    try std.testing.expect(std.mem.indexOf(u8, saved.body, "hello") != null);
    try std.testing.expect(std.mem.indexOf(u8, saved.body, "world") != null);
    lockMutex(&probe.mu);
    defer probe.mu.unlock();
    try std.testing.expect(std.mem.indexOf(u8, probe.req_body[0..probe.req_body_len], "hello") != null);
}

fn deleteMethodHeaderAndQuery(
    database: *db.Db,
    allocator: std.mem.Allocator,
    probe: *Probe,
    hook: u64,
    listen_port: u16,
    io: std.Io,
    host: [:0]const u8,
    user: [:0]const u8,
    password: [:0]const u8,
    port: u16,
) !void {
    try clearNet(database);
    const url = try std.fmt.allocPrint(allocator, "http://127.0.0.1:{d}/delete?param-foo=bar", .{listen_port});
    defer allocator.free(url);
    try enqueue(database, allocator, hook, "DELETE", url, "{\"X-Baz\":\"foo\"}", "{\"key\": \"val\"}", 2000, 1);
    try pump(allocator, io, host, user, password, port);
    var saved = try latest(database, allocator);
    defer saved.deinit(allocator);
    try std.testing.expectEqualStrings("success", saved.outcome);
    try std.testing.expect(std.mem.indexOf(u8, saved.body, "DELETE") != null);
    try std.testing.expect(std.mem.indexOf(u8, saved.body, "X-Baz") != null);
    try std.testing.expect(std.mem.indexOf(u8, saved.body, "param-foo=bar") != null);
    try std.testing.expect(std.mem.indexOf(u8, saved.body, "val") != null);
    _ = probe;
}

fn customHeaderArrives(
    database: *db.Db,
    allocator: std.mem.Allocator,
    probe: *Probe,
    hook: u64,
    listen_port: u16,
    io: std.Io,
    host: [:0]const u8,
    user: [:0]const u8,
    password: [:0]const u8,
    port: u16,
) !void {
    try clearNet(database);
    const url = try std.fmt.allocPrint(allocator, "http://127.0.0.1:{d}/headers", .{listen_port});
    defer allocator.free(url);
    try enqueue(database, allocator, hook, "GET", url, "{\"pytest-header\":\"pytest-header\"}", "", 2000, 1);
    try pump(allocator, io, host, user, password, port);
    var saved = try latest(database, allocator);
    defer saved.deinit(allocator);
    try std.testing.expectEqualStrings("success", saved.outcome);
    try std.testing.expect(std.mem.indexOf(u8, saved.body, "pytest-header") != null);
    _ = probe;
}

fn nullHeadersStillSucceed(
    database: *db.Db,
    allocator: std.mem.Allocator,
    probe: *Probe,
    hook: u64,
    listen_port: u16,
    io: std.Io,
    host: [:0]const u8,
    user: [:0]const u8,
    password: [:0]const u8,
    port: u16,
) !void {
    try clearNet(database);
    const url = try std.fmt.allocPrint(allocator, "http://127.0.0.1:{d}/ok", .{listen_port});
    defer allocator.free(url);
    try enqueue(database, allocator, hook, "GET", url, null, "", 2000, 1);
    try pump(allocator, io, host, user, password, port);
    var saved = try latest(database, allocator);
    defer saved.deinit(allocator);
    try std.testing.expectEqualStrings("success", saved.outcome);
    try std.testing.expectEqual(@as(?u64, 200), saved.status);
    try std.testing.expect(std.mem.indexOf(u8, saved.body, "Hello world") != null);
    _ = probe;
}

fn timeoutThenWorkerStillSucceeds(
    database: *db.Db,
    allocator: std.mem.Allocator,
    probe: *Probe,
    hook: u64,
    listen_port: u16,
    io: std.Io,
    host: [:0]const u8,
    user: [:0]const u8,
    password: [:0]const u8,
    port: u16,
) !void {
    try clearNet(database);
    const slow = try std.fmt.allocPrint(allocator, "http://127.0.0.1:{d}/slow", .{listen_port});
    defer allocator.free(slow);
    try enqueue(database, allocator, hook, "GET", slow, null, "", 400, 1);
    try pump(allocator, io, host, user, password, port);
    var failed = try latest(database, allocator);
    defer failed.deinit(allocator);
    try std.testing.expectEqualStrings("dead", failed.outcome);
    try std.testing.expectEqual(@as(?u64, null), failed.status);
    try std.testing.expect(failed.err.len != 0);
    sleepMs(1600);
    try clearNet(database);
    const brief = try std.fmt.allocPrint(allocator, "http://127.0.0.1:{d}/brief", .{listen_port});
    defer allocator.free(brief);
    try enqueue(database, allocator, hook, "GET", brief, null, "", 2000, 1);
    try pump(allocator, io, host, user, password, port);
    var saved = try latest(database, allocator);
    defer saved.deinit(allocator);
    try std.testing.expectEqualStrings("success", saved.outcome);
    try std.testing.expectEqual(@as(?u64, 200), saved.status);
    _ = probe;
}

fn refusedConnectionsDoNotKillWorker(
    database: *db.Db,
    allocator: std.mem.Allocator,
    probe: *Probe,
    hook: u64,
    listen_port: u16,
    io: std.Io,
    host: [:0]const u8,
    user: [:0]const u8,
    password: [:0]const u8,
    port: u16,
) !void {
    try clearNet(database);
    const closed = try closedPort();
    const url = try std.fmt.allocPrint(allocator, "http://127.0.0.1:{d}/", .{closed});
    defer allocator.free(url);
    var i: usize = 0;
    while (i < 10) : (i += 1) try enqueue(database, allocator, hook, "GET", url, null, "", 1000, 1);
    try pump(allocator, io, host, user, password, port);
    try std.testing.expectEqual(@as(u64, 10), try scalar(database, allocator, "SELECT COUNT(*) FROM net.http_response WHERE outcome = 'dead'"));
    try std.testing.expectEqual(@as(u64, 0), try scalar(database, allocator, "SELECT COUNT(*) FROM net.http_request_queue"));
    try clearNet(database);
    const ok = try std.fmt.allocPrint(allocator, "http://127.0.0.1:{d}/ok", .{listen_port});
    defer allocator.free(ok);
    try enqueue(database, allocator, hook, "GET", ok, null, "", 2000, 1);
    try pump(allocator, io, host, user, password, port);
    var saved = try latest(database, allocator);
    defer saved.deinit(allocator);
    try std.testing.expectEqualStrings("success", saved.outcome);
    try std.testing.expectEqual(@as(?u64, 200), saved.status);
    _ = probe;
}

fn emptyReplyDoesNotKillWorker(
    database: *db.Db,
    allocator: std.mem.Allocator,
    probe: *Probe,
    hook: u64,
    listen_port: u16,
    io: std.Io,
    host: [:0]const u8,
    user: [:0]const u8,
    password: [:0]const u8,
    port: u16,
) !void {
    try clearNet(database);
    const url = try std.fmt.allocPrint(allocator, "http://127.0.0.1:{d}/drop", .{listen_port});
    defer allocator.free(url);
    var i: usize = 0;
    while (i < 10) : (i += 1) try enqueue(database, allocator, hook, "GET", url, null, "", 2000, 1);
    try pump(allocator, io, host, user, password, port);
    try std.testing.expectEqual(@as(u64, 10), try scalar(database, allocator, "SELECT COUNT(*) FROM net.http_response WHERE outcome = 'dead' AND status_code IS NULL"));
    try clearNet(database);
    const ok = try std.fmt.allocPrint(allocator, "http://127.0.0.1:{d}/ok", .{listen_port});
    defer allocator.free(ok);
    try enqueue(database, allocator, hook, "GET", ok, null, "", 2000, 1);
    try pump(allocator, io, host, user, password, port);
    var saved = try latest(database, allocator);
    defer saved.deinit(allocator);
    try std.testing.expectEqualStrings("success", saved.outcome);
    _ = probe;
}

fn redirectIsNotFollowed(
    database: *db.Db,
    allocator: std.mem.Allocator,
    probe: *Probe,
    hook: u64,
    listen_port: u16,
    io: std.Io,
    host: [:0]const u8,
    user: [:0]const u8,
    password: [:0]const u8,
    port: u16,
) !void {
    try clearNet(database);
    const before = probe.finals.load(.seq_cst);
    const url = try std.fmt.allocPrint(allocator, "http://127.0.0.1:{d}/redirect", .{listen_port});
    defer allocator.free(url);
    try enqueue(database, allocator, hook, "GET", url, null, "", 2000, 1);
    try pump(allocator, io, host, user, password, port);
    try std.testing.expectEqual(before, probe.finals.load(.seq_cst));
    var saved = try latest(database, allocator);
    defer saved.deinit(allocator);
    try std.testing.expectEqualStrings("dead", saved.outcome);
    try std.testing.expect(std.mem.indexOf(u8, saved.body, "I got redirected") == null);
}

fn non2xxIsDeadLetter(
    database: *db.Db,
    allocator: std.mem.Allocator,
    hook: u64,
    listen_port: u16,
    io: std.Io,
    host: [:0]const u8,
    user: [:0]const u8,
    password: [:0]const u8,
    port: u16,
) !void {
    try clearNet(database);
    const url = try std.fmt.allocPrint(allocator, "http://127.0.0.1:{d}/status500", .{listen_port});
    defer allocator.free(url);
    try enqueue(database, allocator, hook, "GET", url, null, "", 2000, 1);
    try pump(allocator, io, host, user, password, port);
    var saved = try latest(database, allocator);
    defer saved.deinit(allocator);
    try std.testing.expectEqualStrings("dead", saved.outcome);
    try std.testing.expectEqual(@as(?u64, null), saved.status);
}

fn responseTimestampsDiffer(
    database: *db.Db,
    allocator: std.mem.Allocator,
    hook: u64,
    listen_port: u16,
    io: std.Io,
    host: [:0]const u8,
    user: [:0]const u8,
    password: [:0]const u8,
    port: u16,
) !void {
    try clearNet(database);
    const url = try std.fmt.allocPrint(allocator, "http://127.0.0.1:{d}/ok", .{listen_port});
    defer allocator.free(url);
    var i: usize = 0;
    while (i < 3) : (i += 1) {
        try enqueue(database, allocator, hook, "GET", url, null, "", 2000, 1);
        try pump(allocator, io, host, user, password, port);
        sleepMs(30);
    }
    try std.testing.expectEqual(@as(u64, 3), try scalar(database, allocator, "SELECT COUNT(DISTINCT created_at) FROM net.http_response"));
}

fn badUrlBecomesDeadLetter(
    database: *db.Db,
    allocator: std.mem.Allocator,
    hook: u64,
    listen_port: u16,
    io: std.Io,
    host: [:0]const u8,
    user: [:0]const u8,
    password: [:0]const u8,
    port: u16,
) !void {
    try clearNet(database);
    try enqueue(database, allocator, hook, "GET", "localhost:6666", null, "", 1000, 1);
    try std.testing.expectEqual(@as(u64, 1), try scalar(database, allocator, "SELECT COUNT(*) FROM net.http_request_queue"));
    try pump(allocator, io, host, user, password, port);
    try std.testing.expectEqual(@as(u64, 0), try scalar(database, allocator, "SELECT COUNT(*) FROM net.http_request_queue"));
    var saved = try latest(database, allocator);
    defer saved.deinit(allocator);
    try std.testing.expectEqualStrings("dead", saved.outcome);
    try std.testing.expectEqualStrings("SsrfBlocked", saved.err);
    try clearNet(database);
    const ok = try std.fmt.allocPrint(allocator, "http://127.0.0.1:{d}/ok", .{listen_port});
    defer allocator.free(ok);
    try enqueue(database, allocator, hook, "GET", ok, null, "", 2000, 1);
    try pump(allocator, io, host, user, password, port);
    var again = try latest(database, allocator);
    defer again.deinit(allocator);
    try std.testing.expectEqualStrings("success", again.outcome);
}

fn enqueue(
    database: *db.Db,
    allocator: std.mem.Allocator,
    hook: u64,
    method: []const u8,
    url: []const u8,
    headers_json: ?[]const u8,
    body: []const u8,
    timeout_ms: u32,
    max_attempts: u32,
) !void {
    const method_sql = try db.sqlString(allocator, method);
    defer allocator.free(method_sql);
    const url_sql = try db.sqlString(allocator, url);
    defer allocator.free(url_sql);
    const body_sql = try db.sqlString(allocator, body);
    defer allocator.free(body_sql);
    const headers_sql = if (headers_json) |raw|
        try db.sqlString(allocator, raw)
    else
        try allocator.dupe(u8, "NULL");
    defer allocator.free(headers_sql);
    const sql = try std.fmt.allocPrint(allocator,
        \\INSERT INTO net.http_request_queue
        \\  (webhook_id, method, url, headers, body, timeout_ms, max_attempts)
        \\VALUES ({d}, {s}, {s}, {s}, {s}, {d}, {d})
    , .{ hook, method_sql, url_sql, headers_sql, body_sql, timeout_ms, max_attempts });
    defer allocator.free(sql);
    try database.exec(sql);
}

fn pump(
    allocator: std.mem.Allocator,
    io: std.Io,
    host: [:0]const u8,
    user: [:0]const u8,
    password: [:0]const u8,
    port: u16,
) !void {
    var worker: daemon.Daemon = undefined;
    try worker.init(allocator, .{
        .host = host,
        .user = user,
        .password = password,
        .port = port,
        .max_in_flight = 16,
        .allow_loopback = true,
        .io = io,
    });
    defer worker.deinit();
    try worker.once();
}

fn clearNet(database: *db.Db) !void {
    try database.exec("DELETE FROM net.http_request_queue");
    try database.exec("DELETE FROM net.http_response");
}

fn scalar(database: *db.Db, allocator: std.mem.Allocator, sql: []const u8) !u64 {
    var rows = try database.query(allocator, sql);
    defer rows.deinit();
    const row = rows.next() orelse return 0;
    return row.int(0) orelse 0;
}

fn latest(database: *db.Db, allocator: std.mem.Allocator) !Saved {
    var rows = try database.query(allocator, "SELECT outcome, status_code, body, error FROM net.http_response ORDER BY id DESC LIMIT 1");
    defer rows.deinit();
    const row = rows.next() orelse return error.NoResponse;
    return .{
        .outcome = try allocator.dupe(u8, row.text(0) orelse ""),
        .status = row.int(1),
        .body = try allocator.dupe(u8, row.text(2) orelse ""),
        .err = try allocator.dupe(u8, row.text(3) orelse ""),
    };
}

fn listenLoopback() !Listener {
    const fd_raw = linux.socket(linux.AF.INET, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
    const fd = try syscallFd(fd_raw);
    var one: c_int = 1;
    _ = linux.setsockopt(fd, 1, 2, @ptrCast(&one), @sizeOf(c_int));
    var addr = linux.sockaddr.in{
        .family = linux.AF.INET,
        .port = 0,
        .addr = std.mem.nativeToBig(u32, 0x7f000001),
    };
    try syscallOk(linux.bind(fd, @ptrCast(&addr), @sizeOf(@TypeOf(addr))));
    try syscallOk(linux.listen(fd, 64));
    var len: linux.socklen_t = @sizeOf(@TypeOf(addr));
    try syscallOk(linux.getsockname(fd, @ptrCast(&addr), &len));
    return .{ .fd = fd, .port = std.mem.bigToNative(u16, addr.port) };
}

fn closedPort() !u16 {
    var listener = try listenLoopback();
    const port = listener.port;
    listener.close();
    return port;
}

fn serve(listener: *Listener, probe: *Probe) void {
    while (!probe.stop.load(.seq_cst)) {
        var addr: linux.sockaddr = undefined;
        var len: linux.socklen_t = @sizeOf(linux.sockaddr);
        const client_raw = linux.accept(listener.fd, &addr, &len);
        const client = syscallFd(client_raw) catch break;
        defer _ = linux.close(client);
        var buf: [8192]u8 = undefined;
        const filled = readHttp(client, &buf);
        if (filled == 0) continue;
        const header_at = std.mem.indexOf(u8, buf[0..filled], "\r\n\r\n") orelse filled;
        const body_at = @min(header_at + 4, filled);
        const path = requestPath(buf[0..filled]);
        lockMutex(&probe.mu);
        const head_n = @min(probe.head.len, header_at);
        @memcpy(probe.head[0..head_n], buf[0..head_n]);
        probe.head_len = head_n;
        const body_n = @min(probe.req_body.len, filled - body_at);
        @memcpy(probe.req_body[0..body_n], buf[body_at..][0..body_n]);
        probe.req_body_len = body_n;
        probe.mu.unlock();
        if (std.mem.startsWith(u8, path, "/drop")) {
            _ = probe.hits.fetchAdd(1, .seq_cst);
            continue;
        }
        if (std.mem.startsWith(u8, path, "/slow")) sleepMs(1500);
        if (std.mem.startsWith(u8, path, "/brief")) sleepMs(250);
        if (std.mem.startsWith(u8, path, "/final")) _ = probe.finals.fetchAdd(1, .seq_cst);
        const echoed = if (std.mem.startsWith(u8, path, "/post") or std.mem.startsWith(u8, path, "/delete"))
            buf[0..filled]
        else if (std.mem.startsWith(u8, path, "/headers"))
            buf[0..header_at]
        else
            "Hello world";
        if (std.mem.startsWith(u8, path, "/redirect")) {
            var location: [128]u8 = undefined;
            const loc = std.fmt.bufPrint(&location, "http://127.0.0.1:{d}/final", .{listener.port}) catch continue;
            var response_buf: [256]u8 = undefined;
            const response = std.fmt.bufPrint(&response_buf, "HTTP/1.1 302 Found\r\nLocation: {s}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", .{loc}) catch continue;
            _ = writeAll(client, response);
        } else if (std.mem.startsWith(u8, path, "/status500")) {
            const response = "HTTP/1.1 500 ERR\r\nContent-Length: 2\r\nConnection: close\r\n\r\nNO";
            _ = writeAll(client, response);
        } else {
            var response_buf: [9000]u8 = undefined;
            const response = std.fmt.bufPrint(&response_buf, "HTTP/1.1 200 OK\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}", .{ echoed.len, echoed }) catch continue;
            _ = writeAll(client, response);
        }
        _ = probe.hits.fetchAdd(1, .seq_cst);
    }
}

fn readHttp(client: i32, buf: []u8) usize {
    var filled: usize = 0;
    while (filled < buf.len) {
        const nraw = linux.read(client, buf[filled..].ptr, buf.len - filled);
        const n: isize = @bitCast(nraw);
        if (n <= 0) break;
        filled += @intCast(n);
        const header_at = std.mem.indexOf(u8, buf[0..filled], "\r\n\r\n") orelse continue;
        const need = header_at + 4 + contentLength(buf[0 .. header_at + 4]);
        if (filled >= need or filled == buf.len) break;
    }
    return filled;
}

fn contentLength(head: []const u8) usize {
    var lines = std.mem.splitSequence(u8, head, "\r\n");
    while (lines.next()) |line| {
        const prefix = "content-length:";
        if (line.len < prefix.len) continue;
        if (!std.ascii.eqlIgnoreCase(line[0..prefix.len], prefix)) continue;
        const raw = std.mem.trim(u8, line[prefix.len..], " \t");
        return std.fmt.parseInt(usize, raw, 10) catch 0;
    }
    return 0;
}

fn requestPath(buf: []const u8) []const u8 {
    const line_end = std.mem.indexOf(u8, buf, "\r\n") orelse buf.len;
    const line = buf[0..line_end];
    const sp = std.mem.indexOfScalar(u8, line, ' ') orelse return "/";
    const rest = line[sp + 1 ..];
    const sp2 = std.mem.indexOfScalar(u8, rest, ' ') orelse return rest;
    return rest[0..sp2];
}

fn writeAll(client: i32, bytes: []const u8) bool {
    var sent: usize = 0;
    while (sent < bytes.len) {
        const nraw = linux.write(client, bytes[sent..].ptr, bytes.len - sent);
        const n: isize = @bitCast(nraw);
        if (n <= 0) return false;
        sent += @intCast(n);
    }
    return true;
}

fn sleepMs(ms: u64) void {
    var req = linux.timespec{
        .sec = @intCast(ms / 1000),
        .nsec = @intCast((ms % 1000) * 1_000_000),
    };
    _ = linux.nanosleep(&req, null);
}

fn syscallFd(rc: usize) !i32 {
    const signed: isize = @bitCast(rc);
    if (signed < 0) return error.Socket;
    return @intCast(signed);
}

fn syscallOk(rc: usize) !void {
    const signed: isize = @bitCast(rc);
    if (signed < 0) return error.Socket;
}

extern "c" fn getenv(name: [*:0]const u8) ?[*:0]const u8;

test "history ttl is seven days where pg_net keeps responses for six hours" {
    try std.testing.expect(std.mem.indexOf(u8, schema.sql, "TTL=604800") != null);
}

test "pg_net contract" {
    const host_c = getenv("MARIA_NET_TEST_HOST") orelse return;
    const user_c = getenv("MARIA_NET_TEST_USER") orelse return error.MissingUser;
    const pass_c = getenv("MARIA_NET_TEST_PASSWORD") orelse "";
    const port_c = getenv("MARIA_NET_TEST_PORT") orelse "3306";
    const port = try std.fmt.parseInt(u16, std.mem.span(port_c), 10);
    lockGate();
    defer unlockGate();
    try run(std.testing.allocator, std.testing.io, std.mem.span(host_c), std.mem.span(user_c), std.mem.span(pass_c), port);
}
