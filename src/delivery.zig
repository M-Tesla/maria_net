const std = @import("std");
const claim = @import("claim.zig");
const daemon = @import("daemon.zig");
const db = @import("db.zig");
const pg_net_contract = @import("pg_net_contract.zig");
const schema = @import("schema.zig");
const trigger_api = @import("trigger_api.zig");

const linux = std.os.linux;

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

    try reset(&database, allocator);
    try testRollbackAndCommit(&database, allocator);
    try reset(&database, allocator);
    try testTwoClaimers(allocator, host, user, password, port);
    try reset(&database, allocator);
    try testCrashRedelivery(&database, allocator);
    try reset(&database, allocator);
    try testHttpSsrfRetry(allocator, io, host, user, password, port);
    try reset(&database, allocator);
    try testBulk(&database, allocator);
    try testColumnInjection(&database, allocator);
    try testPluginSwitch(&database, allocator, io, host, user, password, port);
}

fn reset(database: *db.Db, allocator: std.mem.Allocator) !void {
    try database.exec("DROP DATABASE IF EXISTS app");
    try database.exec("CREATE DATABASE app");
    try database.exec("DELETE FROM net.http_request_queue");
    try database.exec("DELETE FROM net.http_response");
    try database.exec("DELETE FROM net.webhook");
    _ = allocator;
}

fn testRollbackAndCommit(database: *db.Db, allocator: std.mem.Allocator) !void {
    const create = try std.fmt.allocPrint(allocator, "CREATE TABLE app.events (id INT NOT NULL PRIMARY KEY, name VARCHAR(64) NOT NULL) {s}", .{schema.table_options});
    defer allocator.free(create);
    try database.exec(create);
    const id = try trigger_api.createWebhook(database, allocator, .{
        .schema = "app",
        .table = "events",
        .events = &.{ .insert, .update, .delete },
        .method = "POST",
        .url = "http://127.0.0.1/unused",
        .headers_json = null,
        .timeout_ms = 1000,
        .max_attempts = 3,
        .secret = "delivery-secret",
    });
    try std.testing.expect(id != 0);
    try database.exec("START TRANSACTION");
    try database.exec("INSERT INTO app.events VALUES (1, 'rollback')");
    try database.exec("ROLLBACK");
    try std.testing.expectEqual(@as(u64, 0), try scalar(database, allocator, "SELECT COUNT(*) FROM net.http_request_queue"));
    try database.exec("INSERT INTO app.events VALUES (2, 'commit')");
    try std.testing.expectEqual(@as(u64, 1), try scalar(database, allocator, "SELECT COUNT(*) FROM net.http_request_queue"));
}

fn testTwoClaimers(
    allocator: std.mem.Allocator,
    host: [:0]const u8,
    user: [:0]const u8,
    password: [:0]const u8,
    port: u16,
) !void {
    var database = try db.Db.open(allocator, host, user, password, "net", port);
    defer database.deinit();
    var i: usize = 0;
    while (i < 20) : (i += 1) {
        try database.exec(
            \\INSERT INTO net.http_request_queue
            \\  (webhook_id, method, url, body, timeout_ms, max_attempts)
            \\VALUES (1, 'POST', 'http://127.0.0.1/x', '{}', 1000, 3)
        );
    }
    const Slot = struct {
        ids: [64]u64 = undefined,
        n: usize = 0,
        failed: bool = false,
        host: [:0]const u8,
        user: [:0]const u8,
        password: [:0]const u8,
        port: u16,
    };
    var a = Slot{ .host = host, .user = user, .password = password, .port = port };
    var b = a;
    const worker = struct {
        fn run(slot: *Slot) void {
            var local = db.Db.open(std.heap.smp_allocator, slot.host, slot.user, slot.password, "net", slot.port) catch {
                slot.failed = true;
                return;
            };
            defer local.deinit();
            const token = claim.newToken();
            const rows = claim.claim(&local, std.heap.smp_allocator, 20, &token) catch {
                slot.failed = true;
                return;
            };
            defer claim.freeRows(std.heap.smp_allocator, rows);
            slot.n = rows.len;
            for (rows, 0..) |row, index| slot.ids[index] = row.id;
        }
    }.run;
    const t1 = try std.Thread.spawn(.{}, worker, .{&a});
    const t2 = try std.Thread.spawn(.{}, worker, .{&b});
    t1.join();
    t2.join();
    try std.testing.expect(!a.failed and !b.failed);
    try std.testing.expectEqual(@as(usize, 20), a.n + b.n);
    for (a.ids[0..a.n]) |left| {
        for (b.ids[0..b.n]) |right| try std.testing.expect(left != right);
    }
}

fn testCrashRedelivery(database: *db.Db, allocator: std.mem.Allocator) !void {
    try database.exec(
        \\INSERT INTO net.http_request_queue
        \\  (webhook_id, method, url, body, timeout_ms, status, claim_token, locked_at, max_attempts)
        \\VALUES (1, 'POST', 'http://127.0.0.1/x', '{}', 1000, 'processing',
        \\        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', DATE_SUB(NOW(3), INTERVAL 120 SECOND), 3)
    );
    const reclaimed = try claim.reclaimStale(database);
    try std.testing.expect(reclaimed >= 1);
    const pending = try scalar(database, allocator, "SELECT COUNT(*) FROM net.http_request_queue WHERE status = 'pending'");
    try std.testing.expect(pending >= 1);
    const token = claim.newToken();
    const rows = try claim.claim(database, allocator, 8, &token);
    defer claim.freeRows(allocator, rows);
    try std.testing.expect(rows.len >= 1);
}

fn testHttpSsrfRetry(
    allocator: std.mem.Allocator,
    io: std.Io,
    host: [:0]const u8,
    user: [:0]const u8,
    password: [:0]const u8,
    port: u16,
) !void {
    var listener = try listenLoopback();
    defer listener.close();
    var got = Capture{};
    const server = try std.Thread.spawn(.{}, serve, .{ &listener, &got });
    defer {
        got.stop = true;
        _ = linux.shutdown(listener.fd, linux.SHUT.RDWR);
        server.join();
    }

    var database = try db.Db.open(allocator, host, user, password, null, port);
    defer database.deinit();
    const create = try std.fmt.allocPrint(allocator, "CREATE TABLE IF NOT EXISTS app.events (id INT NOT NULL PRIMARY KEY, name VARCHAR(64) NOT NULL) {s}", .{schema.table_options});
    defer allocator.free(create);
    database.exec("DROP TABLE IF EXISTS app.events") catch {};
    try database.exec(create);
    const url = try std.fmt.allocPrint(allocator, "http://127.0.0.1:{d}/hook", .{listener.port});
    defer allocator.free(url);
    const hook = try trigger_api.createWebhook(&database, allocator, .{
        .schema = "app",
        .table = "events",
        .events = &.{.insert},
        .method = "POST",
        .url = url,
        .headers_json = null,
        .timeout_ms = 2000,
        .max_attempts = 2,
        .secret = "delivery-secret",
    });
    try database.exec("INSERT INTO app.events VALUES (10, 'http')");

    var worker = DaemonSlot{
        .allocator = allocator,
        .io = io,
        .host = host,
        .user = user,
        .password = password,
        .port = port,
        .allow_loopback = true,
    };
    try worker.once();
    try std.testing.expectEqual(@as(u64, 0), try scalar(&database, allocator, "SELECT COUNT(*) FROM net.http_request_queue"));
    const ok = try scalar(&database, allocator, "SELECT COUNT(*) FROM net.http_response WHERE outcome = 'success' AND status_code = 200");
    try std.testing.expectEqual(@as(u64, 1), ok);
    try std.testing.expect(got.saw_signature);

    try database.exec("DELETE FROM net.http_request_queue");
    try database.exec("DELETE FROM net.http_response");
    const ssrf_sql = try std.fmt.allocPrint(allocator,
        \\INSERT INTO net.http_request_queue
        \\  (webhook_id, method, url, body, timeout_ms, max_attempts)
        \\VALUES ({d}, 'POST', 'http://169.254.169.254/latest', '{{}}', 1000, 1)
    , .{hook});
    defer allocator.free(ssrf_sql);
    try database.exec(ssrf_sql);
    worker.allow_loopback = false;
    try worker.once();
    const dead = try scalar(&database, allocator, "SELECT COUNT(*) FROM net.http_response WHERE outcome = 'dead'");
    try std.testing.expect(dead >= 1);
    try std.testing.expectEqual(@as(u64, 0), try scalar(&database, allocator, "SELECT COUNT(*) FROM net.http_request_queue"));

    try database.exec("DELETE FROM net.http_response");
    got.code = 500;
    got.limit = got.count + 2;
    const retry_url = try std.fmt.allocPrint(allocator, "http://127.0.0.1:{d}/fail", .{listener.port});
    defer allocator.free(retry_url);
    const retry_sql = try std.fmt.allocPrint(allocator,
        \\INSERT INTO net.http_request_queue
        \\  (webhook_id, method, url, body, timeout_ms, max_attempts)
        \\VALUES ({d}, 'POST', '{s}', '{{}}', 1000, 2)
    , .{ hook, retry_url });
    defer allocator.free(retry_sql);
    try database.exec(retry_sql);
    worker.allow_loopback = true;
    try worker.once();
    try std.testing.expectEqual(@as(u64, 1), try scalar(&database, allocator, "SELECT COUNT(*) FROM net.http_request_queue WHERE status = 'pending' AND attempts = 1"));
    try database.exec("UPDATE net.http_request_queue SET available_at = DATE_SUB(NOW(3), INTERVAL 1 SECOND) WHERE status = 'pending'");
    try worker.once();
    try std.testing.expectEqual(@as(u64, 0), try scalar(&database, allocator, "SELECT COUNT(*) FROM net.http_request_queue"));
    try std.testing.expect(try scalar(&database, allocator, "SELECT COUNT(*) FROM net.http_response WHERE outcome = 'dead'") >= 1);
}

fn testPluginSwitch(
    database: *db.Db,
    allocator: std.mem.Allocator,
    io: std.Io,
    host: [:0]const u8,
    user: [:0]const u8,
    password: [:0]const u8,
    port: u16,
) !void {
    try database.exec("DROP TABLE IF EXISTS app.switch_events");
    const create = try std.fmt.allocPrint(allocator, "CREATE TABLE app.switch_events (id INT NOT NULL PRIMARY KEY, name VARCHAR(64) NOT NULL) {s}", .{schema.table_options});
    defer allocator.free(create);
    try database.exec(create);
    var listener = try listenLoopback();
    defer listener.close();
    var got = Capture{};
    const server = try std.Thread.spawn(.{}, serve, .{ &listener, &got });
    defer {
        got.stop = true;
        _ = linux.shutdown(listener.fd, linux.SHUT.RDWR);
        server.join();
    }
    const url = try std.fmt.allocPrint(allocator, "http://127.0.0.1:{d}/switch", .{listener.port});
    defer allocator.free(url);
    _ = try trigger_api.createWebhook(database, allocator, .{
        .schema = "app",
        .table = "switch_events",
        .events = &.{.insert},
        .method = "POST",
        .url = url,
        .headers_json = null,
        .timeout_ms = 2000,
        .max_attempts = 1,
        .secret = "switch-secret",
    });
    try database.exec("DELETE FROM net.http_request_queue");
    try database.exec("DELETE FROM net.http_response");
    try database.exec("UNINSTALL SONAME 'maria_net'");
    defer database.exec("INSTALL SONAME 'maria_net'") catch {};
    try std.testing.expect(!try daemon.switchOn(database, allocator));
    try database.exec("INSERT INTO app.switch_events VALUES (1, 'held')");
    try std.testing.expectEqual(@as(u64, 1), try scalar(database, allocator, "SELECT COUNT(*) FROM net.http_request_queue WHERE status = 'pending'"));

    var worker = DaemonSlot{
        .allocator = allocator,
        .io = io,
        .host = host,
        .user = user,
        .password = password,
        .port = port,
        .allow_loopback = true,
    };
    try worker.once();
    try std.testing.expectEqual(@as(usize, 0), got.count);
    try std.testing.expectEqual(@as(u64, 1), try scalar(database, allocator, "SELECT COUNT(*) FROM net.http_request_queue WHERE status = 'pending'"));

    try database.exec("INSTALL SONAME 'maria_net'");
    try std.testing.expect(try daemon.switchOn(database, allocator));
    try worker.once();
    try std.testing.expectEqual(@as(usize, 1), got.count);
    try std.testing.expect(got.saw_signature);
    try std.testing.expectEqual(@as(u64, 0), try scalar(database, allocator, "SELECT COUNT(*) FROM net.http_request_queue"));
    try std.testing.expectEqual(@as(u64, 1), try scalar(database, allocator, "SELECT COUNT(*) FROM net.http_response WHERE outcome = 'success' AND status_code = 200"));
    try database.exec("DROP TABLE IF EXISTS app.switch_events");
}

fn testColumnInjection(database: *db.Db, allocator: std.mem.Allocator) !void {
    try database.exec("SET @pwn = NULL");
    try database.exec("DELETE FROM net.http_request_queue");
    try database.exec("DROP DATABASE IF EXISTS breakcol");
    try database.exec("CREATE DATABASE breakcol");
    const create = try std.fmt.allocPrint(allocator, "CREATE TABLE breakcol.victim (id INT NOT NULL PRIMARY KEY, `x',(SELECT 'PWNED' INTO @pwn),'y` INT NULL) {s}", .{schema.table_options});
    defer allocator.free(create);
    try database.exec(create);
    try std.testing.expectError(error.InvalidIdentifier, trigger_api.createWebhook(database, allocator, .{
        .schema = "breakcol",
        .table = "victim",
        .events = &.{.insert},
        .method = "POST",
        .url = "http://127.0.0.1/column",
        .headers_json = null,
        .timeout_ms = 1000,
        .max_attempts = 1,
        .secret = "column-secret",
    }));
    try database.exec("INSERT INTO breakcol.victim VALUES (1, NULL)");
    try std.testing.expectEqual(@as(u64, 0), try scalar(database, allocator, "SELECT COUNT(*) FROM net.http_request_queue"));
    var rows = try database.query(allocator, "SELECT @pwn");
    defer rows.deinit();
    const row = rows.next() orelse return error.Missing;
    try std.testing.expect(row.text(0) == null);
    try database.exec("DROP DATABASE IF EXISTS breakcol");
}

fn testBulk(database: *db.Db, allocator: std.mem.Allocator) !void {
    try database.exec("CREATE DATABASE IF NOT EXISTS app");
    database.exec("DROP TABLE IF EXISTS app.events") catch {};
    const create = try std.fmt.allocPrint(allocator, "CREATE TABLE app.events (id INT NOT NULL PRIMARY KEY, name VARCHAR(64) NOT NULL) {s}", .{schema.table_options});
    defer allocator.free(create);
    try database.exec(create);
    _ = try trigger_api.createWebhook(database, allocator, .{
        .schema = "app",
        .table = "events",
        .events = &.{.insert},
        .method = "POST",
        .url = "http://127.0.0.1/bulk",
        .headers_json = null,
        .timeout_ms = 1000,
        .max_attempts = 3,
        .secret = "delivery-secret",
    });
    try database.exec("DELETE FROM net.http_request_queue");
    try database.exec("START TRANSACTION");
    var i: usize = 0;
    while (i < 40) : (i += 1) {
        const sql = try std.fmt.allocPrint(allocator, "INSERT INTO app.events VALUES ({d}, 'bulk')", .{1000 + i});
        defer allocator.free(sql);
        try database.exec(sql);
    }
    try database.exec("ROLLBACK");
    const after_rollback = try scalar(database, allocator, "SELECT COUNT(*) FROM net.http_request_queue");
    if (after_rollback != 0) {
        std.log.info("TideSQL mid-statement commit left {d} queue rows after rollback of 40 inserts", .{after_rollback});
    }
    try database.exec("DELETE FROM net.http_request_queue");
    var values: std.ArrayList(u8) = .empty;
    defer values.deinit(allocator);
    try values.appendSlice(allocator, "INSERT INTO app.events (id, name) VALUES ");
    i = 0;
    while (i < 600) : (i += 1) {
        if (i != 0) try values.append(allocator, ',');
        const piece = try std.fmt.allocPrint(allocator, "({d},'b')", .{2000 + i});
        defer allocator.free(piece);
        try values.appendSlice(allocator, piece);
    }
    try database.exec(values.items);
    const queued = try scalar(database, allocator, "SELECT COUNT(*) FROM net.http_request_queue");
    try std.testing.expectEqual(@as(u64, 600), queued);
    std.log.info("bulk insert of 600 rows queued {d}; TideSQL can commit internally around 500 ops if that statement later fails", .{queued});
}

const DaemonSlot = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    host: [:0]const u8,
    user: [:0]const u8,
    password: [:0]const u8,
    port: u16,
    allow_loopback: bool,

    fn once(self: *DaemonSlot) !void {
        var worker: daemon.Daemon = undefined;
        try worker.init(self.allocator, .{
            .host = self.host,
            .user = self.user,
            .password = self.password,
            .port = self.port,
            .max_in_flight = 8,
            .allow_loopback = self.allow_loopback,
            .io = self.io,
        });
        defer worker.deinit();
        try worker.once();
    }
};

fn scalar(database: *db.Db, allocator: std.mem.Allocator, sql: []const u8) !u64 {
    var rows = try database.query(allocator, sql);
    defer rows.deinit();
    const row = rows.next() orelse return 0;
    return row.int(0) orelse 0;
}

const Listener = struct {
    fd: i32,
    port: u16,

    fn close(self: *Listener) void {
        _ = linux.close(self.fd);
    }
};

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
    try syscallOk(linux.listen(fd, 16));
    var len: linux.socklen_t = @sizeOf(@TypeOf(addr));
    try syscallOk(linux.getsockname(fd, @ptrCast(&addr), &len));
    return .{ .fd = fd, .port = std.mem.bigToNative(u16, addr.port) };
}

const Capture = struct {
    count: usize = 0,
    limit: usize = 8,
    code: u16 = 200,
    saw_signature: bool = false,
    stop: bool = false,
};

fn serve(listener: *Listener, got: *Capture) void {
    while (!got.stop and got.count < got.limit) {
        var addr: linux.sockaddr = undefined;
        var len: linux.socklen_t = @sizeOf(linux.sockaddr);
        const client_raw = linux.accept(listener.fd, &addr, &len);
        const client = syscallFd(client_raw) catch break;
        defer _ = linux.close(client);
        var buf: [8192]u8 = undefined;
        var filled: usize = 0;
        while (filled < buf.len) {
            const n = linux.read(client, buf[filled..].ptr, buf.len - filled);
            const signed: isize = @bitCast(n);
            if (signed <= 0) break;
            filled += @intCast(signed);
            if (std.mem.indexOf(u8, buf[0..filled], "\r\n\r\n") != null) break;
        }
        const request = buf[0..filled];
        if (std.mem.indexOf(u8, request, "X-Maria-Signature: ") != null) got.saw_signature = true;
        const body = if (got.code == 200) "OK" else "NO";
        var response_buf: [128]u8 = undefined;
        const response = std.fmt.bufPrint(&response_buf, "HTTP/1.1 {d} {s}\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}", .{
            got.code,
            if (got.code == 200) "OK" else "ERR",
            body.len,
            body,
        }) catch break;
        var sent: usize = 0;
        while (sent < response.len) {
            const n = linux.write(client, response[sent..].ptr, response.len - sent);
            const signed: isize = @bitCast(n);
            if (signed <= 0) break;
            sent += @intCast(signed);
        }
        got.count += 1;
    }
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

test "delivery suite" {
    const host_c = getenv("MARIA_NET_TEST_HOST") orelse return;
    const user_c = getenv("MARIA_NET_TEST_USER") orelse return error.MissingUser;
    const pass_c = getenv("MARIA_NET_TEST_PASSWORD") orelse "";
    const port_c = getenv("MARIA_NET_TEST_PORT") orelse "3306";
    const port = try std.fmt.parseInt(u16, std.mem.span(port_c), 10);
    pg_net_contract.lockGate();
    defer pg_net_contract.unlockGate();
    try run(std.testing.allocator, std.testing.io, std.mem.span(host_c), std.mem.span(user_c), std.mem.span(pass_c), port);
}
