const std = @import("std");
const daemon = @import("daemon.zig");
const db = @import("db.zig");
const pg_net_contract = @import("pg_net_contract.zig");
const schema = @import("schema.zig");
const trigger_api = @import("trigger_api.zig");

const linux = std.os.linux;

fn scalar(database: *db.Db, allocator: std.mem.Allocator, sql: []const u8) !u64 {
    var rows = try database.query(allocator, sql);
    defer rows.deinit();
    const row = rows.next() orelse return 0;
    return row.int(0) orelse 0;
}

fn readAll(path: [*:0]const u8, buf: []u8) usize {
    const fd = syscallFd(linux.open(path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0)) catch return 0;
    defer _ = linux.close(fd);
    const n = linux.read(fd, buf.ptr, buf.len);
    const signed: isize = @bitCast(n);
    if (signed <= 0) return 0;
    return @intCast(signed);
}

fn statusKb(comptime key: []const u8) u64 {
    var buf: [4096]u8 = undefined;
    const n = readAll("/proc/self/status", &buf);
    return fieldKb(buf[0..n], key);
}

fn processKb(comptime key: []const u8, needle: []const u8) u64 {
    const dir = syscallFd(linux.open("/proc", .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true }, 0)) catch return 0;
    defer _ = linux.close(dir);
    var buf: [8192]u8 = undefined;
    while (true) {
        const nraw = linux.getdents64(dir, &buf, buf.len);
        const nsigned: isize = @bitCast(nraw);
        if (nsigned <= 0) break;
        var off: usize = 0;
        const n: usize = @intCast(nsigned);
        while (off + @sizeOf(linux.dirent64) <= n) {
            const ent: *align(1) linux.dirent64 = @ptrCast(buf[off..].ptr);
            const reclen = ent.reclen;
            if (reclen == 0) break;
            const name = std.mem.sliceTo(@as([*:0]const u8, @ptrCast(&ent.name)), 0);
            off += reclen;
            if (name.len == 0 or name[0] < '0' or name[0] > '9') continue;
            var path: [96]u8 = undefined;
            const comm_path = std.fmt.bufPrintZ(&path, "/proc/{s}/comm", .{name}) catch continue;
            var comm_buf: [64]u8 = undefined;
            const cn = readAll(comm_path.ptr, &comm_buf);
            const comm = std.mem.trim(u8, comm_buf[0..cn], " \t\r\n");
            if (!std.mem.eql(u8, comm, needle)) continue;
            const status_path = std.fmt.bufPrintZ(&path, "/proc/{s}/status", .{name}) catch continue;
            var status_buf: [4096]u8 = undefined;
            const sn = readAll(status_path.ptr, &status_buf);
            return fieldKb(status_buf[0..sn], key);
        }
    }
    return 0;
}

fn fieldKb(text: []const u8, key: []const u8) u64 {
    const at = std.mem.indexOf(u8, text, key) orelse return 0;
    var rest = text[at + key.len ..];
    while (rest.len > 0 and (rest[0] == ' ' or rest[0] == '\t')) rest = rest[1..];
    const end = std.mem.indexOfAny(u8, rest, " \t\n") orelse rest.len;
    return std.fmt.parseInt(u64, rest[0..end], 10) catch 0;
}

fn memoryUsed(database: *db.Db, allocator: std.mem.Allocator) !u64 {
    var rows = try database.query(allocator, "SHOW GLOBAL STATUS LIKE 'Memory_used'");
    defer rows.deinit();
    const row = rows.next() orelse return 0;
    const text = row.text(1) orelse return 0;
    return std.fmt.parseInt(u64, text, 10) catch 0;
}

fn report(
    database: *db.Db,
    allocator: std.mem.Allocator,
    worker: *daemon.Daemon,
    label: []const u8,
    delivered: u64,
) !void {
    const responses = try scalar(database, allocator, "SELECT COUNT(*) FROM net.http_response");
    const queued = try scalar(database, allocator, "SELECT COUNT(*) FROM net.http_request_queue");
    const server = try memoryUsed(database, allocator);
    std.debug.print(
        "stress {s} delivered={d} queue={d} responses={d} daemon_rss_kb={d} daemon_vmsize_kb={d} fds={d} held={d} inflight={d}             server_rss_kb={d} server_vmdata_kb={d} server_memory={d}\n",
        .{
            label,
            delivered,
            queued,
            responses,
            statusKb("VmRSS:"),
            statusKb("VmSize:"),
            worker.curl.fds.items.len,
            worker.held.items.len,
            worker.curl.inflight,
            processKb("VmRSS:", "mariadbd"),
            processKb("VmData:", "mariadbd"),
            server,
        },
    );
}

const Listener = struct {
    fd: i32,
    port: u16,

    fn close(self: *Listener) void {
        _ = linux.close(self.fd);
    }
};

fn listenLoopback() !Listener {
    const fd = try syscallFd(linux.socket(linux.AF.INET, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0));
    var one: c_int = 1;
    _ = linux.setsockopt(fd, 1, 2, @ptrCast(&one), @sizeOf(c_int));
    var addr = linux.sockaddr.in{
        .family = linux.AF.INET,
        .port = 0,
        .addr = std.mem.nativeToBig(u32, 0x7f000001),
    };
    try syscallOk(linux.bind(fd, @ptrCast(&addr), @sizeOf(@TypeOf(addr))));
    try syscallOk(linux.listen(fd, 256));
    var len: linux.socklen_t = @sizeOf(@TypeOf(addr));
    try syscallOk(linux.getsockname(fd, @ptrCast(&addr), &len));
    return .{ .fd = fd, .port = std.mem.bigToNative(u16, addr.port) };
}

const Sink = struct {
    stop: std.atomic.Value(bool) = .init(false),
    hits: std.atomic.Value(u64) = .init(0),
    body: []const u8,
};

fn serve(listener: *Listener, sink: *Sink) void {
    const response_head = "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: ";
    while (!sink.stop.load(.acquire)) {
        var addr: linux.sockaddr = undefined;
        var len: linux.socklen_t = @sizeOf(linux.sockaddr);
        const client = syscallFd(linux.accept(listener.fd, &addr, &len)) catch break;
        defer _ = linux.close(client);
        var buf: [2048]u8 = undefined;
        var filled: usize = 0;
        while (filled < buf.len) {
            const n = linux.read(client, buf[filled..].ptr, buf.len - filled);
            const signed: isize = @bitCast(n);
            if (signed <= 0) break;
            filled += @intCast(signed);
            if (std.mem.indexOf(u8, buf[0..filled], "\r\n\r\n") != null) break;
        }
        var response_buf: [128]u8 = undefined;
        const response = std.fmt.bufPrint(&response_buf, "{s}{d}\r\n\r\n{s}", .{
            response_head,
            sink.body.len,
            sink.body,
        }) catch break;
        var sent: usize = 0;
        while (sent < response.len) {
            const n = linux.write(client, response[sent..].ptr, response.len - sent);
            const signed: isize = @bitCast(n);
            if (signed <= 0) break;
            sent += @intCast(signed);
        }
        _ = sink.hits.fetchAdd(1, .release);
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

fn enqueue(database: *db.Db, allocator: std.mem.Allocator, hook: u64, url: []const u8, body: []const u8, n: u64) !void {
    var left = n;
    while (left > 0) {
        const batch: u64 = @min(left, 100);
        var sql: std.ArrayList(u8) = .empty;
        defer sql.deinit(allocator);
        try sql.appendSlice(allocator, "INSERT INTO net.http_request_queue (webhook_id, method, url, body, timeout_ms, max_attempts) VALUES ");
        var i: u64 = 0;
        while (i < batch) : (i += 1) {
            if (i != 0) try sql.append(allocator, ',');
            const piece = try std.fmt.allocPrint(allocator, "({d},'POST','{s}','{s}',2000,1)", .{ hook, url, body });
            defer allocator.free(piece);
            try sql.appendSlice(allocator, piece);
        }
        try database.exec(sql.items);
        left -= batch;
    }
}

fn drain(database: *db.Db, allocator: std.mem.Allocator, worker: *daemon.Daemon, expect: u64) !void {
    var round: u32 = 0;
    while (round < 8) : (round += 1) {
        const passes: u32 = @intCast(expect * 2 / 64 + 32);
        var spins: u32 = 0;
        while (spins < passes) : (spins += 1) {
            worker.once() catch |err| {
                std.debug.print("stress once {s} errno={d} db={s} held={d} inflight={d}\n", .{
                    @errorName(err),
                    worker.database.errno,
                    worker.database.err,
                    worker.held.items.len,
                    worker.curl.inflight,
                });
                return err;
            };
        }
        const left = try scalar(database, allocator, "SELECT COUNT(*) FROM net.http_request_queue");
        if (left == 0) return;
        const processing = try scalar(database, allocator, "SELECT COUNT(*) FROM net.http_request_queue WHERE status = 'processing'");
        var pause = std.os.linux.timespec{
            .sec = if (processing > 0) 35 else 0,
            .nsec = if (processing > 0) 0 else 100_000_000,
        };
        _ = std.os.linux.nanosleep(&pause, null);
    }
    const left = try scalar(database, allocator, "SELECT COUNT(*) FROM net.http_request_queue");
    std.debug.print("stress still queued={d} expect_wave={d} held={d} inflight={d}\n", .{
        left,
        expect,
        worker.held.items.len,
        worker.curl.inflight,
    });
    return error.StillQueued;
}

extern "c" fn getenv(name: [*:0]const u8) ?[*:0]const u8;

test "memory stays bounded across a long delivery run" {
    const count_c = getenv("MARIA_NET_STRESS") orelse return;
    const host_c = getenv("MARIA_NET_TEST_HOST") orelse return error.MissingHost;
    const user_c = getenv("MARIA_NET_TEST_USER") orelse return error.MissingUser;
    const pass_c = getenv("MARIA_NET_TEST_PASSWORD") orelse "";
    const port_c = getenv("MARIA_NET_TEST_PORT") orelse "3306";
    const total = try std.fmt.parseInt(u64, std.mem.span(count_c), 10);
    const port = try std.fmt.parseInt(u16, std.mem.span(port_c), 10);
    pg_net_contract.lockGate();
    defer pg_net_contract.unlockGate();

    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var database = try db.Db.open(allocator, std.mem.span(host_c), std.mem.span(user_c), std.mem.span(pass_c), null, port);
    defer database.deinit();
    try schema.requireAvailable(&database);
    try database.execScript(schema.sql);
    try daemon.installSwitch(&database);
    try database.exec("CREATE DATABASE IF NOT EXISTS app");
    try database.exec("DROP TABLE IF EXISTS app.stress_events");
    const create = try std.fmt.allocPrint(allocator, "CREATE TABLE app.stress_events (id INT NOT NULL PRIMARY KEY) {s}", .{schema.table_options});
    defer allocator.free(create);
    try database.exec(create);

    var listener = try listenLoopback();
    defer listener.close();
    var sink = Sink{ .body = "OK" };
    const server = try std.Thread.spawn(.{}, serve, .{ &listener, &sink });
    defer {
        sink.stop.store(true, .release);
        _ = linux.shutdown(listener.fd, linux.SHUT.RDWR);
        server.join();
    }

    const url = try std.fmt.allocPrint(allocator, "http://127.0.0.1:{d}/stress", .{listener.port});
    defer allocator.free(url);
    const hook = try trigger_api.createWebhook(&database, allocator, .{
        .schema = "app",
        .table = "stress_events",
        .events = &.{.insert},
        .method = "POST",
        .url = url,
        .headers_json = null,
        .timeout_ms = 2000,
        .max_attempts = 1,
        .secret = "stress-secret",
    });

    try database.exec("DELETE FROM net.http_request_queue");
    try database.exec("DELETE FROM net.http_response");

    var worker: daemon.Daemon = undefined;
    try worker.init(allocator, .{
        .host = std.mem.span(host_c),
        .user = std.mem.span(user_c),
        .password = std.mem.span(pass_c),
        .port = port,
        .max_in_flight = 64,
        .allow_loopback = true,
        .io = io,
    });
    defer worker.deinit();
    try report(&database, allocator, &worker, "baseline", 0);

    var delivered: u64 = 0;
    var next_report: u64 = @min(total, 10000);
    var left = total;
    while (left > 0) {
        const wave: u64 = @min(left, 2000);
        try enqueue(&database, allocator, hook, url, "{}", wave);
        try drain(&database, allocator, &worker, wave);
        delivered += wave;
        left -= wave;
        if (delivered >= next_report or left == 0) {
            try report(&database, allocator, &worker, "wave", delivered);
            next_report += 10000;
        }
    }
    const retained = try memoryUsed(&database, allocator);
    const retained_rss = processKb("VmRSS:", "mariadbd");
    try database.exec("DELETE FROM net.http_response");
    std.Io.sleep(io, .fromMilliseconds(2000), .awake) catch {};
    try report(&database, allocator, &worker, "after-delete", delivered);

    var round: u32 = 0;
    while (round < 3) : (round += 1) {
        try enqueue(&database, allocator, hook, url, "{}", 5000);
        try drain(&database, allocator, &worker, 5000);
        delivered += 5000;
        try report(&database, allocator, &worker, "reclaim-full", delivered);
        try database.exec("DELETE FROM net.http_response");
        std.Io.sleep(io, .fromMilliseconds(1000), .awake) catch {};
        try report(&database, allocator, &worker, "reclaim-empty", delivered);
    }

    const fat = "0123456789abcdef" ** 512;
    try enqueue(&database, allocator, hook, url, fat, 1000);
    try drain(&database, allocator, &worker, 1000);
    delivered += 1000;
    try report(&database, allocator, &worker, "fat-full", delivered);
    try database.exec("DELETE FROM net.http_response");
    try report(&database, allocator, &worker, "fat-empty", delivered);

    try std.testing.expectEqual(@as(u64, 0), try scalar(&database, allocator, "SELECT COUNT(*) FROM net.http_request_queue"));
    try std.testing.expectEqual(@as(usize, 0), worker.held.items.len);
    try std.testing.expectEqual(@as(u32, 0), worker.curl.inflight);
    try std.testing.expectEqual(@as(usize, 0), worker.curl.flights.items.len);
    try std.testing.expect(worker.curl.fds.items.len <= 256);
    const empty_rss = processKb("VmRSS:", "mariadbd");
    const empty_mem = try memoryUsed(&database, allocator);
    std.debug.print("stress summary retained_rss_kb={d} empty_rss_kb={d} retained_memory={d} empty_memory={d} hits={d}\n", .{
        retained_rss,
        empty_rss,
        retained,
        empty_mem,
        sink.hits.load(.acquire),
    });
    try database.exec("DROP TABLE IF EXISTS app.stress_events");
}
