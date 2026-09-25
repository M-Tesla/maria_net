const std = @import("std");
const accounts = @import("accounts.zig");
const curl_loop = @import("curl_loop.zig");
const daemon = @import("daemon.zig");
const db = @import("db.zig");
const delivery = @import("delivery.zig");
const schema = @import("schema.zig");
const trigger_api = @import("trigger_api.zig");

const usage_text =
    \\maria-net apply
    \\maria-net accounts --daemon-password-file FILE --tenant-user USER --tenant-password-file FILE --tenant-schema SCHEMA [--tenant-host %] [--daemon-user maria_net]
    \\maria-net webhook-create --schema S --table T --events INSERT,UPDATE --url URL [--method POST] [--secret-hex HEX] [--timeout-ms 5000] [--max-attempts 5] [--headers-json JSON]
    \\maria-net webhook-delete --id N
    \\maria-net daemon [--max-in-flight 64] [--password-file FILE]
    \\maria-net test-delivery
    \\
    \\Admin connection: --host 127.0.0.1 --port 3306 --user root --password-file FILE
    \\--allow-loopback exists for tests. Do not use it on a service.
    \\
;

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len < 2 or std.mem.eql(u8, args[1], "--help")) {
        std.debug.print("{s}", .{usage_text});
        return;
    }
    const cmd = args[1];
    const host = flag(args, "--host") orelse "127.0.0.1";
    const user = flag(args, "--user") orelse "root";
    const port = try std.fmt.parseInt(u16, flag(args, "--port") orelse "3306", 10);
    const host_z = try init.gpa.dupeZ(u8, host);
    defer init.gpa.free(host_z);
    const user_z = try init.gpa.dupeZ(u8, user);
    defer init.gpa.free(user_z);
    const pass_z = try resolvePassword(init.gpa, args);
    defer init.gpa.free(pass_z);

    if (std.mem.eql(u8, cmd, "apply")) {
        var database = try db.Db.open(init.gpa, host_z, user_z, pass_z, null, port);
        defer database.deinit();
        try database.execScript(schema.sql);
        std.log.info("applied net schema", .{});
        return;
    }
    if (std.mem.eql(u8, cmd, "accounts")) {
        const daemon_password = try namedSecret(init.gpa, args, "--daemon-password-file", "--daemon-password");
        defer init.gpa.free(daemon_password);
        const tenant_password = try namedSecret(init.gpa, args, "--tenant-password-file", "--tenant-password");
        defer init.gpa.free(tenant_password);
        var database = try db.Db.open(init.gpa, host_z, user_z, pass_z, null, port);
        defer database.deinit();
        try accounts.install(&database, init.gpa, .{
            .daemon_user = flag(args, "--daemon-user") orelse "maria_net",
            .daemon_password = daemon_password,
            .tenant_user = flag(args, "--tenant-user") orelse return error.MissingUser,
            .tenant_password = tenant_password,
            .tenant_schema = flag(args, "--tenant-schema") orelse return error.MissingSchema,
            .tenant_host = flag(args, "--tenant-host") orelse "%",
        });
        std.log.info("installed daemon and tenant accounts", .{});
        return;
    }
    if (std.mem.eql(u8, cmd, "webhook-create")) {
        const events = try trigger_api.parseEvents(flag(args, "--events") orelse return error.MissingEvents);
        const secret = try secretBytes(init.gpa, flag(args, "--secret-hex"));
        defer init.gpa.free(secret);
        var database = try db.Db.open(init.gpa, host_z, user_z, pass_z, "net", port);
        defer database.deinit();
        const id = try trigger_api.createWebhook(&database, init.gpa, .{
            .schema = flag(args, "--schema") orelse return error.MissingSchema,
            .table = flag(args, "--table") orelse return error.MissingTable,
            .events = events,
            .method = flag(args, "--method") orelse "POST",
            .url = flag(args, "--url") orelse return error.MissingUrl,
            .headers_json = flag(args, "--headers-json"),
            .timeout_ms = try std.fmt.parseInt(u32, flag(args, "--timeout-ms") orelse "5000", 10),
            .max_attempts = try std.fmt.parseInt(u32, flag(args, "--max-attempts") orelse "5", 10),
            .secret = secret,
        });
        std.debug.print("{d}\n", .{id});
        return;
    }
    if (std.mem.eql(u8, cmd, "webhook-delete")) {
        const id = try std.fmt.parseInt(u64, flag(args, "--id") orelse return error.MissingId, 10);
        var database = try db.Db.open(init.gpa, host_z, user_z, pass_z, "net", port);
        defer database.deinit();
        try trigger_api.deleteWebhook(&database, init.gpa, id);
        return;
    }
    if (std.mem.eql(u8, cmd, "daemon")) {
        if (pass_z.len == 0) return error.MissingPassword;
        const max_in_flight = try std.fmt.parseInt(u32, flag(args, "--max-in-flight") orelse "64", 10);
        var worker: daemon.Daemon = undefined;
        try worker.init(init.gpa, .{
            .host = host_z,
            .user = user_z,
            .password = pass_z,
            .port = port,
            .max_in_flight = max_in_flight,
            .allow_loopback = has(args, "--allow-loopback"),
            .io = init.io,
        });
        defer worker.deinit();
        try worker.run();
        return;
    }
    if (std.mem.eql(u8, cmd, "test-delivery")) {
        try delivery.run(init.gpa, init.io, host_z, user_z, pass_z, port);
        return;
    }
    std.debug.print("{s}", .{usage_text});
    return error.UnknownCommand;
}

fn resolvePassword(allocator: std.mem.Allocator, args: []const [:0]const u8) ![:0]u8 {
    if (flag(args, "--password-file")) |path| return readSecretFile(allocator, path);
    return allocator.dupeZ(u8, flag(args, "--password") orelse "");
}

fn namedSecret(allocator: std.mem.Allocator, args: []const [:0]const u8, file_flag: []const u8, inline_flag: []const u8) ![:0]u8 {
    if (flag(args, file_flag)) |path| return readSecretFile(allocator, path);
    const value = flag(args, inline_flag) orelse return error.MissingPassword;
    if (value.len == 0) return error.MissingPassword;
    return allocator.dupeZ(u8, value);
}

fn readSecretFile(allocator: std.mem.Allocator, path: []const u8) ![:0]u8 {
    const path_z = try allocator.dupeZ(u8, path);
    defer allocator.free(path_z);
    const fd_raw = std.os.linux.open(path_z, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    const opened: isize = @bitCast(fd_raw);
    if (opened < 0) return error.PasswordFile;
    const fd: i32 = @intCast(opened);
    defer _ = std.os.linux.close(fd);
    var buf: [512]u8 = undefined;
    const nraw = std.os.linux.read(fd, &buf, buf.len);
    const nsigned: isize = @bitCast(nraw);
    if (nsigned <= 0 or nsigned == buf.len) return error.PasswordFile;
    const trimmed = std.mem.trim(u8, buf[0..@intCast(nsigned)], " \t\r\n");
    if (trimmed.len == 0 or std.mem.indexOfScalar(u8, trimmed, 0) != null) return error.MissingPassword;
    return allocator.dupeZ(u8, trimmed);
}

fn flag(args: []const [:0]const u8, name: []const u8) ?[]const u8 {
    for (args, 0..) |arg, i| {
        if (std.mem.eql(u8, arg, name)) {
            if (i + 1 < args.len) return args[i + 1];
            return null;
        }
        if (std.mem.startsWith(u8, arg, name) and arg.len > name.len and arg[name.len] == '=') {
            return arg[name.len + 1 ..];
        }
    }
    return null;
}

fn has(args: []const [:0]const u8, name: []const u8) bool {
    for (args) |arg| if (std.mem.eql(u8, arg, name)) return true;
    return false;
}

fn secretBytes(allocator: std.mem.Allocator, hex: ?[]const u8) ![]u8 {
    if (hex) |text| {
        if (text.len == 0 or text.len % 2 != 0 or text.len > 256) return error.BadSecret;
        const out = try allocator.alloc(u8, text.len / 2);
        errdefer allocator.free(out);
        _ = std.fmt.hexToBytes(out, text) catch return error.BadSecret;
        return out;
    }
    const out = try allocator.alloc(u8, 32);
    const n = std.os.linux.getrandom(out.ptr, out.len, 0);
    if (@as(isize, @bitCast(n)) != out.len) return error.BadSecret;
    return out;
}

comptime {
    _ = curl_loop.mn_write_cb;
    _ = curl_loop.mn_on_socket;
    _ = curl_loop.mn_on_timer;
}

test {
    _ = @import("accounts.zig");
    _ = @import("backoff.zig");
    _ = @import("claim.zig");
    _ = @import("db.zig");
    _ = @import("delivery.zig");
    _ = @import("headers.zig");
    _ = @import("pg_net_contract.zig");
    _ = @import("schema.zig");
    _ = @import("sign.zig");
    _ = @import("ssrf.zig");
    _ = @import("stress.zig");
    _ = @import("trigger_api.zig");
}
