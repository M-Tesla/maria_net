const std = @import("std");

const Mysql = opaque {};
const MysqlRes = opaque {};

extern fn mysql_init(mysql: ?*Mysql) ?*Mysql;
extern fn mysql_real_connect(
    mysql: *Mysql,
    host: [*:0]const u8,
    user: [*:0]const u8,
    passwd: [*:0]const u8,
    db: ?[*:0]const u8,
    port: c_uint,
    unix_socket: ?[*:0]const u8,
    client_flag: c_ulong,
) ?*Mysql;
extern fn mysql_close(mysql: *Mysql) void;
extern fn mysql_real_query(mysql: *Mysql, sql: [*]const u8, len: c_ulong) c_int;
extern fn mysql_store_result(mysql: *Mysql) ?*MysqlRes;
extern fn mysql_free_result(res: *MysqlRes) void;
extern fn mysql_fetch_row(res: *MysqlRes) ?[*]?*u8;
extern fn mysql_fetch_lengths(res: *MysqlRes) ?[*]c_ulong;
extern fn mysql_num_fields(res: *MysqlRes) c_uint;
extern fn mysql_errno(mysql: *Mysql) c_uint;
extern fn mysql_error(mysql: *Mysql) [*:0]const u8;
extern fn mysql_affected_rows(mysql: *Mysql) u64;
extern fn mysql_insert_id(mysql: *Mysql) u64;
extern fn mysql_thread_init() c_int;
extern fn mysql_thread_end() void;
pub extern fn mysql_set_character_set(mysql: *Mysql, cs: [*:0]const u8) c_int;

pub const single_delete_off = "SET SESSION tidesdb_single_delete_primary = 0";
pub const unknown_system_variable: c_uint = 1193;
pub const commit_conflict: c_uint = 1180;
pub const lock_deadlock: c_uint = 1213;
pub const access_denied_db: c_uint = 1044;
pub const access_denied_table: c_uint = 1142;

pub const Db = struct {
    allocator: std.mem.Allocator,
    mysql: *Mysql,
    errno: c_uint = 0,
    err: []u8 = &.{},

    pub fn open(
        allocator: std.mem.Allocator,
        host: [*:0]const u8,
        user: [*:0]const u8,
        password: [*:0]const u8,
        database: ?[*:0]const u8,
        port: u16,
    ) !Db {
        _ = mysql_thread_init();
        const mysql = mysql_init(null) orelse return error.Connect;
        errdefer mysql_close(mysql);
        if (mysql_real_connect(mysql, host, user, password, database, port, null, 0) == null) {
            return error.Connect;
        }
        _ = mysql_set_character_set(mysql, "utf8mb4");
        return .{ .allocator = allocator, .mysql = mysql };
    }

    pub fn deinit(self: *Db) void {
        if (self.err.len != 0) self.allocator.free(self.err);
        mysql_close(self.mysql);
        mysql_thread_end();
    }

    pub fn exec(self: *Db, sql: []const u8) !void {
        try self.queryRaw(sql);
        if (mysql_store_result(self.mysql)) |res| mysql_free_result(res);
    }

    pub fn execIgnoreMissingVariable(self: *Db, sql: []const u8) !void {
        self.exec(sql) catch |err| {
            if (err == error.Sql and self.errno == unknown_system_variable) return;
            return err;
        };
    }

    pub fn query(self: *Db, allocator: std.mem.Allocator, sql: []const u8) !Result {
        try self.queryRaw(sql);
        const res = mysql_store_result(self.mysql) orelse {
            self.errno = mysql_errno(self.mysql);
            if (self.errno != 0) {
                self.err = self.allocator.dupe(u8, std.mem.span(mysql_error(self.mysql))) catch &.{};
                return error.Sql;
            }
            return .{ .allocator = allocator, .res = null, .fields = 0 };
        };
        return .{
            .allocator = allocator,
            .res = res,
            .fields = mysql_num_fields(res),
        };
    }

    pub fn affected(self: *Db) u64 {
        return mysql_affected_rows(self.mysql);
    }

    pub fn insertId(self: *Db) u64 {
        return mysql_insert_id(self.mysql);
    }

    pub fn execScript(self: *Db, script: []const u8) !void {
        var stripped: std.ArrayList(u8) = .empty;
        defer stripped.deinit(self.allocator);
        var lines = std.mem.splitScalar(u8, script, '\n');
        while (lines.next()) |line| {
            const trimmed = std.mem.trim(u8, line, " \t\r");
            if (std.mem.startsWith(u8, trimmed, "--")) continue;
            try stripped.appendSlice(self.allocator, line);
            try stripped.append(self.allocator, '\n');
        }
        var it = std.mem.splitScalar(u8, stripped.items, ';');
        while (it.next()) |part| {
            if (!meaningful(part)) continue;
            const stmt = std.mem.trim(u8, part, " \t\r\n");
            try self.exec(stmt);
        }
    }

    fn queryRaw(self: *Db, sql: []const u8) !void {
        if (self.err.len != 0) {
            self.allocator.free(self.err);
            self.err = &.{};
        }
        if (mysql_real_query(self.mysql, sql.ptr, sql.len) != 0) {
            self.errno = mysql_errno(self.mysql);
            self.err = self.allocator.dupe(u8, std.mem.span(mysql_error(self.mysql))) catch &.{};
            if (self.errno != unknown_system_variable and self.errno != commit_conflict and self.errno != lock_deadlock and self.errno != access_denied_db and self.errno != access_denied_table) {
                std.log.err("sql {d}: {s}", .{ self.errno, self.err });
            }
            return error.Sql;
        }
        self.errno = 0;
    }
};

fn meaningful(stmt: []const u8) bool {
    var lines = std.mem.splitScalar(u8, stmt, '\n');
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (trimmed.len == 0) continue;
        if (std.mem.startsWith(u8, trimmed, "--")) continue;
        return true;
    }
    return false;
}

pub const Result = struct {
    allocator: std.mem.Allocator,
    res: ?*MysqlRes,
    fields: c_uint,

    pub fn deinit(self: *Result) void {
        if (self.res) |res| mysql_free_result(res);
        self.res = null;
    }

    pub fn next(self: *Result) ?Row {
        const res = self.res orelse return null;
        const raw = mysql_fetch_row(res) orelse return null;
        const lengths = mysql_fetch_lengths(res) orelse return null;
        return .{ .raw = raw, .lengths = lengths, .fields = self.fields };
    }
};

pub const Row = struct {
    raw: [*]?*u8,
    lengths: [*]c_ulong,
    fields: c_uint,

    pub fn text(self: Row, index: usize) ?[]const u8 {
        if (index >= self.fields) return null;
        const ptr = self.raw[index] orelse return null;
        const bytes: [*]const u8 = @ptrCast(ptr);
        return bytes[0..self.lengths[index]];
    }

    pub fn int(self: Row, index: usize) ?u64 {
        const value = self.text(index) orelse return null;
        return std.fmt.parseInt(u64, value, 10) catch null;
    }
};

pub fn quoteIdent(allocator: std.mem.Allocator, name: []const u8) ![]u8 {
    if (!validIdent(name)) return error.InvalidIdentifier;
    return std.fmt.allocPrint(allocator, "`{s}`", .{name});
}

pub fn validIdent(name: []const u8) bool {
    if (name.len == 0 or name.len > 64) return false;
    for (name, 0..) |ch, i| {
        const ok = std.ascii.isAlphabetic(ch) or ch == '_' or (i > 0 and std.ascii.isDigit(ch));
        if (!ok) return false;
    }
    return true;
}

pub fn sqlString(allocator: std.mem.Allocator, value: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try out.append(allocator, '\'');
    for (value) |ch| {
        if (ch == 0) return error.InvalidString;
        if (ch == '\'' or ch == '\\') try out.append(allocator, '\\');
        try out.append(allocator, ch);
    }
    try out.append(allocator, '\'');
    return try out.toOwnedSlice(allocator);
}

test "identifiers reject the characters a trigger cannot quote safely" {
    try std.testing.expect(validIdent("events"));
    try std.testing.expect(!validIdent("net.webhook"));
    try std.testing.expect(!validIdent(""));
    try std.testing.expect(!validIdent("1bad"));
}
