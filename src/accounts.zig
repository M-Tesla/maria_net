const std = @import("std");
const db = @import("db.zig");
const pg_net_contract = @import("pg_net_contract.zig");
const schema = @import("schema.zig");

pub const Spec = struct {
    daemon_user: []const u8,
    daemon_password: []const u8,
    tenant_user: []const u8,
    tenant_password: []const u8,
    tenant_schema: []const u8,
    tenant_host: []const u8,
};

pub const Grants = struct {
    daemon_account: []u8,
    tenant_account: []u8,
    daemon_net: []u8,
    daemon_schema: []u8,
    tenant_schema: []u8,

    pub fn deinit(self: *Grants, allocator: std.mem.Allocator) void {
        allocator.free(self.daemon_account);
        allocator.free(self.tenant_account);
        allocator.free(self.daemon_net);
        allocator.free(self.daemon_schema);
        allocator.free(self.tenant_schema);
    }
};

pub fn grants(allocator: std.mem.Allocator, spec: Spec) !Grants {
    if (!db.validIdent(spec.daemon_user) or !db.validIdent(spec.tenant_user) or !db.validIdent(spec.tenant_schema)) return error.InvalidIdentifier;
    if (!validHost(spec.tenant_host)) return error.InvalidIdentifier;
    if (spec.daemon_password.len == 0 or spec.tenant_password.len == 0) return error.MissingPassword;
    const schema_ident = try db.quoteIdent(allocator, spec.tenant_schema);
    defer allocator.free(schema_ident);
    const daemon_account = try account(allocator, spec.daemon_user, "127.0.0.1");
    errdefer allocator.free(daemon_account);
    const tenant_account = try account(allocator, spec.tenant_user, spec.tenant_host);
    errdefer allocator.free(tenant_account);
    const daemon_net = try std.fmt.allocPrint(allocator, "GRANT SELECT, INSERT, UPDATE, DELETE ON net.* TO {s}", .{daemon_account});
    errdefer allocator.free(daemon_net);
    const daemon_schema = try std.fmt.allocPrint(allocator, "GRANT SELECT, INSERT, UPDATE, DELETE, TRIGGER ON {s}.* TO {s}", .{ schema_ident, daemon_account });
    errdefer allocator.free(daemon_schema);
    const tenant_schema = try std.fmt.allocPrint(allocator, "GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, DROP, ALTER, INDEX, TRIGGER ON {s}.* TO {s}", .{ schema_ident, tenant_account });
    return .{
        .daemon_account = daemon_account,
        .tenant_account = tenant_account,
        .daemon_net = daemon_net,
        .daemon_schema = daemon_schema,
        .tenant_schema = tenant_schema,
    };
}

pub fn install(database: *db.Db, allocator: std.mem.Allocator, spec: Spec) !void {
    var sql = try grants(allocator, spec);
    defer sql.deinit(allocator);
    const schema_ident = try db.quoteIdent(allocator, spec.tenant_schema);
    defer allocator.free(schema_ident);
    const create_db = try std.fmt.allocPrint(allocator, "CREATE DATABASE IF NOT EXISTS {s}", .{schema_ident});
    defer allocator.free(create_db);
    try database.exec(create_db);
    try ensureUser(database, allocator, spec.daemon_user, "127.0.0.1", spec.daemon_password);
    try ensureUser(database, allocator, spec.tenant_user, spec.tenant_host, spec.tenant_password);
    try revokeAll(database, allocator, sql.daemon_account);
    try revokeAll(database, allocator, sql.tenant_account);
    try database.exec(sql.daemon_net);
    try database.exec(sql.daemon_schema);
    try database.exec(sql.tenant_schema);
}

fn ensureUser(database: *db.Db, allocator: std.mem.Allocator, user: []const u8, host: []const u8, password: []const u8) !void {
    const acct = try account(allocator, user, host);
    defer allocator.free(acct);
    const secret = try db.sqlString(allocator, password);
    defer allocator.free(secret);
    const create = try std.fmt.allocPrint(allocator, "CREATE USER IF NOT EXISTS {s} IDENTIFIED BY {s}", .{ acct, secret });
    defer allocator.free(create);
    try database.exec(create);
    const alter = try std.fmt.allocPrint(allocator, "ALTER USER {s} IDENTIFIED BY {s}", .{ acct, secret });
    defer allocator.free(alter);
    try database.exec(alter);
}

fn revokeAll(database: *db.Db, allocator: std.mem.Allocator, acct: []const u8) !void {
    const sql = try std.fmt.allocPrint(allocator, "REVOKE ALL PRIVILEGES, GRANT OPTION FROM {s}", .{acct});
    defer allocator.free(sql);
    try database.exec(sql);
}

fn account(allocator: std.mem.Allocator, user: []const u8, host: []const u8) ![]u8 {
    const user_sql = try db.sqlString(allocator, user);
    defer allocator.free(user_sql);
    const host_sql = try db.sqlString(allocator, host);
    defer allocator.free(host_sql);
    return std.fmt.allocPrint(allocator, "{s}@{s}", .{ user_sql, host_sql });
}

fn validHost(host: []const u8) bool {
    if (host.len == 0 or host.len > 255) return false;
    for (host) |ch| {
        const ok = std.ascii.isAlphanumeric(ch) or ch == '%' or ch == '.' or ch == '_' or ch == '-';
        if (!ok) return false;
    }
    return true;
}

test "tenant grant does not touch schema net" {
    var sql = try grants(std.testing.allocator, .{
        .daemon_user = "maria_net",
        .daemon_password = "daemon-secret",
        .tenant_user = "app_user",
        .tenant_password = "tenant-secret",
        .tenant_schema = "app",
        .tenant_host = "%",
    });
    defer sql.deinit(std.testing.allocator);
    try std.testing.expect(std.mem.indexOf(u8, sql.tenant_schema, "net.") == null);
    try std.testing.expect(std.mem.indexOf(u8, sql.daemon_net, "ON net.*") != null);
    try std.testing.expect(std.mem.indexOf(u8, sql.daemon_account, "127.0.0.1") != null);
    try std.testing.expect(std.mem.indexOf(u8, sql.daemon_schema, "TRIGGER") != null);
    try std.testing.expectError(error.InvalidIdentifier, grants(std.testing.allocator, .{
        .daemon_user = "maria_net",
        .daemon_password = "x",
        .tenant_user = "app_user",
        .tenant_password = "y",
        .tenant_schema = "app",
        .tenant_host = "bad host",
    }));
}

extern "c" fn getenv(name: [*:0]const u8) ?[*:0]const u8;

test "tenant account cannot read net.webhook" {
    const host_c = getenv("MARIA_NET_TEST_HOST") orelse return;
    const user_c = getenv("MARIA_NET_TEST_USER") orelse return error.MissingUser;
    const pass_c = getenv("MARIA_NET_TEST_PASSWORD") orelse "";
    const port_c = getenv("MARIA_NET_TEST_PORT") orelse "3306";
    const port = try std.fmt.parseInt(u16, std.mem.span(port_c), 10);
    pg_net_contract.lockGate();
    defer pg_net_contract.unlockGate();

    const allocator = std.testing.allocator;
    var admin = try db.Db.open(allocator, std.mem.span(host_c), std.mem.span(user_c), std.mem.span(pass_c), null, port);
    defer admin.deinit();
    try schema.requireAvailable(&admin);
    try admin.execScript(schema.sql);

    const daemon_password = "daemon-pass-1";
    const tenant_password = "tenant-pass-1";
    const spec = Spec{
        .daemon_user = "maria_net_t",
        .daemon_password = daemon_password,
        .tenant_user = "tenant_app_t",
        .tenant_password = tenant_password,
        .tenant_schema = "tenant_box",
        .tenant_host = "%",
    };
    defer {
        admin.exec("DROP USER IF EXISTS 'maria_net_t'@'127.0.0.1'") catch {};
        admin.exec("DROP USER IF EXISTS 'tenant_app_t'@'%'") catch {};
        admin.exec("DROP DATABASE IF EXISTS tenant_box") catch {};
    }
    try install(&admin, allocator, spec);

    const host_z = std.mem.span(host_c);
    var tenant = try db.Db.open(allocator, host_z, "tenant_app_t", tenant_password, null, port);
    defer tenant.deinit();
    if (tenant.exec("SELECT COUNT(*) FROM net.webhook")) |_| return error.TenantCanReadSecret else |err| {
        if (err != error.Sql or (tenant.errno != db.access_denied_db and tenant.errno != db.access_denied_table)) return err;
    }

    var who = try admin.query(allocator, "SELECT USER()");
    defer who.deinit();
    const user_host = (who.next() orelse return error.Missing).text(0) orelse return error.Missing;
    if (std.mem.endsWith(u8, user_host, "@127.0.0.1")) {
        var worker = try db.Db.open(allocator, host_z, "maria_net_t", daemon_password, "net", port);
        defer worker.deinit();
        try worker.exec("SELECT COUNT(*) FROM net.webhook");
    } else {
        try std.testing.expectError(error.Connect, db.Db.open(allocator, host_z, "maria_net_t", daemon_password, "net", port));
    }
    try expectGrant(&admin, allocator, "SHOW GRANTS FOR 'maria_net_t'@'127.0.0.1'", "`net`", true);
    try expectGrant(&admin, allocator, "SHOW GRANTS FOR 'tenant_app_t'@'%'", "net", false);
}

fn expectGrant(database: *db.Db, allocator: std.mem.Allocator, sql: []const u8, needle: []const u8, want: bool) !void {
    var rows = try database.query(allocator, sql);
    defer rows.deinit();
    var found = false;
    while (rows.next()) |row| {
        const text = row.text(0) orelse continue;
        if (std.mem.indexOf(u8, text, needle) != null) found = true;
    }
    try std.testing.expectEqual(want, found);
}
