const std = @import("std");
const db = @import("db.zig");

pub const sql = @import("net_sql").sql;
pub const table_options = "ENGINE=TidesDB";

pub fn requireAvailable(database: *db.Db) !void {
    var rows = try database.query(database.allocator, "SHOW ENGINES");
    defer rows.deinit();
    while (rows.next()) |row| {
        const name = row.text(0) orelse continue;
        const support = row.text(1) orelse continue;
        if (std.ascii.eqlIgnoreCase(name, "TidesDB") and std.ascii.eqlIgnoreCase(support, "YES")) return;
    }
    return error.TidesDBUnavailable;
}

test "shipped schema is TidesDB queue plus append-only history" {
    try std.testing.expect(std.mem.indexOf(u8, sql, "ENGINE=TidesDB") != null);
    try std.testing.expect(std.mem.indexOf(u8, sql, "tidesdb_memtable_sync_mode") != null);
    try std.testing.expect(std.mem.indexOf(u8, sql, "KEY idx_claim (status, available_at, id)") != null);
    try std.testing.expect(std.mem.indexOf(u8, sql, "TOMBSTONE_DENSITY_TRIGGER=5000") != null);
    try std.testing.expect(std.mem.indexOf(u8, sql, "TTL=604800") != null);
    try std.testing.expect(std.mem.indexOf(u8, sql, "tidesdb_single_delete_primary") != null);
    const queue_at = std.mem.indexOf(u8, sql, "net.http_request_queue").?;
    const response_at = std.mem.indexOf(u8, sql, "net.http_response").?;
    const queue_sql = sql[queue_at..response_at];
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, queue_sql, "KEY idx_claim"));
    const response_sql = sql[response_at..];
    try std.testing.expectEqual(@as(usize, 0), std.mem.count(u8, response_sql, "KEY idx"));
}
