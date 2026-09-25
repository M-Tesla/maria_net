const std = @import("std");
const backoff = @import("backoff.zig");
const claim = @import("claim.zig");
const curl_loop = @import("curl_loop.zig");
const db = @import("db.zig");
const headers = @import("headers.zig");
const shim = @import("shim.zig");
const sign = @import("sign.zig");
const ssrf = @import("ssrf.zig");

pub fn switchOn(database: *db.Db, allocator: std.mem.Allocator) !bool {
    var rows = try database.query(allocator,
        \\SELECT COUNT(*) FROM information_schema.PLUGINS
        \\WHERE PLUGIN_NAME = 'maria_net' AND PLUGIN_STATUS = 'ACTIVE'
    );
    defer rows.deinit();
    const row = rows.next() orelse return false;
    return (row.int(0) orelse 0) != 0;
}

pub fn installSwitch(database: *db.Db) !void {
    try database.exec("INSTALL SONAME 'maria_net'");
}

pub const Options = struct {
    host: [:0]const u8,
    user: [:0]const u8,
    password: [:0]const u8,
    port: u16,
    max_in_flight: u32 = 64,
    allow_loopback: bool = false,
    io: std.Io,
};

pub const Daemon = struct {
    allocator: std.mem.Allocator,
    database: db.Db,
    curl: curl_loop.Loop,
    options: Options,
    held: std.ArrayList(Held) = .empty,

    const Held = struct {
        row: claim.Row,
        token: [32]u8,
        url: [:0]u8,
        method: [:0]u8,
        body: []u8,
    };

    pub fn init(self: *Daemon, allocator: std.mem.Allocator, options: Options) !void {
        const database = try db.Db.open(allocator, options.host, options.user, options.password, "net", options.port);
        self.* = .{
            .allocator = allocator,
            .database = database,
            .curl = undefined,
            .options = options,
        };
        try self.database.execIgnoreMissingVariable(db.single_delete_off);
        try self.curl.init(allocator, options.max_in_flight);
    }

    pub fn deinit(self: *Daemon) void {
        for (self.held.items) |*held| self.freeHeld(held);
        self.held.deinit(self.allocator);
        self.curl.deinit();
        self.database.deinit();
    }

    pub fn run(self: *Daemon) !void {
        var idle_ms: i64 = 20;
        while (true) {
            if (!try switchOn(&self.database, self.allocator)) {
                if (self.curl.inflight > 0) {
                    try self.curl.drive(200);
                    try self.finish();
                } else {
                    std.Io.sleep(self.options.io, .fromMilliseconds(idle_ms), .awake) catch return;
                    idle_ms = @min(idle_ms * 2, 500);
                }
                continue;
            }
            const reclaimed = try claim.reclaimStale(&self.database);
            const started = try self.fill();
            if (self.curl.inflight > 0) {
                try self.curl.drive(200);
                try self.finish();
                idle_ms = 20;
            } else if (started == 0 and reclaimed == 0) {
                std.Io.sleep(self.options.io, .fromMilliseconds(idle_ms), .awake) catch return;
                idle_ms = @min(idle_ms * 2, 500);
            } else idle_ms = 20;
        }
    }

    pub fn once(self: *Daemon) !void {
        if (!try switchOn(&self.database, self.allocator)) return;
        _ = try claim.reclaimStale(&self.database);
        _ = try self.fill();
        var spins: u32 = 0;
        while (self.curl.inflight > 0 and spins < 500) : (spins += 1) {
            try self.curl.drive(200);
            try self.finish();
        }
        try self.finish();
    }

    fn fill(self: *Daemon) !u32 {
        if (self.curl.inflight >= self.options.max_in_flight) return 0;
        const room = self.options.max_in_flight - self.curl.inflight;
        const token = claim.newToken();
        const rows = try claim.claim(&self.database, self.allocator, room, &token);
        defer self.allocator.free(rows);
        var started: u32 = 0;
        for (rows) |row| {
            self.dispatch(row, token) catch |err| {
                var owned = row;
                self.failLocal(&owned, &token, @errorName(err)) catch {};
                owned.deinit(self.allocator);
            };
            started += 1;
        }
        return started;
    }

    fn dispatch(self: *Daemon, row: claim.Row, token: [32]u8) !void {
        if (row.missing_webhook) return error.WebhookMissing;
        if (!allowedMethod(row.method)) return error.BadMethod;
        if (row.timeout_ms == 0 or row.timeout_ms > 300_000) return error.BadTimeout;
        const resolved = ssrf.checkUrl(self.allocator, row.url, self.options.allow_loopback) catch |err| switch (err) {
            error.Blocked, error.BadUrl => return error.SsrfBlocked,
            error.Transient => return error.Dns,
            error.OutOfMemory => return error.OutOfMemory,
        };
        defer self.allocator.free(resolved.host);
        defer self.allocator.free(resolved.ip);
        const line = try ssrf.resolveLine(self.allocator, resolved.host, resolved.port, resolved.ip);
        defer self.allocator.free(line);
        const line_z = try self.allocator.dupeZ(u8, line);
        var resolve = shim.mn_slist_append(null, line_z);
        self.allocator.free(line_z);
        errdefer shim.mn_slist_free(resolve);

        var header_list: ?*shim.SList = null;
        errdefer shim.mn_slist_free(header_list);
        if (row.headers_json) |raw| {
            const pairs = headers.parse(self.allocator, raw) catch return error.BadHeaders;
            defer {
                for (pairs) |pair| {
                    self.allocator.free(pair.key);
                    self.allocator.free(pair.value);
                }
                self.allocator.free(pairs);
            }
            for (pairs) |pair| {
                if (!headers.safePair(pair.key, pair.value) or headers.reserved(pair.key)) return error.BadHeaders;
                const line_h = try std.fmt.allocPrintSentinel(self.allocator, "{s}: {s}", .{ pair.key, pair.value }, 0);
                defer self.allocator.free(line_h);
                header_list = shim.mn_slist_append(header_list, line_h);
            }
        }
        const mac = sign.hex(sign.sign(row.body, row.secret));
        const sig = try std.fmt.allocPrintSentinel(self.allocator, "X-Maria-Signature: {s}", .{mac}, 0);
        defer self.allocator.free(sig);
        header_list = shim.mn_slist_append(header_list, sig);
        const req_id = try std.fmt.allocPrintSentinel(self.allocator, "X-Request-Id: {d}", .{row.id}, 0);
        defer self.allocator.free(req_id);
        header_list = shim.mn_slist_append(header_list, req_id);
        const now_s = @divTrunc(std.Io.Clock.real.now(self.options.io).nanoseconds, std.time.ns_per_s);
        const stamp = try std.fmt.allocPrintSentinel(self.allocator, "X-Maria-Timestamp: {d}", .{now_s}, 0);
        defer self.allocator.free(stamp);
        header_list = shim.mn_slist_append(header_list, stamp);
        const send_body = !std.mem.eql(u8, row.method, "GET") and row.body.len != 0;
        if (send_body) {
            var has_type = false;
            if (row.headers_json) |raw| has_type = containsIgnore(raw, "content-type");
            if (!has_type) header_list = shim.mn_slist_append(header_list, "Content-Type: application/json");
        }

        const url_z = try self.allocator.dupeZ(u8, row.url);
        errdefer self.allocator.free(url_z);
        const method_z = try self.allocator.dupeZ(u8, row.method);
        errdefer self.allocator.free(method_z);
        const body_copy = try self.allocator.dupe(u8, row.body);
        errdefer self.allocator.free(body_copy);
        try self.held.append(self.allocator, .{
            .row = row,
            .token = token,
            .url = url_z,
            .method = method_z,
            .body = body_copy,
        });
        const held = &self.held.items[self.held.items.len - 1];
        self.curl.add(.{
            .url = held.url,
            .method = held.method,
            .body = held.body,
            .send_body = send_body,
            .headers = header_list,
            .resolve = resolve,
            .timeout_ms = row.timeout_ms,
            .row_id = row.id,
        }) catch |err| {
            const dropped = self.held.pop().?;
            self.allocator.free(dropped.url);
            self.allocator.free(dropped.method);
            self.allocator.free(dropped.body);
            resolve = null;
            header_list = null;
            return err;
        };
        resolve = null;
        header_list = null;
    }

    fn finish(self: *Daemon) !void {
        const done = try self.curl.harvest(self.allocator);
        defer {
            for (done) |item| {
                self.allocator.free(item.body);
                self.allocator.free(item.error_text);
            }
            self.allocator.free(done);
        }
        for (done) |item| {
            const index = self.findHeld(item.row_id) orelse continue;
            var held = self.held.swapRemove(index);
            defer self.freeHeld(&held);
            const ok = item.curl_code == 0 and !item.overflow and item.status >= 200 and item.status < 300;
            if (ok) {
                claim.finish(&self.database, self.allocator, held.row, &held.token, "success", item.status, item.latency_ms, "", item.body, null) catch |err| try skipBusy(err);
            } else {
                const message = if (item.overflow) "response too large" else item.error_text;
                self.failLocal(&held.row, &held.token, message) catch |err| try skipBusy(err);
            }
        }
    }

    // 1180/1213 already retried inside claim.finish. The row stays processing
    // and reclaimStale returns it later. One conflict must not stop the process.
    fn skipBusy(err: anyerror) !void {
        if (err == error.Busy) return;
        return err;
    }

    fn failLocal(self: *Daemon, row: *claim.Row, token: []const u8, message: []const u8) !void {
        const next = row.attempts + 1;
        if (terminal(message) or next >= row.max_attempts) {
            try claim.finish(&self.database, self.allocator, row.*, token, "dead", null, 0, message, "", null);
            return;
        }
        var jitter: [2]u8 = undefined;
        const n = std.os.linux.getrandom(&jitter, jitter.len, 0);
        if (@as(isize, @bitCast(n)) != jitter.len) @panic("getrandom");
        const unit: u32 = (@as(u32, jitter[0]) << 2 | jitter[1]) % 1000;
        const delay = backoff.delayMs(next, unit);
        try claim.finish(&self.database, self.allocator, row.*, token, "retry", null, 0, message, "", delay);
    }

    fn terminal(message: []const u8) bool {
        const names = [_][]const u8{ "SsrfBlocked", "WebhookMissing", "BadMethod", "BadHeaders", "BadTimeout" };
        for (names) |name| if (std.mem.eql(u8, message, name)) return true;
        return false;
    }

    fn allowedMethod(method: []const u8) bool {
        const names = [_][]const u8{ "GET", "POST", "PUT", "PATCH", "DELETE" };
        for (names) |name| if (std.mem.eql(u8, method, name)) return true;
        return false;
    }

    fn containsIgnore(hay: []const u8, needle: []const u8) bool {
        if (needle.len == 0 or needle.len > hay.len) return false;
        var i: usize = 0;
        while (i + needle.len <= hay.len) : (i += 1) {
            if (std.ascii.eqlIgnoreCase(hay[i..][0..needle.len], needle)) return true;
        }
        return false;
    }

    fn findHeld(self: *Daemon, id: u64) ?usize {
        for (self.held.items, 0..) |held, i| if (held.row.id == id) return i;
        return null;
    }

    fn freeHeld(self: *Daemon, held: *Held) void {
        held.row.deinit(self.allocator);
        self.allocator.free(held.url);
        self.allocator.free(held.method);
        self.allocator.free(held.body);
    }
};
