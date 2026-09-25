const std = @import("std");
const shim = @import("shim.zig");

pub const max_response: usize = 64 * 1024;

pub const WriteCtx = struct {
    body: std.ArrayList(u8) = .empty,
    overflow: bool = false,
    allocator: std.mem.Allocator,
};

pub const InFlight = struct {
    easy: *shim.Easy,
    headers: ?*shim.SList,
    resolve: ?*shim.SList,
    write: *WriteCtx,
    errbuf: *[256]u8,
    row_id: u64,
};

pub const Done = struct {
    row_id: u64,
    curl_code: c_int,
    status: u32,
    latency_ms: u32,
    overflow: bool,
    body: []u8,
    error_text: []u8,
};

pub const Loop = struct {
    allocator: std.mem.Allocator,
    multi: *shim.Multi,
    ep: c_int,
    timer: c_int,
    poll_in: c_int,
    poll_out: c_int,
    poll_inout: c_int,
    poll_remove: c_int,
    socket_timeout: c_int,
    inflight: u32 = 0,
    fds: std.ArrayList(c_int) = .empty,
    flights: std.ArrayList(InFlight) = .empty,

    pub fn init(self: *Loop, allocator: std.mem.Allocator, max_total: u32) !void {
        if (shim.mn_global_init() != 0) return error.Curl;
        const ep = shim.mn_epoll_create();
        if (ep < 0) return error.Epoll;
        const timer = shim.mn_timerfd_create();
        if (timer < 0) return error.Timer;
        if (shim.mn_epoll_set(ep, timer, 1, 1, 0) != 0) return error.Epoll;
        self.* = .{
            .allocator = allocator,
            .multi = undefined,
            .ep = ep,
            .timer = timer,
            .poll_in = shim.mn_poll_in(),
            .poll_out = shim.mn_poll_out(),
            .poll_inout = shim.mn_poll_inout(),
            .poll_remove = shim.mn_poll_remove(),
            .socket_timeout = shim.mn_socket_timeout(),
        };
        self.multi = shim.mn_multi_new(self, max_total) orelse return error.Curl;
    }

    pub fn deinit(self: *Loop) void {
        for (self.flights.items) |*flight| self.destroyFlight(flight);
        self.flights.deinit(self.allocator);
        self.fds.deinit(self.allocator);
        shim.mn_multi_destroy(self.multi);
        _ = std.os.linux.close(self.timer);
        _ = std.os.linux.close(self.ep);
    }

    pub fn add(self: *Loop, easy_setup: struct {
        url: [:0]const u8,
        method: [:0]const u8,
        body: []const u8,
        send_body: bool,
        headers: ?*shim.SList,
        resolve: ?*shim.SList,
        timeout_ms: u32,
        row_id: u64,
    }) !void {
        const easy = shim.mn_easy_new() orelse return error.Curl;
        const write = try self.allocator.create(WriteCtx);
        write.* = .{ .allocator = self.allocator };
        const errbuf = try self.allocator.create([256]u8);
        errbuf.* = std.mem.zeroes([256]u8);
        self.flights.append(self.allocator, .{
            .easy = easy,
            .headers = easy_setup.headers,
            .resolve = easy_setup.resolve,
            .write = write,
            .errbuf = errbuf,
            .row_id = easy_setup.row_id,
        }) catch |err| {
            self.allocator.destroy(errbuf);
            self.allocator.destroy(write);
            shim.mn_easy_free(easy);
            return err;
        };
        const flight = &self.flights.items[self.flights.items.len - 1];
        const connect_ms: c_long = @intCast(@min(easy_setup.timeout_ms, 5_000));
        _ = shim.mn_easy_setup(
            easy,
            easy_setup.url,
            easy_setup.method,
            if (easy_setup.body.len == 0) "".ptr else easy_setup.body.ptr,
            @intCast(easy_setup.body.len),
            if (easy_setup.send_body) 1 else 0,
            easy_setup.headers,
            easy_setup.resolve,
            @intCast(easy_setup.timeout_ms),
            connect_ms,
            max_response,
            flight.errbuf,
            write,
        );
        if (shim.mn_multi_add(self.multi, easy) != 0) {
            var failed = self.flights.pop().?;
            self.destroyFlight(&failed);
            return error.Curl;
        }
        self.inflight += 1;
    }

    pub fn drive(self: *Loop, wait_ms: i32) !void {
        var ready: [32]shim.Ready = undefined;
        const n = shim.mn_epoll_wait(self.ep, self.timer, &ready, ready.len, wait_ms);
        if (n < 0) return error.Epoll;
        var i: usize = 0;
        while (i < @as(usize, @intCast(n))) : (i += 1) {
            if (ready[i].is_timer != 0) {
                try self.action(self.socket_timeout, 0);
            } else {
                try self.action(ready[i].fd, ready[i].in_ev | ready[i].out_ev);
            }
        }
    }

    pub fn harvest(self: *Loop, allocator: std.mem.Allocator) ![]Done {
        var out: std.ArrayList(Done) = .empty;
        errdefer out.deinit(allocator);
        while (true) {
            var easy: ?*shim.Easy = null;
            var code: c_int = 0;
            if (shim.mn_next_done(self.multi, &easy, &code) == 0) break;
            const handle = easy orelse continue;
            const index = self.find(handle) orelse continue;
            var flight = self.flights.swapRemove(index);
            _ = shim.mn_multi_remove(self.multi, handle);
            if (self.inflight > 0) self.inflight -= 1;
            const message = std.mem.sliceTo(shim.mn_errstr(code), 0);
            const err_copy = try allocator.dupe(u8, if (flight.errbuf[0] != 0) std.mem.sliceTo(flight.errbuf, 0) else message);
            const body = try flight.write.body.toOwnedSlice(self.allocator);
            try out.append(allocator, .{
                .row_id = flight.row_id,
                .curl_code = code,
                .status = @intCast(shim.mn_status(handle)),
                .latency_ms = @intCast(@max(shim.mn_time_ms(handle), 0)),
                .overflow = flight.write.overflow,
                .body = body,
                .error_text = err_copy,
            });
            shim.mn_easy_free(handle);
            shim.mn_slist_free(flight.headers);
            shim.mn_slist_free(flight.resolve);
            self.allocator.destroy(flight.errbuf);
            self.allocator.destroy(flight.write);
        }
        return try out.toOwnedSlice(allocator);
    }

    fn action(self: *Loop, sock: c_int, ev: c_int) !void {
        var running: c_int = 0;
        if (shim.mn_socket_action(self.multi, sock, ev, &running) != 0) return error.Curl;
    }

    fn find(self: *Loop, easy: *shim.Easy) ?usize {
        for (self.flights.items, 0..) |flight, i| {
            if (flight.easy == easy) return i;
        }
        return null;
    }

    fn destroyFlight(self: *Loop, flight: *InFlight) void {
        shim.mn_easy_free(flight.easy);
        shim.mn_slist_free(flight.headers);
        shim.mn_slist_free(flight.resolve);
        flight.write.body.deinit(self.allocator);
        self.allocator.destroy(flight.errbuf);
        self.allocator.destroy(flight.write);
    }

    fn hasFd(self: *Loop, sock: c_int) bool {
        for (self.fds.items) |fd| if (fd == sock) return true;
        return false;
    }

    fn removeFd(self: *Loop, sock: c_int) void {
        var i: usize = 0;
        while (i < self.fds.items.len) {
            if (self.fds.items[i] == sock) {
                _ = self.fds.swapRemove(i);
                return;
            }
            i += 1;
        }
    }

    fn onSocket(self: *Loop, sock: c_int, what: c_int) c_int {
        if (what == self.poll_remove) {
            _ = shim.mn_epoll_del(self.ep, sock);
            self.removeFd(sock);
            return 0;
        }
        const want_in: c_int = if (what == self.poll_in or what == self.poll_inout) 1 else 0;
        const want_out: c_int = if (what == self.poll_out or what == self.poll_inout) 1 else 0;
        const known = self.hasFd(sock);
        if (shim.mn_epoll_set(self.ep, sock, if (known) 0 else 1, want_in, want_out) != 0) return -1;
        if (!known) self.fds.append(self.allocator, sock) catch return -1;
        return 0;
    }
};

pub export fn mn_write_cb(ptr: [*]u8, size: usize, nmemb: usize, userdata: ?*anyopaque) callconv(.c) usize {
    const ctx: *WriteCtx = @ptrCast(@alignCast(userdata orelse return 0));
    const n = size * nmemb;
    if (ctx.body.items.len + n > max_response) {
        ctx.overflow = true;
        return 0;
    }
    ctx.body.appendSlice(ctx.allocator, ptr[0..n]) catch {
        ctx.overflow = true;
        return 0;
    };
    return n;
}

pub export fn mn_on_socket(user: ?*anyopaque, easy: ?*anyopaque, sock: c_int, what: c_int, socketp: ?*anyopaque) callconv(.c) c_int {
    _ = easy;
    _ = socketp;
    const loop: *Loop = @ptrCast(@alignCast(user orelse return -1));
    return loop.onSocket(sock, what);
}

pub export fn mn_on_timer(user: ?*anyopaque, timeout_ms: c_long) callconv(.c) c_int {
    const loop: *Loop = @ptrCast(@alignCast(user orelse return -1));
    if (shim.mn_timerfd_arm(loop.timer, timeout_ms) != 0) return -1;
    return 0;
}
