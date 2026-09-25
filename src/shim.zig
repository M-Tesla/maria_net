const std = @import("std");

pub const Multi = opaque {};
pub const Easy = opaque {};
pub const SList = opaque {};

pub const Ready = extern struct {
    fd: c_int,
    is_timer: c_int,
    in_ev: c_int,
    out_ev: c_int,
    err_ev: c_int,
};

pub extern fn mn_global_init() c_int;
pub extern fn mn_multi_new(user: ?*anyopaque, max_total: c_long) ?*Multi;
pub extern fn mn_multi_destroy(multi: ?*Multi) void;
pub extern fn mn_multi_add(multi: *Multi, easy: *Easy) c_int;
pub extern fn mn_multi_remove(multi: *Multi, easy: *Easy) c_int;
pub extern fn mn_socket_action(multi: *Multi, sock: c_int, ev: c_int, running: *c_int) c_int;
pub extern fn mn_next_done(multi: *Multi, easy: *?*Easy, result: *c_int) c_int;
pub extern fn mn_easy_new() ?*Easy;
pub extern fn mn_easy_free(easy: ?*Easy) void;
pub extern fn mn_easy_setup(
    easy: *Easy,
    url: [*:0]const u8,
    method: [*:0]const u8,
    body: [*]const u8,
    body_len: c_long,
    send_body: c_int,
    headers: ?*SList,
    resolve: ?*SList,
    timeout_ms: c_long,
    connect_timeout_ms: c_long,
    max_body: c_long,
    errbuf: [*]u8,
    write_user: ?*anyopaque,
) c_int;
pub extern fn mn_status(easy: *Easy) c_long;
pub extern fn mn_time_ms(easy: *Easy) c_long;
pub extern fn mn_errstr(code: c_int) [*:0]const u8;
pub extern fn mn_slist_append(list: ?*SList, line: [*:0]const u8) ?*SList;
pub extern fn mn_slist_free(list: ?*SList) void;
pub extern fn mn_poll_in() c_int;
pub extern fn mn_poll_out() c_int;
pub extern fn mn_poll_inout() c_int;
pub extern fn mn_poll_remove() c_int;
pub extern fn mn_socket_timeout() c_int;
pub extern fn mn_epoll_create() c_int;
pub extern fn mn_epoll_set(ep: c_int, fd: c_int, add: c_int, want_in: c_int, want_out: c_int) c_int;
pub extern fn mn_epoll_del(ep: c_int, fd: c_int) c_int;
pub extern fn mn_epoll_wait(ep: c_int, timerfd: c_int, out: [*]Ready, max: c_int, timeout_ms: c_int) c_int;
pub extern fn mn_timerfd_create() c_int;
pub extern fn mn_timerfd_arm(fd: c_int, timeout_ms: c_long) c_int;
