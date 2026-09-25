const std = @import("std");

const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;

pub fn sign(body: []const u8, secret: []const u8) [HmacSha256.mac_length]u8 {
    var mac: [HmacSha256.mac_length]u8 = undefined;
    HmacSha256.create(&mac, body, secret);
    return mac;
}

pub fn hex(mac: [HmacSha256.mac_length]u8) [HmacSha256.mac_length * 2]u8 {
    return std.fmt.bytesToHex(mac, .lower);
}

test "hmac is stable and covers the body" {
    const mac = sign("{}", "secret");
    const again = sign("{}", "secret");
    try std.testing.expectEqualSlices(u8, &mac, &again);
    const other = sign("{ }", "secret");
    try std.testing.expect(!std.mem.eql(u8, &mac, &other));
    const rendered = hex(mac);
    try std.testing.expectEqual(@as(usize, 64), rendered.len);
}
