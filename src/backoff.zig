const std = @import("std");

/// attempt is the failure count about to be stored (1 on the first failure).
/// Delay grows from 1s and caps at 60s. jitter_unit is 0..999 and adds up to 25%.
pub fn delayMs(attempt: u32, jitter_unit: u32) u64 {
    const steps: u6 = @intCast(@min(if (attempt == 0) 0 else attempt - 1, 16));
    const base: u64 = @as(u64, 1000) << steps;
    const capped = @min(base, 60_000);
    const unit = @min(jitter_unit, 999);
    const jitter = (capped / 4) * @as(u64, unit) / 1000;
    return capped + jitter;
}

test "backoff grows then caps" {
    try std.testing.expectEqual(@as(u64, 1000), delayMs(1, 0));
    try std.testing.expectEqual(@as(u64, 2000), delayMs(2, 0));
    try std.testing.expectEqual(@as(u64, 4000), delayMs(3, 0));
    try std.testing.expectEqual(@as(u64, 60_000), delayMs(10, 0));
    const with_jitter = delayMs(1, 999);
    try std.testing.expect(with_jitter > 1000 and with_jitter <= 1250);
}
