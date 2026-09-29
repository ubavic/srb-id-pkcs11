const std = @import("std");

const PkcsError = @import("../pkcs_error.zig").PkcsError;

pub fn pad(pin: []const u8) PkcsError![8]u8 {
    var padded_pin: [8]u8 = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0 };

    for (pin, 0..) |p, i| {
        padded_pin[i] = p;
    }

    return padded_pin;
}

pub fn validate(pin: []const u8) bool {
    if (pin.len < 4 or pin.len > 8)
        return false;

    for (pin) |p| {
        if (p < '0' or p > '9')
            return false;
    }

    return true;
}

pub fn validateNew(pin: []const u8) PkcsError!void {
    if (pin.len < 4 or pin.len > 8)
        return PkcsError.PinLenRange;

    for (pin) |p| {
        if (p < '0' or p > '9')
            return PkcsError.PinInvalid;
    }
}

test "Pad pin" {
    const test_cases = [_]struct {
        pin: []const u8,
        expected: []const u8,
    }{
        .{ .pin = &.{}, .expected = &.{ 0, 0, 0, 0, 0, 0, 0, 0 } },
        .{ .pin = &.{1}, .expected = &.{ 1, 0, 0, 0, 0, 0, 0, 0 } },
        .{ .pin = &.{ 1, 2, 3 }, .expected = &.{ 1, 2, 3, 0, 0, 0, 0, 0 } },
        .{ .pin = &.{ 1, 2, 3, 4, 5, 6, 7, 8 }, .expected = &.{ 1, 2, 3, 4, 5, 6, 7, 8 } },
    };

    for (test_cases) |tc| {
        const result = try pad(tc.pin);
        try std.testing.expectEqualSlices(u8, tc.expected, result[0..]);
    }
}

test "validate pin" {
    const test_cases = [_]struct {
        pin: []const u8,
        expected: bool,
    }{
        .{ .pin = "", .expected = false },
        .{ .pin = "1", .expected = false },
        .{ .pin = "123456789", .expected = false },
        .{ .pin = "123A", .expected = false },
        .{ .pin = "abcd", .expected = false },
        .{ .pin = "01w1", .expected = false },
        .{ .pin = "#+()", .expected = false },
        .{ .pin = "4321", .expected = true },
        .{ .pin = "0000", .expected = true },
        .{ .pin = "01234567", .expected = true },
    };

    for (test_cases) |tc|
        try std.testing.expect(validate(tc.pin) == tc.expected);
}

test "validate new pin" {
    const test_cases = [_]struct {
        pin: []const u8,
        expected: PkcsError,
    }{
        .{ .pin = "", .expected = PkcsError.PinLenRange },
        .{ .pin = "1", .expected = PkcsError.PinLenRange },
        .{ .pin = "123456789", .expected = PkcsError.PinLenRange },
        .{ .pin = "123A", .expected = PkcsError.PinInvalid },
        .{ .pin = "abcd", .expected = PkcsError.PinInvalid },
        .{ .pin = "01w1", .expected = PkcsError.PinInvalid },
        .{ .pin = "#+()", .expected = PkcsError.PinInvalid },
    };

    for (test_cases) |tc|
        try std.testing.expectError(tc.expected, validateNew(tc.pin));
}
