const std = @import("std");

const PkcsError = @import("../pkcs_error.zig").PkcsError;

const PaddedPin = @This();

buffer: [8]u8,

pub fn construct(pin_slice: []const u8) !PaddedPin {
    if (pin_slice.len < 4 or pin_slice.len > 8)
        return error.PinLenRange;

    for (pin_slice) |p| {
        if (p < '0' or p > '9')
            return error.PinInvalid;
    }

    var new_pin = PaddedPin{
        .buffer = @splat(0x00),
    };

    @memcpy(new_pin.buffer[0..pin_slice.len], pin_slice);

    return new_pin;
}

pub fn slice(self: *const PaddedPin) []const u8 {
    return &self.buffer;
}

test "pad pin" {
    const test_cases = [_]struct {
        pin: []const u8,
        expected: []const u8,
    }{
        .{
            .pin = &.{ '1', '2', '3', '4' },
            .expected = &.{ '1', '2', '3', '4', 0, 0, 0, 0 },
        },
        .{
            .pin = &.{ '1', '2', '3', '4', '5', '6', '7', '8' },
            .expected = &.{ '1', '2', '3', '4', '5', '6', '7', '8' },
        },
    };

    for (test_cases) |tc| {
        const pin = try construct(tc.pin);
        try std.testing.expectEqualSlices(u8, tc.expected, pin.slice());
    }
}

test "validate pin" {
    const test_cases = [_]struct {
        pin: []const u8,
        expected: PkcsError,
    }{
        .{
            .pin = "",
            .expected = error.PinLenRange,
        },
        .{
            .pin = "1",
            .expected = error.PinLenRange,
        },
        .{
            .pin = "123456789",
            .expected = error.PinLenRange,
        },
        .{
            .pin = "123A",
            .expected = error.PinInvalid,
        },
        .{
            .pin = "abcd",
            .expected = error.PinInvalid,
        },
        .{
            .pin = "01w1",
            .expected = error.PinInvalid,
        },
        .{
            .pin = "#+()",
            .expected = error.PinInvalid,
        },
    };

    for (test_cases) |tc|
        try std.testing.expectError(tc.expected, construct(tc.pin));

    const no_error_test_cases = [_][]const u8{
        "4321",
        "0000",
        "01234567",
    };

    for (no_error_test_cases) |tc|
        _ = try construct(tc);
}
