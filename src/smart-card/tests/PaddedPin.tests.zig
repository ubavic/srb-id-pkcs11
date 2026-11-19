const std = @import("std");

const PaddedPin = @import("../PaddedPin.zig");

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
        const pin = try PaddedPin.construct(tc.pin);
        try std.testing.expectEqualSlices(u8, tc.expected, pin.slice());
    }
}

test "validate pin" {
    const test_cases = [_]struct {
        pin: []const u8,
        expected: anyerror,
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
        try std.testing.expectError(tc.expected, PaddedPin.construct(tc.pin));

    const no_error_test_cases = [_][]const u8{
        "4321",
        "0000",
        "01234567",
    };

    for (no_error_test_cases) |tc|
        _ = try PaddedPin.construct(tc);
}
