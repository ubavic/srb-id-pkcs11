const std = @import("std");

const apdu = @import("../apdu.zig");

test "build APDU" {
    const test_cases = [_]struct {
        parameters: [4]u8,
        data: []const u8,
        ne: u32,
        expected: []const u8,
    }{
        .{ .parameters = .{ 0x00, 0xA4, 0x04, 0x01 }, .data = &.{}, .ne = 0, .expected = &.{ 0x00, 0xA4, 0x04, 0x01 } },
        .{ .parameters = .{ 0x00, 0xA4, 0x04, 0x01 }, .data = &.{}, .ne = 0xFF, .expected = &.{ 0x00, 0xA4, 0x04, 0x01, 0xFF } },
        .{ .parameters = .{ 0x00, 0xA4, 0x04, 0x03 }, .data = &.{}, .ne = 0x01FF, .expected = &.{ 0x00, 0xA4, 0x04, 0x03, 0x00, 0x01, 0xFF } },
        .{ .parameters = .{ 0x00, 0xA4, 0x04, 0x01 }, .data = &.{}, .ne = 0x10000, .expected = &.{ 0x00, 0xA4, 0x04, 0x01, 0x00, 0x00, 0x00 } },
        .{ .parameters = .{ 0x00, 0xA4, 0x04, 0x01 }, .data = &.{ 0x00, 0x00, 0x00 }, .ne = 0, .expected = &.{ 0x00, 0xA4, 0x04, 0x01, 0x03, 0x00, 0x00, 0x00 } },
        .{ .parameters = .{ 0x00, 0xA4, 0x04, 0x01 }, .data = &.{ 0x00, 0x00, 0x00 }, .ne = 0x01, .expected = &.{ 0x00, 0xA4, 0x04, 0x01, 0x03, 0x00, 0x00, 0x00, 0x01 } },
        .{ .parameters = .{ 0x00, 0xA4, 0x04, 0x01 }, .data = &.{ 0x00, 0x00, 0x00 }, .ne = 0x100, .expected = &.{ 0x00, 0xA4, 0x04, 0x01, 0x03, 0x00, 0x00, 0x00, 0x00 } },
    };

    for (test_cases) |tc| {
        const result = try apdu.build(std.testing.allocator, tc.parameters[0], tc.parameters[1], tc.parameters[2], tc.parameters[3], tc.data, tc.ne);
        defer std.testing.allocator.free(result);
        try std.testing.expectEqualSlices(u8, tc.expected, result);
    }
}

test "Response OK" {
    const test_cases = [_]struct {
        pin: []const u8,
        expected: bool,
    }{
        .{ .pin = &.{}, .expected = false },
        .{ .pin = &.{1}, .expected = false },
        .{ .pin = &.{ 0, 0 }, .expected = false },
        .{ .pin = &.{ 1, 2, 3 }, .expected = false },
        .{ .pin = &.{ 0x90, 0x00, 0x00 }, .expected = false },
        .{ .pin = &.{ 0x00, 0x00, 0x00, 0x90, 0x10 }, .expected = false },
        .{ .pin = &.{ 0x90, 0x00 }, .expected = true },
        .{ .pin = &.{ 0x00, 0x90, 0x00 }, .expected = true },
    };

    for (test_cases) |tc| {
        try std.testing.expect(apdu.statusOK(tc.pin) == tc.expected);
    }
}
