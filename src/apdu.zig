const std = @import("std");
const testing = std.testing;

pub fn build(
    allocator: std.mem.Allocator,
    cla: u8,
    ins: u8,
    p1: u8,
    p2: u8,
    data: ?[]const u8,
    ne: u32,
) std.mem.Allocator.Error![]u8 {
    const length = if (data == null) 0 else data.?.len;

    if (length > 0xFFFF)
        return std.mem.Allocator.Error.OutOfMemory;

    var apdu = try std.ArrayList(u8).initCapacity(allocator, 4 + length);
    errdefer apdu.deinit(allocator);
    try apdu.append(allocator, cla);
    try apdu.append(allocator, ins);
    try apdu.append(allocator, p1);
    try apdu.append(allocator, p2);

    if (length == 0) {
        if (ne != 0) {
            if (ne <= 256) {
                const l: u8 = if (ne == 256) 0x00 else @intCast(ne);
                try apdu.append(allocator, l);
            } else {
                var l1: u8 = undefined;
                var l2: u8 = undefined;
                if (ne == 65536) {
                    l1 = 0;
                    l2 = 0;
                } else {
                    l1 = @intCast(ne >> 8);
                    l2 = @intCast(ne & 0xFF);
                }
                try apdu.append(allocator, l1);
                try apdu.append(allocator, l2);
            }
        }
    } else {
        if (ne == 0) {
            if (length <= 255) {
                try apdu.append(allocator, @intCast(length));
                try apdu.appendSlice(allocator, data.?);
            } else {
                try apdu.append(allocator, 0x00);
                try apdu.append(allocator, @intCast(length >> 8));
                try apdu.append(allocator, @intCast(length & 0xFF));
                try apdu.appendSlice(allocator, data.?);
            }
        } else {
            if (length <= 255 and ne <= 256) {
                try apdu.append(allocator, @intCast(length));
                try apdu.appendSlice(allocator, data.?);
                const neByte: u8 = if (ne == 256) 0x00 else @intCast(ne);
                try apdu.append(allocator, neByte);
            } else {
                try apdu.append(allocator, 0x00);
                try apdu.append(allocator, @intCast(length >> 8));
                try apdu.append(allocator, @intCast(length & 0xFF));
                try apdu.appendSlice(allocator, data.?);
                if (ne != 65536) {
                    try apdu.append(allocator, @intCast(ne >> 8));
                    try apdu.append(allocator, @intCast(ne & 0xFF));
                }
            }
        }
    }

    return apdu.toOwnedSlice(allocator);
}

test "build APDU" {
    const testCases = [_]struct {
        parameters: [4]u8,
        data: []const u8,
        ne: u32,
        expected: []const u8,
    }{
        .{ .parameters = .{ 0x00, 0xA4, 0x04, 0x01 }, .data = &.{}, .ne = 0, .expected = &.{ 0x00, 0xA4, 0x04, 0x01 } },
        .{ .parameters = .{ 0x00, 0xA4, 0x04, 0x01 }, .data = &.{}, .ne = 0xFF, .expected = &.{ 0x00, 0xA4, 0x04, 0x01, 0xFF } },
        .{ .parameters = .{ 0x00, 0xA4, 0x04, 0x01 }, .data = &.{}, .ne = 0x01FF, .expected = &.{ 0x00, 0xA4, 0x04, 0x01, 0x01, 0xFF } },
        .{ .parameters = .{ 0x00, 0xA4, 0x04, 0x01 }, .data = &.{}, .ne = 0x10000, .expected = &.{ 0x00, 0xA4, 0x04, 0x01, 0x00, 0x00 } },
        .{ .parameters = .{ 0x00, 0xA4, 0x04, 0x01 }, .data = &.{ 0x00, 0x00, 0x00 }, .ne = 0, .expected = &.{ 0x00, 0xA4, 0x04, 0x01, 0x03, 0x00, 0x00, 0x00 } },
        .{ .parameters = .{ 0x00, 0xA4, 0x04, 0x01 }, .data = &.{ 0x00, 0x00, 0x00 }, .ne = 0x01, .expected = &.{ 0x00, 0xA4, 0x04, 0x01, 0x03, 0x00, 0x00, 0x00, 0x01 } },
        .{ .parameters = .{ 0x00, 0xA4, 0x04, 0x01 }, .data = &.{ 0x00, 0x00, 0x00 }, .ne = 0x100, .expected = &.{ 0x00, 0xA4, 0x04, 0x01, 0x03, 0x00, 0x00, 0x00, 0x00 } },
    };

    for (testCases) |tc| {
        const result = try build(std.testing.allocator, tc.parameters[0], tc.parameters[1], tc.parameters[2], tc.parameters[3], tc.data, tc.ne);
        defer std.testing.allocator.free(result);
        try testing.expectEqualSlices(u8, tc.expected, result);
    }
}
