const std = @import("std");

const PkcsError = @import("../pkcs_error.zig").PkcsError;

const Index = @This();

buffer: []const u8,
length: u16,
i: usize,

pub fn init(buffer: []const u8) PkcsError!Index {
    if (buffer.len < 2)
        return PkcsError.GeneralError;

    const length = std.mem.readInt(u16, buffer[0..2], .little);

    if (2 * @as(usize, length) > buffer.len - 2)
        return PkcsError.GeneralError;

    return .{
        .buffer = buffer,
        .length = length,
        .i = 0,
    };
}

pub fn next(self: *Index) ?[2]u8 {
    if (self.i >= self.length)
        return null;

    const position = 2 + 2 * self.i;
    self.i += 1;

    return [2]u8{ self.buffer[position + 1], self.buffer[position] };
}

pub fn deinit(self: *Index, allocator: std.mem.Allocator) void {
    allocator.free(self.buffer);
}

test "parse invalid index" {
    const test_cases = [_][]const u8{
        &.{},
        &.{0x01},
        &.{ 0x01, 0x00 },
        &.{ 0x01, 0x00, 0x00 },
        &.{ 0x02, 0x00, 0xff, 0xff },
        &.{ 0xff, 0xff },
    };

    for (test_cases) |tc|
        try std.testing.expectError(PkcsError.GeneralError, Index.init(tc));
}

test "parse valid index" {
    const test_cases = [_]struct {
        input: []const u8,
        expected_values: []const [2]u8,
    }{
        .{
            .input = &.{ 0x00, 0x00 },
            .expected_values = &.{},
        },
        .{
            .input = &.{ 0x01, 0x00, 0xff, 0xdd },
            .expected_values = &.{.{ 0xdd, 0xff }},
        },
        .{
            .input = &.{ 0x02, 0x00, 0x02, 0x71, 0x03, 0x71 },
            .expected_values = &.{ .{ 0x71, 0x02 }, .{ 0x71, 0x03 } },
        },
        .{
            .input = &.{ 0x03, 0x00, 0x02, 0x71, 0x03, 0x71, 0x04, 0x71 },
            .expected_values = &.{ .{ 0x71, 0x02 }, .{ 0x71, 0x03 }, .{ 0x71, 0x04 } },
        },
        .{
            .input = &.{ 0x02, 0x00, 0x02, 0x71, 0x03, 0x71, 0xaa, 0xaa, 0xaa, 0xaa },
            .expected_values = &.{ .{ 0x71, 0x02 }, .{ 0x71, 0x03 } },
        },
    };

    for (test_cases) |tc| {
        var actual = try Index.init(tc.input);

        try std.testing.expectEqual(tc.expected_values.len, actual.length);

        var i: usize = 0;
        while (actual.next()) |a| {
            if (i >= tc.expected_values.len)
                return error.TooManyEntries;

            try std.testing.expectEqual(tc.expected_values[i], a);
            i += 1;
        }

        try std.testing.expectEqual(tc.expected_values.len, i);
    }
}

test "iterate index with more than 127 entries" {
    const entry_count = 200;

    var buffer: [2 + 2 * entry_count]u8 = undefined;
    std.mem.writeInt(u16, buffer[0..2], entry_count, .little);

    for (0..entry_count) |n| {
        buffer[2 + 2 * n] = @intCast(n);
        buffer[3 + 2 * n] = 0x71;
    }

    var index = try Index.init(&buffer);

    var count: usize = 0;
    while (index.next()) |entry| {
        try std.testing.expectEqual([2]u8{ 0x71, @intCast(count) }, entry);
        count += 1;
    }

    try std.testing.expectEqual(@as(usize, entry_count), count);
}
