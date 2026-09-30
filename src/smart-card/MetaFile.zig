const std = @import("std");

const PkcsError = @import("../pkcs_error.zig").PkcsError;

const MetaFile = @This();

class: u8,
file_name: [2]u8,
label: ?[]const u8,
id: [20]u8,

pub fn parse(buffer: []const u8) PkcsError!MetaFile {
    if (buffer.len < 4)
        return PkcsError.GeneralError;

    const class = buffer[0];
    if (class == 0 or class > 3)
        return PkcsError.GeneralError;

    const file_name = [2]u8{ buffer[1], buffer[2] };

    var position: usize = 3;
    var label: ?[]const u8 = null;

    const label_length = buffer[position];
    position += 1;

    if (label_length > 0) {
        if (position + label_length > buffer.len)
            return PkcsError.GeneralError;

        label = buffer[position .. position + label_length];

        position += label_length;
    }

    if (position >= buffer.len)
        return PkcsError.GeneralError;

    const id_length = buffer[position];
    position += 1;

    if (id_length != 20)
        return PkcsError.GeneralError;

    if (position + id_length > buffer.len)
        return PkcsError.GeneralError;

    var id: [20]u8 = std.mem.zeroes([20]u8);
    @memcpy(&id, buffer[position .. position + id_length]);

    return .{
        .class = class,
        .file_name = file_name,
        .label = label,
        .id = id,
    };
}

test "parse invalid meta file" {
    const test_cases = [_][]const u8{
        &.{},
        &.{0x01},
        &.{ 0x01, 0x00, 0x00 },
        &.{ 0x01, 0xff, 0xff, 0x00, 0x01 },
        &.{ 0x01, 0xff, 0xff, 0x01, 0xff },
        &.{ 0x01, 0xff, 0xff, 0x02, 0xff, 0x01, 0xff },
        &.{ 0x07, 0xff, 0xff, 0x02, 0xff, 0xff, 0x01, 0xff },
        &.{ 0x01, 0xf1, 0xf2, 0x02, 0xd1, 0xd2, 0x01, 0xff },
        &.{ 0x02, 0xa1, 0xa2, 0x00, 0x01, 0xcc },
        &.{ 0x03, 0xa1, 0xa2, 0x03, 0x11, 0x12, 0x13, 0x02, 0x21, 0x22 },
    };

    for (test_cases) |tc|
        try std.testing.expectError(PkcsError.GeneralError, MetaFile.parse(tc));
}

test "parse valid meta file" {
    const test_cases = [_]struct {
        input: []const u8,
        expected: MetaFile,
    }{
        .{
            .input = &([_]u8{ 0x01, 0xf1, 0xf2, 0x02, 0xd1, 0xd2, 0x14 } ++ [_]u8{0xff} ** 20),
            .expected = MetaFile{
                .class = 0x01,
                .file_name = .{ 0xf1, 0xf2 },
                .label = &.{ 0xd1, 0xd2 },
                .id = [_]u8{0xff} ** 20,
            },
        },
        .{
            .input = &([_]u8{ 0x02, 0xa1, 0xa2, 0x00, 0x14 } ++ [_]u8{0xcc} ** 20),
            .expected = MetaFile{
                .class = 0x02,
                .file_name = .{ 0xa1, 0xa2 },
                .label = null,
                .id = [_]u8{0xcc} ** 20,
            },
        },
        .{
            .input = &([_]u8{ 0x03, 0xa1, 0xa2, 0x03, 0x11, 0x12, 0x13, 0x14 } ++ [_]u8{0x22} ** 20 ++ [_]u8{ 0x21, 0x22 }),
            .expected = MetaFile{
                .class = 0x03,
                .file_name = .{ 0xa1, 0xa2 },
                .label = &.{ 0x11, 0x12, 0x13 },
                .id = [_]u8{0x22} ** 20,
            },
        },
        .{
            .input = &.{ 0x02, 0x60, 0x18, 0x00, 0x14, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x00, 0x01 },
            .expected = MetaFile{
                .class = 0x02,
                .file_name = .{ 0x60, 0x18 },
                .label = null,
                .id = [_]u8{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44 },
            },
        },
    };

    for (test_cases) |tc| {
        const actual = try MetaFile.parse(tc.input);

        try std.testing.expectEqual(tc.expected.class, actual.class);
        try std.testing.expectEqual(tc.expected.file_name, actual.file_name);
        try std.testing.expectEqualSlices(u8, &tc.expected.id, &actual.id);
        if (tc.expected.label != null)
            try std.testing.expectEqualSlices(u8, tc.expected.label.?, actual.label.?)
        else
            try std.testing.expectEqual(null, actual.label);
    }
}
