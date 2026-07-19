const std = @import("std");

const pkcs_error = @import("pkcs_error.zig");
const PkcsError = pkcs_error.PkcsError;

pub const InfoFile = struct {
    buffer: []const u8,
    class: u8,
    file_name: [2]u8,
    label: ?[]const u8,
    id: []const u8,

    pub fn parse(buffer: []const u8) PkcsError!InfoFile {
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

        if (position + id_length > buffer.len)
            return PkcsError.GeneralError;

        return .{
            .buffer = buffer,
            .class = class,
            .file_name = file_name,
            .label = label,
            .id = buffer[position .. position + id_length],
        };
    }

    pub fn deinit(self: *InfoFile, allocator: std.mem.Allocator) void {
        allocator.free(self.buffer);
    }
};

pub const InfoFileIndex = struct {
    buffer: []const u8,
    length: u16,
    i: u8,

    pub fn init(buffer: []const u8) PkcsError!InfoFileIndex {
        if (buffer.len < 2)
            return PkcsError.GeneralError;

        const length = std.mem.readInt(u16, buffer[0..2], .little);

        if (2 * length > buffer.len - 2)
            return PkcsError.GeneralError;

        return .{
            .buffer = buffer,
            .length = length,
            .i = 1,
        };
    }

    pub fn next(self: *InfoFileIndex) ?[2]u8 {
        if (self.i >= self.length * 2)
            return null;

        const position = self.i * 2;
        self.i += 1;

        return [2]u8{ self.buffer[position + 1], self.buffer[position] };
    }

    pub fn deinit(self: *InfoFileIndex, allocator: std.mem.Allocator) void {
        allocator.free(self.buffer);
    }
};

test "parse invalid smart card file directory" {
    const test_cases = [_][]const u8{
        &[_]u8{},
        &[_]u8{0x01},
        &[_]u8{ 0x01, 0x00 },
        &[_]u8{ 0x01, 0x00, 0x00 },
        &[_]u8{ 0x02, 0x00, 0xff, 0xff },
    };

    for (test_cases) |tc|
        try std.testing.expectError(PkcsError.GeneralError, InfoFileIndex.init(tc));
}

test "parse valid smart card file directory" {
    const test_cases = [_]struct {
        input: []const u8,
        expected_values: []const [2]u8,
    }{
        .{
            .input = &[_]u8{ 0x00, 0x00 },
            .expected_values = &[_][2]u8{},
        },
        .{
            .input = &[_]u8{ 0x01, 0x00, 0xff, 0xdd },
            .expected_values = &[_][2]u8{.{ 0xdd, 0xff }},
        },
    };

    for (test_cases) |tc| {
        var actual = try InfoFileIndex.init(tc.input);

        try std.testing.expectEqual(tc.expected_values.len, actual.length);

        var i: usize = 0;
        while (actual.next()) |a| {
            try std.testing.expectEqual(tc.expected_values[i], a);
            i += 1;
        }
    }
}

test "parse invalid smart card file" {
    const test_cases = [_][]const u8{
        &[_]u8{},
        &[_]u8{0x01},
        &[_]u8{ 0x01, 0x00, 0x00 },
        &[_]u8{ 0x01, 0xff, 0xff, 0x00, 0x01 },
        &[_]u8{ 0x01, 0xff, 0xff, 0x01, 0xff },
        &[_]u8{ 0x01, 0xff, 0xff, 0x02, 0xff, 0x01, 0xff },
        &[_]u8{ 0x07, 0xff, 0xff, 0x02, 0xff, 0xff, 0x01, 0xff },
    };

    for (test_cases) |tc|
        try std.testing.expectError(PkcsError.GeneralError, InfoFile.parse(tc));
}

test "parse valid smart card file" {
    const test_cases = [_]struct {
        input: []const u8,
        expected: InfoFile,
    }{
        .{
            .input = &[_]u8{ 0x01, 0xf1, 0xf2, 0x02, 0xd1, 0xd2, 0x01, 0xff },
            .expected = InfoFile{
                .buffer = &[_]u8{},
                .class = 0x01,
                .file_name = [2]u8{ 0xf1, 0xf2 },
                .label = &[_]u8{ 0xd1, 0xd2 },
                .id = &[_]u8{0xff},
            },
        },
        .{
            .input = &[_]u8{ 0x02, 0xa1, 0xa2, 0x00, 0x01, 0xcc },
            .expected = InfoFile{
                .buffer = &[_]u8{},
                .class = 0x02,
                .file_name = [2]u8{ 0xa1, 0xa2 },
                .label = null,
                .id = &[_]u8{0xcc},
            },
        },
        .{
            .input = &[_]u8{ 0x03, 0xa1, 0xa2, 0x03, 0x11, 0x12, 0x13, 0x02, 0x21, 0x22 },
            .expected = InfoFile{
                .buffer = &[_]u8{},
                .class = 0x03,
                .file_name = [2]u8{ 0xa1, 0xa2 },
                .label = &[_]u8{ 0x11, 0x12, 0x13 },
                .id = &[_]u8{ 0x21, 0x22 },
            },
        },
    };

    for (test_cases) |tc| {
        const actual = try InfoFile.parse(tc.input);

        try std.testing.expectEqual(tc.expected.class, actual.class);
        try std.testing.expectEqual(tc.expected.file_name, actual.file_name);
        try std.testing.expectEqualSlices(u8, tc.expected.id, actual.id);
        if (tc.expected.label != null)
            try std.testing.expectEqualSlices(u8, tc.expected.label.?, actual.label.?)
        else
            try std.testing.expectEqual(null, actual.label);
    }
}
