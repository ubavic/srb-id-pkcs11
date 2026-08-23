const std = @import("std");

const pkcs_error = @import("pkcs_error.zig");
const PkcsError = pkcs_error.PkcsError;

pub const Index = struct {
    buffer: []const u8,
    length: u16,
    i: u8,

    pub fn init(buffer: []const u8) PkcsError!Index {
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

    pub fn next(self: *Index) ?[2]u8 {
        if (self.i >= self.length * 2)
            return null;

        const position = self.i * 2;
        self.i += 1;

        return [2]u8{ self.buffer[position + 1], self.buffer[position] };
    }

    pub fn deinit(self: *Index, allocator: std.mem.Allocator) void {
        allocator.free(self.buffer);
    }
};

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

pub const KeyPair = struct {
    id: [20]u8,
    pub_key_file_name: ?[2]u8,
    priv_key_file_name: ?[2]u8,
    modulus: [2048]u8 = std.mem.zeroes([2048]u8),
    modulus_len: usize = 0,
    exponent: [8]u8 = std.mem.zeroes([8]u8),
    exponent_len: usize = 0,
    allow_encrypt: bool = false,

    pub fn parsePublicKeyFile(self: *KeyPair, data: []u8) PkcsError!void {
        _ = self;
        _ = data;
    }
};

pub const Keychain = struct {
    data: [8]?KeyPair,

    pub fn init() Keychain {
        return Keychain{
            .data = .{null} ** 8,
        };
    }

    pub fn addPublicKey(self: *Keychain, file_name: [2]u8, id: [20]u8, data: []u8) PkcsError!?u3 {
        const existing_index = self.findById(id);

        if (existing_index == null) {
            const new_index = try self.findEmptySlot();

            self.data[new_index] = KeyPair{
                .id = id,
                .pub_key_file_name = file_name,
            };
            self.data[new_index].?.parsePublicKeyFile(data);

            return null;
        } else {
            self.data[existing_index.?].?.parsePublicKeyFile(data);
            self.data[existing_index.?].?.pub_key_file_name = file_name;
        }

        return existing_index;
    }

    pub fn addPrivateKey(self: *Keychain, file_name: [2]u8, id: [20]u8) PkcsError!?u3 {
        const existing_index = self.findById(id);

        if (existing_index == null) {
            const new_index = try self.findEmptySlot();

            self.data[new_index] = KeyPair{
                .id = id,
                .priv_key_file_name = file_name,
            };
        } else {
            self.data[existing_index.?].?.priv_key_file_name = file_name;
        }

        return existing_index;
    }

    fn findById(self: *Keychain, id: [20]u8) ?u8 {
        for (self.data, 0..) |k, i| {
            if (k != null)
                if (k.?.id == id)
                    return i;
        }

        return null;
    }

    fn findEmptySlot(self: *Keychain) PkcsError!u8 {
        for (self.data, 0..) |k, i| {
            if (k == null)
                return i;
        }

        return PkcsError.HostMemory;
    }

    pub fn popKey(self: *Keychain, index: u3) PkcsError!KeyPair {
        if (self.data[index] == null)
            return PkcsError.GeneralError;

        defer self.data[index] = null;
        return self.data[index];
    }
};

test "parse invalid smart card file directory" {
    const test_cases = [_][]const u8{
        &.{},
        &.{0x01},
        &.{ 0x01, 0x00 },
        &.{ 0x01, 0x00, 0x00 },
        &.{ 0x02, 0x00, 0xff, 0xff },
    };

    for (test_cases) |tc|
        try std.testing.expectError(PkcsError.GeneralError, Index.init(tc));
}

test "parse valid smart card file directory" {
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
    };

    for (test_cases) |tc| {
        var actual = try Index.init(tc.input);

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
        &.{},
        &.{0x01},
        &.{ 0x01, 0x00, 0x00 },
        &.{ 0x01, 0xff, 0xff, 0x00, 0x01 },
        &.{ 0x01, 0xff, 0xff, 0x01, 0xff },
        &.{ 0x01, 0xff, 0xff, 0x02, 0xff, 0x01, 0xff },
        &.{ 0x07, 0xff, 0xff, 0x02, 0xff, 0xff, 0x01, 0xff },
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
                .buffer = &.{},
                .class = 0x01,
                .file_name = .{ 0xf1, 0xf2 },
                .label = &.{ 0xd1, 0xd2 },
                .id = &.{0xff},
            },
        },
        .{
            .input = &[_]u8{ 0x02, 0xa1, 0xa2, 0x00, 0x01, 0xcc },
            .expected = InfoFile{
                .buffer = &.{},
                .class = 0x02,
                .file_name = .{ 0xa1, 0xa2 },
                .label = null,
                .id = &.{0xcc},
            },
        },
        .{
            .input = &[_]u8{ 0x03, 0xa1, 0xa2, 0x03, 0x11, 0x12, 0x13, 0x02, 0x21, 0x22 },
            .expected = InfoFile{
                .buffer = &.{},
                .class = 0x03,
                .file_name = .{ 0xa1, 0xa2 },
                .label = &.{ 0x11, 0x12, 0x13 },
                .id = &.{ 0x21, 0x22 },
            },
        },
        .{
            .input = &.{ 0x02, 0x60, 0x18, 0x00, 0x14, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x00, 0x01 },
            .expected = InfoFile{
                .buffer = &.{},
                .class = 0x02,
                .file_name = .{ 0x60, 0x18 },
                .label = null,
                .id = &.{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44 },
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
