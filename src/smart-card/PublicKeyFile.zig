const std = @import("std");

const PkcsError = @import("../pkcs_error.zig").PkcsError;

pub const PublicKeyFile = @This();

id: [20]u8,
pub_key_file_name: [2]u8,
priv_key_file_name: [2]u8 = std.mem.zeroes([2]u8),
modulus: [256]u8 = std.mem.zeroes([256]u8),
modulus_len: usize = 0,
exponent: [8]u8 = std.mem.zeroes([8]u8),
exponent_len: usize = 0,
allow_encrypt: bool = false,

pub fn parse(self: *PublicKeyFile, data: []const u8) PkcsError!void {
    if (data.len < 2)
        return PkcsError.GeneralError;

    if (data[0] != 0x00 or data[1] != 0x05)
        return PkcsError.GeneralError;

    var pos: usize = 3;

    if (data.len < pos + 2)
        return PkcsError.GeneralError;

    @memcpy(&self.priv_key_file_name, data[pos..(pos + 2)][0..2]);

    pos += 2;

    if (data.len < pos + 2)
        return PkcsError.GeneralError;

    const modulus_length = std.mem.readInt(u16, data[pos..(pos + 2)][0..2], .big);
    if (modulus_length > self.modulus.len)
        return PkcsError.HostMemory;

    pos += 2;

    if (data.len < pos + modulus_length)
        return PkcsError.GeneralError;

    self.modulus_len = modulus_length;
    @memcpy(self.modulus[0..modulus_length], data[pos..(pos + modulus_length)]);

    pos += modulus_length;

    if (data.len < pos + 2)
        return PkcsError.GeneralError;

    const exponent_length = std.mem.readInt(u16, data[pos..(pos + 2)][0..2], .big);
    if (exponent_length > self.exponent.len)
        return PkcsError.HostMemory;

    pos += 2;

    if (data.len < pos + exponent_length)
        return PkcsError.GeneralError;

    self.exponent_len = exponent_length;
    @memcpy(self.exponent[0..exponent_length], data[pos..(pos + exponent_length)]);

    self.allow_encrypt = ((self.priv_key_file_name[1] >> 2) & 0b0011) == 1;
}

test "parse valid public key" {
    const valid_test_pub_key_file_1: []const u8 = &[_]u8{ 0x00, 0x05, 0x01, 0x60, 0x05, 0x00, 0x02, 0xAA, 0xBB, 0x00, 0x04, 0xAA, 0xBB, 0xCC, 0xDD };

    var key_pair_1: PublicKeyFile = .{
        .id = std.mem.zeroes([20]u8),
        .pub_key_file_name = .{ 0x60, 0x04 },
    };
    try key_pair_1.parse(valid_test_pub_key_file_1);

    try std.testing.expect(key_pair_1.allow_encrypt);
    try std.testing.expectEqual([2]u8{ 0x60, 0x05 }, key_pair_1.priv_key_file_name);
    try std.testing.expectEqual(2, key_pair_1.modulus_len);
    try std.testing.expect(std.mem.eql(u8, key_pair_1.modulus[0..key_pair_1.modulus_len], &.{ 0xAA, 0xBB }));
    try std.testing.expectEqual(4, key_pair_1.exponent_len);
    try std.testing.expect(std.mem.eql(u8, key_pair_1.exponent[0..key_pair_1.exponent_len], &.{ 0xAA, 0xBB, 0xCC, 0xDD }));

    const valid_test_pub_key_file_2: []const u8 = &[_]u8{ 0x00, 0x05, 0x01, 0x60, 0x19, 0x00, 0x04, 0xAA, 0xBB, 0xCC, 0xDD, 0x00, 0x00 };

    var key_pair_2: PublicKeyFile = .{
        .id = std.mem.zeroes([20]u8),
        .pub_key_file_name = .{ 0x60, 0x18 },
    };
    try key_pair_2.parse(valid_test_pub_key_file_2);

    try std.testing.expect(!key_pair_2.allow_encrypt);
    try std.testing.expectEqual([2]u8{ 0x60, 0x19 }, key_pair_2.priv_key_file_name);
    try std.testing.expectEqual(4, key_pair_2.modulus_len);
    try std.testing.expect(std.mem.eql(u8, key_pair_2.modulus[0..key_pair_2.modulus_len], &.{ 0xAA, 0xBB, 0xCC, 0xDD }));
    try std.testing.expectEqual(0, key_pair_2.exponent_len);
    try std.testing.expect(std.mem.eql(u8, key_pair_2.exponent[0..key_pair_2.exponent_len], &.{}));
}

test "parse invalid public key" {
    const test_cases = [_][]const u8{
        &.{},
        &.{0x01},
        &.{ 0x00, 0x05 },
        &.{ 0x00, 0x05, 0x01 },
        &.{ 0x00, 0x05, 0x01, 0x60, 0x05 },
        &.{ 0x00, 0x05, 0x01, 0x60, 0x05, 0x00 },
        &.{ 0x00, 0x05, 0x01, 0x60, 0x05, 0x00, 0x00 },
        &.{ 0x00, 0x05, 0x01, 0x60, 0x05, 0x00, 0x07 },
        &.{ 0x00, 0x05, 0x01, 0x60, 0x05, 0x00, 0x01, 0xFF, 0x00 },
        &.{ 0x00, 0x05, 0x01, 0x60, 0x05, 0x00, 0x01, 0xFF, 0x00, 0x01 },
        &.{ 0x00, 0x05, 0x01, 0x60, 0x05, 0x00, 0x01, 0xFF, 0x00, 0x03, 0x01, 0x02 },
    };

    for (test_cases) |tc| {
        var key_pair: PublicKeyFile = .{
            .id = std.mem.zeroes([20]u8),
            .pub_key_file_name = .{ 0x00, 0x00 },
        };
        try std.testing.expectError(PkcsError.GeneralError, key_pair.parse(tc));
    }
}
