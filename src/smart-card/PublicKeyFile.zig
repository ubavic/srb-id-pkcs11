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

pub fn parse(self: *PublicKeyFile, data: []const u8) !void {
    if (data.len < 2)
        return error.GeneralError;

    if (data[0] != 0x00 or data[1] != 0x05)
        return error.GeneralError;

    var pos: usize = 3;

    if (data.len < pos + 2)
        return error.GeneralError;

    @memcpy(&self.priv_key_file_name, data[pos..(pos + 2)][0..2]);

    pos += 2;

    if (data.len < pos + 2)
        return error.GeneralError;

    const modulus_length = std.mem.readInt(u16, data[pos..(pos + 2)][0..2], .big);
    if (modulus_length > self.modulus.len)
        return error.HostMemory;

    pos += 2;

    if (data.len < pos + modulus_length)
        return error.GeneralError;

    self.modulus_len = modulus_length;
    @memcpy(self.modulus[0..modulus_length], data[pos..(pos + modulus_length)]);

    pos += modulus_length;

    if (data.len < pos + 2)
        return error.GeneralError;

    const exponent_length = std.mem.readInt(u16, data[pos..(pos + 2)][0..2], .big);
    if (exponent_length > self.exponent.len)
        return error.HostMemory;

    pos += 2;

    if (data.len < pos + exponent_length)
        return error.GeneralError;

    self.exponent_len = exponent_length;
    @memcpy(self.exponent[0..exponent_length], data[pos..(pos + exponent_length)]);

    self.allow_encrypt = ((self.priv_key_file_name[1] >> 2) & 0b0011) == 1;
}
