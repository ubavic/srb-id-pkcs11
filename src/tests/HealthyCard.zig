//! Card that answers every request successfully. Private key operations
//! are computed in software with the injected `key_pair`.

const std = @import("std");

const KeyPair = @import("KeyPair.zig");
const PaddedPin = @import("../smart-card/PaddedPin.zig");
const TokenInfo = @import("../smart-card/TokenInfo.zig");

const HealthyCard = @This();

/// Key stored on the card. Signing and decryption fail without it.
key_pair: ?*const KeyPair = null,
connected: bool = true,
open_transactions: usize = 0,
sign_requests: usize = 0,
decrypt_requests: usize = 0,
random_requests: usize = 0,

pub const Transaction = struct {};

pub fn readFile(_: *HealthyCard, allocator: std.mem.Allocator, _: []const u8) ![]u8 {
    return allocator.alloc(u8, 0) catch
        return error.HostMemory;
}

pub fn readTokenInfo(_: *HealthyCard, _: std.mem.Allocator) !TokenInfo {
    return .{};
}

pub fn disconnect(self: *HealthyCard) !void {
    self.connected = false;
}

pub fn initCrypto(_: *const HealthyCard, _: std.mem.Allocator) !void {}

pub fn startTransaction(self: *HealthyCard) !Transaction {
    self.open_transactions += 1;
    return .{};
}

pub fn endTransaction(self: *HealthyCard, _: Transaction) void {
    self.open_transactions -= 1;
}

/// Every byte of the response is the request number (starting with 1),
/// so tests can tell responses apart.
pub fn readRandom(self: *HealthyCard, _: std.mem.Allocator, length: u8, out_buffer: []u8) ![]const u8 {
    if (out_buffer.len < @as(usize, length) + 2)
        return error.HostMemory;

    self.random_requests += 1;

    @memset(out_buffer[0..length], @truncate(self.random_requests));
    out_buffer[length] = 0x90;
    out_buffer[length + 1] = 0x00;

    return out_buffer[0 .. length + 2];
}

pub fn verifyPin(_: *const HealthyCard, _: std.mem.Allocator, _: *const PaddedPin) !void {}

pub fn setPin(_: *const HealthyCard, _: std.mem.Allocator, _: *const PaddedPin, _: *const PaddedPin) !void {}

pub fn sign(self: *HealthyCard, allocator: std.mem.Allocator, key_file_name: [2]u8, plain_sign: bool, sign_request: []u8) ![]u8 {
    const key_pair = try self.privateKey(key_file_name);
    const key_size = key_pair.size();

    var buffer: [KeyPair.max_size]u8 = @splat(0x00);
    const block = buffer[0..key_size];

    if (plain_sign) {
        if (sign_request.len != key_size)
            return error.GeneralError;

        @memcpy(block, sign_request);
    } else {
        if (sign_request.len > key_size - 11)
            return error.GeneralError;

        // EMSA-PKCS1-v1_5 padding is applied by the card
        const data_start = key_size - sign_request.len;
        block[1] = 0x01;
        @memset(block[2 .. data_start - 1], 0xFF);
        @memcpy(block[data_start..], sign_request);
    }

    self.sign_requests += 1;

    return privateKeyOperation(allocator, key_pair, block);
}

pub fn decrypt(self: *HealthyCard, allocator: std.mem.Allocator, key_file_name: [2]u8, decrypt_request: []u8) ![]u8 {
    const key_pair = try self.privateKey(key_file_name);

    if (decrypt_request.len != key_pair.size())
        return error.GeneralError;

    self.decrypt_requests += 1;

    return privateKeyOperation(allocator, key_pair, decrypt_request);
}

fn privateKey(self: *const HealthyCard, key_file_name: [2]u8) error{GeneralError}!*const KeyPair {
    const key_pair = self.key_pair orelse
        return error.GeneralError;

    if (!std.mem.eql(u8, &key_file_name, &KeyPair.private_key_file_name))
        return error.GeneralError;

    return key_pair;
}

fn privateKeyOperation(allocator: std.mem.Allocator, key_pair: *const KeyPair, input: []const u8) error{ GeneralError, HostMemory }![]u8 {
    const Modulus = std.crypto.ff.Modulus(KeyPair.max_size * 8);

    const n = Modulus.fromBytes(key_pair.modulus, .big) catch
        return error.GeneralError;
    const m = Modulus.Fe.fromBytes(n, input, .big) catch
        return error.GeneralError;
    const result = n.powWithEncodedExponent(m, key_pair.private_exponent, .big) catch
        return error.GeneralError;

    const output = allocator.alloc(u8, key_pair.size()) catch
        return error.HostMemory;
    errdefer allocator.free(output);

    result.toBytes(output, .big) catch
        return error.GeneralError;

    return output;
}
