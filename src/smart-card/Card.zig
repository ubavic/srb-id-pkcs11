const std = @import("std");
const pcsc = @import("pcsc");

const apdu = @import("apdu.zig");
const PaddedPin = @import("PaddedPin.zig");
const TokenInfo = @import("TokenInfo.zig");

const pkcs_error = @import("../pkcs_error.zig");

const PkcsError = pkcs_error.PkcsError;

pub const Card = @This();

smart_card: pcsc.Card,

fn selectFile(
    self: *const Card,
    allocator: std.mem.Allocator,
    name: []const u8,
    selection_method: u8,
    selection_option: u8,
) !?u16 {
    const data_unit = apdu.build(
        allocator,
        0x00,
        0xA4,
        selection_method,
        selection_option,
        name,
        0xFF,
    ) catch
        return error.HostMemory;
    defer allocator.free(data_unit);
    defer std.crypto.secureZero(u8, data_unit);

    var buf: [pcsc.max_buffer_len]u8 = undefined;
    const response = self.smart_card.transmit(data_unit, &buf) catch |err|
        return pkcs_error.formPCSC(err);

    defer std.crypto.secureZero(u8, &buf);

    if (!apdu.statusOK(response))
        return error.DeviceError;

    if (response.len < 8)
        return null;

    return std.mem.readInt(u16, response[2..4], .big);
}

fn transmit(
    self: *const Card,
    data_unit: []u8,
    out: []u8,
) ![]const u8 {
    return self.smart_card.transmit(data_unit, out) catch |err|
        return pkcs_error.formPCSC(err);
}

fn read(
    self: *const Card,
    allocator: std.mem.Allocator,
    offset: u16,
    length: u16,
) ![]u8 {
    const read_size = @min(length, 0xFF);

    const data_unit = apdu.build(
        allocator,
        0x00,
        0xB0,
        @intCast(offset >> 8),
        @intCast(offset & 0x00FF),
        null,
        read_size,
    ) catch
        return error.HostMemory;
    defer allocator.free(data_unit);

    var response_buffer: [pcsc.max_buffer_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &response_buffer);

    const rsp = try self.transmit(data_unit, &response_buffer);

    if (!apdu.statusOK(rsp))
        return error.DeviceError;

    const rsp_len = rsp.len - 2;
    const result = allocator.alloc(u8, rsp_len) catch
        return error.HostMemory;
    @memcpy(result, rsp[0..rsp_len]);

    return result;
}

pub fn readFile(
    self: *Card,
    allocator: std.mem.Allocator,
    file_name: []const u8,
) ![]u8 {
    var offset: u16 = 0;
    var length = try self.selectFile(allocator, file_name, 0, 0) orelse
        return error.DeviceError;

    var list = std.ArrayList(u8).initCapacity(allocator, length) catch
        return error.HostMemory;
    defer list.deinit(allocator);

    while (length > 0) {
        const data = try self.read(allocator, offset, length);
        defer allocator.free(data);
        defer std.crypto.secureZero(u8, data);

        if (data.len == 0)
            break;

        list.appendSlice(allocator, data) catch
            return error.HostMemory;

        offset += @intCast(data.len);
        length -= @intCast(data.len);
    }

    const slice = list.toOwnedSlice(allocator) catch
        return error.HostMemory;

    return slice;
}

pub fn readTokenInfo(
    self: *Card,
    allocator: std.mem.Allocator,
) !TokenInfo {
    try initCrypto(self, allocator);

    const file_name = [_]u8{ 0x70, 0xf3 };
    const size = try self.selectFile(allocator, &file_name, 0, 0);

    if (size == null)
        return error.GeneralError;

    const data = try self.read(allocator, 0, size.?);
    defer allocator.free(data);
    defer std.crypto.secureZero(u8, data);

    return TokenInfo.parse(data);
}

pub fn disconnect(
    self: *Card,
) !void {
    self.smart_card.disconnect(.LEAVE) catch |err|
        return pkcs_error.formPCSC(err);
}

pub fn initCrypto(
    self: *const Card,
    allocator: std.mem.Allocator,
) !void {
    const file_name = [_]u8{ 0xA0, 0x00, 0x00, 0x00, 0x63, 0x50, 0x4B, 0x43, 0x53, 0x2D, 0x31, 0x35 };
    _ = try self.selectFile(allocator, &file_name, 0x04, 0);
}

pub fn startTransaction(
    self: *const Card,
) !pcsc.Card.Transaction {
    return self.smart_card.transaction() catch
        return error.GeneralError;
}

pub fn endTransaction(
    _: *const Card,
    tx: pcsc.Card.Transaction,
) void {
    tx.end(.LEAVE) catch {};
}

pub fn readRandom(
    self: *const Card,
    allocator: std.mem.Allocator,
    length: u8,
    out_buffer: []u8,
) ![]const u8 {
    if (out_buffer.len < length + 2)
        return error.HostMemory;

    const data_unit = apdu.build(allocator, 0xB0, 0x83, 0x00, 0x00, null, length) catch
        return error.HostMemory;

    defer allocator.free(data_unit);

    const response = try self.transmit(data_unit, out_buffer);
    if (!apdu.statusOK(response))
        return error.DeviceError;

    return response;
}

pub fn verifyPin(self: *const Card, allocator: std.mem.Allocator, pin: *const PaddedPin) !void {
    const data_unit = apdu.build(allocator, 0x00, 0x20, 0x00, 0x80, pin.slice(), 0) catch
        return error.HostMemory;
    defer allocator.free(data_unit);
    defer std.crypto.secureZero(u8, data_unit);

    var response_buffer: [pcsc.max_buffer_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &response_buffer);

    const response = try self.transmit(data_unit, &response_buffer);

    if (apdu.statusIs(response, .{ 0x63, 0xC0 }))
        return error.PinLocked;

    if (apdu.statusIs(response, .{ 0x69, 0x83 }))
        return error.PinLocked;

    if (!apdu.statusOK(response))
        return error.PinIncorrect;
}

pub fn setPin(
    self: *const Card,
    allocator: std.mem.Allocator,
    old_pin: *const PaddedPin,
    new_pin: *const PaddedPin,
) !void {
    var data: [16]u8 = @splat(0x00);
    defer std.crypto.secureZero(u8, &data);

    @memcpy(data[0..8], old_pin.slice());
    @memcpy(data[8..16], new_pin.slice());

    const data_unit = apdu.build(allocator, 0x00, 0x24, 0x00, 0x80, &data, 0) catch
        return error.HostMemory;
    defer allocator.free(data_unit);
    defer std.crypto.secureZero(u8, data_unit);

    var response_buffer: [pcsc.max_buffer_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &response_buffer);

    const response = try self.transmit(data_unit, &response_buffer);

    if (!apdu.statusOK(response))
        return error.FunctionFailed;
}

pub fn sign(
    self: *const Card,
    allocator: std.mem.Allocator,
    key_file_name: [2]u8,
    plain_sign: bool,
    sign_request: []u8,
) ![]u8 {
    const tx = try self.startTransaction();
    defer self.endTransaction(tx);

    var response_buffer: [pcsc.max_buffer_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &response_buffer);

    const algorithm_id: u8 = if (plain_sign) 0 else 2;

    const body = [_]u8{ 0x80, 0x01, algorithm_id, 0x84, 0x02, key_file_name[0], key_file_name[1] };

    const select_key_data_unit = apdu.build(allocator, 0, 0x22, 0x41, 0xb6, body[0..body.len], 0) catch
        return error.HostMemory;
    defer allocator.free(select_key_data_unit);

    const select_key_response = try self.transmit(select_key_data_unit, &response_buffer);
    if (!apdu.statusOK(select_key_response))
        return error.GeneralError;

    var p2: u8 = 0x00;
    var sign_request_body = sign_request;

    if (plain_sign) {
        p2 = sign_request[0];
        sign_request_body = sign_request[1..];
    }

    const sign_request_data_unit = apdu.build(allocator, 0, 0x2a, 0x9e, p2, sign_request_body, 0x100) catch
        return error.HostMemory;
    defer allocator.free(sign_request_data_unit);
    defer std.crypto.secureZero(u8, sign_request_data_unit);

    const sign_request_response = try self.transmit(sign_request_data_unit, &response_buffer);
    if (!apdu.statusOK(sign_request_response))
        return error.GeneralError;

    if (sign_request_response.len <= 2)
        return error.GeneralError;

    const signature = allocator.alloc(u8, sign_request_response.len - 2) catch
        return error.HostMemory;

    @memcpy(signature, sign_request_response[0 .. sign_request_response.len - 2]);

    return signature;
}

pub fn decrypt(
    self: *const Card,
    allocator: std.mem.Allocator,
    key_file_name: [2]u8,
    decrypt_request: []u8,
) ![]u8 {
    const tx = try self.startTransaction();
    defer self.endTransaction(tx);

    var response_buffer: [pcsc.max_buffer_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &response_buffer);

    if (decrypt_request.len >= 256)
        return error.GeneralError;

    const body = [_]u8{ 0x80, 0x01, 0x00, 0x84, 0x02, key_file_name[0], key_file_name[1] };

    const select_key_data_unit = apdu.build(allocator, 0, 0x22, 0x41, 0xb6, body[0..body.len], 0) catch
        return error.HostMemory;
    defer allocator.free(select_key_data_unit);

    const select_key_response = try self.transmit(select_key_data_unit, &response_buffer);
    if (!apdu.statusOK(select_key_response))
        return error.GeneralError;

    const decrypt_request_data_unit = apdu.build(allocator, 0, 0x2a, 0x80, decrypt_request[0], decrypt_request[1..], 0x100) catch
        return error.HostMemory;
    defer allocator.free(decrypt_request_data_unit);
    defer std.crypto.secureZero(u8, decrypt_request_data_unit);

    const decrypt_request_response = try self.transmit(decrypt_request_data_unit, &response_buffer);
    if (!apdu.statusOK(decrypt_request_response))
        return error.GeneralError;

    const plain_message = allocator.alloc(u8, decrypt_request_response.len - 2) catch
        return error.HostMemory;

    @memcpy(plain_message, decrypt_request_response[0 .. decrypt_request_response.len - 2]);

    return plain_message;
}

pub fn connect(
    allocator: std.mem.Allocator,
    smart_card_client: *pcsc.Client,
    reader_name: [*:0]const u8,
) !Card {
    const smart_handle = smart_card_client.connect(reader_name, .SHARED, .ANY) catch |err|
        return pkcs_error.formPCSC(err);

    const card = Card{ .smart_card = smart_handle };

    try card.initCrypto(allocator);

    return card;
}
