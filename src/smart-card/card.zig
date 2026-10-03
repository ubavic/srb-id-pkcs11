const std = @import("std");
const pcsc = @import("pcsc");

const apdu = @import("apdu.zig");
const pin = @import("pin.zig");
const TokenInfo = @import("TokenInfo.zig");

const pkcs_error = @import("../pkcs_error.zig");

const PkcsError = pkcs_error.PkcsError;

pub const Card = struct {
    smart_card: pcsc.Card,

    fn selectFile(
        self: *const Card,
        allocator: std.mem.Allocator,
        name: []const u8,
        selection_method: u8,
        selection_option: u8,
        ne: u32,
    ) PkcsError!?u16 {
        const data_unit = apdu.build(
            allocator,
            0x00,
            0xA4,
            selection_method,
            selection_option,
            name,
            ne,
        ) catch
            return PkcsError.HostMemory;
        defer allocator.free(data_unit);
        defer std.crypto.secureZero(u8, data_unit);

        var buf: [24]u8 = undefined;
        const response = self.smart_card.transmit(data_unit, &buf) catch |err|
            return pkcs_error.formPCSC(err);

        defer std.crypto.secureZero(u8, &buf);

        if (!apdu.statusOK(response))
            return PkcsError.DeviceError;

        if (response.len < 8)
            return null;

        return std.mem.readInt(u16, response[2..4], .big);
    }

    // Allocates result buffer
    fn transmit(
        self: *const Card,
        allocator: std.mem.Allocator,
        data_unit: []u8,
    ) PkcsError![]u8 {
        var buf: [pcsc.max_buffer_len]u8 = undefined;
        const response = self.smart_card.transmit(data_unit, &buf) catch |err|
            return pkcs_error.formPCSC(err);

        const out = allocator.alloc(u8, response.len) catch
            return PkcsError.HostMemory;

        @memcpy(out, response[0..response.len]);

        return out;
    }

    fn read(
        self: *const Card,
        allocator: std.mem.Allocator,
        offset: u16,
        length: u16,
    ) PkcsError![]u8 {
        const read_size = @min(length, 0xFF);
        const adpu = apdu.build(
            allocator,
            0x00,
            0xB0,
            @intCast(offset >> 8),
            @intCast(offset & 0x00FF),
            null,
            read_size,
        ) catch
            return PkcsError.HostMemory;

        const rsp = try self.transmit(allocator, adpu);
        defer allocator.free(rsp);
        defer std.crypto.secureZero(u8, rsp);

        if (!apdu.statusOK(rsp))
            return PkcsError.DeviceError;

        const rsp_len = rsp.len - 2;
        const result = allocator.alloc(u8, rsp_len) catch
            return PkcsError.HostMemory;
        @memcpy(result, rsp[0..rsp_len]);

        return result;
    }

    pub fn readFile(
        self: *Card,
        allocator: std.mem.Allocator,
        file_name: []const u8,
    ) PkcsError![]u8 {
        var offset: u16 = 0;
        var length = try self.selectFile(allocator, file_name, 0x00, 0x00, 0xff) orelse
            return PkcsError.DeviceError;

        var list = std.ArrayList(u8).initCapacity(allocator, length) catch
            return PkcsError.HostMemory;
        defer list.deinit(allocator);

        while (length > 0) {
            const data = try self.read(allocator, offset, length);
            defer allocator.free(data);
            defer std.crypto.secureZero(u8, data);

            if (data.len == 0)
                break;

            list.appendSlice(allocator, data) catch
                return PkcsError.HostMemory;

            offset += @intCast(data.len);
            length -= @intCast(data.len);
        }

        const slice = list.toOwnedSlice(allocator) catch
            return PkcsError.HostMemory;

        return slice;
    }

    pub fn readTokenInfo(
        self: *Card,
        allocator: std.mem.Allocator,
    ) PkcsError!TokenInfo {
        try initCrypto(self, allocator);

        const file_name = [_]u8{ 0x70, 0xf3 };
        const size = try self.selectFile(allocator, &file_name, 0, 0, 0xff);

        if (size == null)
            return PkcsError.GeneralError;

        const data = try self.read(allocator, 0, size.?);
        defer allocator.free(data);
        defer std.crypto.secureZero(u8, data);

        return TokenInfo.parse(data);
    }

    pub fn disconnect(
        self: *Card,
    ) PkcsError!void {
        self.smart_card.disconnect(.LEAVE) catch |err|
            return pkcs_error.formPCSC(err);
    }

    pub fn initCrypto(
        self: *const Card,
        allocator: std.mem.Allocator,
    ) PkcsError!void {
        const file_name = [_]u8{ 0xA0, 0x00, 0x00, 0x00, 0x63, 0x50, 0x4B, 0x43, 0x53, 0x2D, 0x31, 0x35 };
        _ = try self.selectFile(allocator, &file_name, 0x04, 0x00, 0);
    }

    pub fn readRandom(
        self: *const Card,
        allocator: std.mem.Allocator,
        length: u8,
    ) PkcsError![]u8 {
        const data_unit = apdu.build(allocator, 0xB0, 0x83, 0x00, 0x00, null, length) catch
            return PkcsError.HostMemory;

        defer allocator.free(data_unit);

        const response = try self.transmit(allocator, data_unit);

        if (!apdu.statusOK(response)) {
            defer allocator.free(response);
            return PkcsError.DeviceError;
        }

        return response;
    }

    pub fn verifyPin(self: *const Card, allocator: std.mem.Allocator, pin_to_verify: []const u8) PkcsError!void {
        pin.validate(pin_to_verify) catch
            return PkcsError.PinIncorrect;

        var padded_pin = try pin.pad(pin_to_verify);
        defer std.crypto.secureZero(u8, &padded_pin);

        const data_unit = apdu.build(allocator, 0x00, 0x20, 0x00, 0x80, &padded_pin, 0) catch
            return PkcsError.HostMemory;
        defer allocator.free(data_unit);
        defer std.crypto.secureZero(u8, data_unit);

        const response = try self.transmit(allocator, data_unit);
        defer allocator.free(response);
        defer std.crypto.secureZero(u8, response);

        if (apdu.statusIs(response, .{ 0x63, 0xC0 }))
            return PkcsError.PinLocked;

        if (apdu.statusIs(response, .{ 0x69, 0x83 }))
            return PkcsError.PinLocked;

        if (!apdu.statusOK(response))
            return PkcsError.PinIncorrect;
    }

    pub fn setPin(
        self: *const Card,
        allocator: std.mem.Allocator,
        old_pin: []const u8,
        new_pin: []const u8,
    ) PkcsError!void {
        try pin.validate(old_pin);
        try pin.validate(new_pin);

        try self.verifyPin(allocator, old_pin);

        var data: [16]u8 = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        defer std.crypto.secureZero(u8, &data);

        var padded_old_pin = try pin.pad(old_pin);
        defer std.crypto.secureZero(u8, &padded_old_pin);

        var padded_new_pin = try pin.pad(new_pin);
        defer std.crypto.secureZero(u8, &padded_new_pin);

        @memcpy(data[0..8], &padded_old_pin);
        @memcpy(data[8..16], &padded_new_pin);

        const data_unit = apdu.build(allocator, 0x00, 0x24, 0x00, 0x80, &data, 0) catch
            return PkcsError.HostMemory;
        defer allocator.free(data_unit);
        defer std.crypto.secureZero(u8, data_unit);

        const response = try self.transmit(allocator, data_unit);
        defer allocator.free(response);
        defer std.crypto.secureZero(u8, response);

        if (!apdu.statusOK(response))
            return PkcsError.FunctionFailed;
    }

    pub fn sign(
        self: *const Card,
        allocator: std.mem.Allocator,
        key_file_name: [2]u8,
        plain_sign: bool,
        sign_request: []u8,
    ) PkcsError![]u8 {
        const algorithm_id: u8 = if (plain_sign) 0 else 2;

        const body = [_]u8{ 0x80, 0x01, algorithm_id, 0x84, 0x02, key_file_name[0], key_file_name[1] };

        const select_key_data_unit = apdu.build(allocator, 0, 0x22, 0x41, 0xb6, body[0..body.len], 0) catch
            return PkcsError.HostMemory;
        defer allocator.free(select_key_data_unit);

        const select_key_response = try self.transmit(allocator, select_key_data_unit);
        defer allocator.free(select_key_response);

        if (!apdu.statusOK(select_key_response))
            return PkcsError.GeneralError;

        var p2: u8 = 0x00;
        var sign_request_body = sign_request;

        if (plain_sign) {
            p2 = sign_request[0];
            sign_request_body = sign_request[1..];
        }

        const sign_request_data_unit = apdu.build(allocator, 0, 0x2a, 0x9e, p2, sign_request_body, 0x100) catch
            return PkcsError.HostMemory;
        defer allocator.free(sign_request_data_unit);
        defer std.crypto.secureZero(u8, sign_request_data_unit);

        const sign_request_response = try self.transmit(allocator, sign_request_data_unit);
        defer allocator.free(sign_request_response);
        defer std.crypto.secureZero(u8, sign_request_response);

        if (!apdu.statusOK(sign_request_response))
            return PkcsError.GeneralError;

        if (sign_request_response.len <= 2)
            return PkcsError.GeneralError;

        const signature = allocator.alloc(u8, sign_request_response.len - 2) catch
            return PkcsError.HostMemory;

        @memcpy(signature, sign_request_response[0 .. sign_request_response.len - 2]);

        return signature;
    }

    pub fn decrypt(
        self: *const Card,
        allocator: std.mem.Allocator,
        key_file_name: [2]u8,
        decrypt_request: []u8,
    ) PkcsError![]u8 {
        if (decrypt_request.len >= 256)
            return PkcsError.GeneralError;

        const body = [_]u8{ 0x80, 0x01, 0x00, 0x84, 0x02, key_file_name[0], key_file_name[1] };

        const select_key_data_unit = apdu.build(allocator, 0, 0x22, 0x41, 0xb6, body[0..body.len], 0) catch
            return PkcsError.HostMemory;
        defer allocator.free(select_key_data_unit);

        const select_key_response = try self.transmit(allocator, select_key_data_unit);
        defer allocator.free(select_key_response);

        const decrypt_request_data_unit = apdu.build(allocator, 0, 0x2a, 0x80, decrypt_request[0], decrypt_request[1..], 0x100) catch
            return PkcsError.HostMemory;
        defer allocator.free(decrypt_request_data_unit);
        defer std.crypto.secureZero(u8, decrypt_request_data_unit);

        const decrypt_request_response = try self.transmit(allocator, decrypt_request_data_unit);
        defer allocator.free(decrypt_request_response);
        defer std.crypto.secureZero(u8, decrypt_request_response);

        if (!apdu.statusOK(decrypt_request_response))
            return PkcsError.GeneralError;

        const plain_message = allocator.alloc(u8, decrypt_request_response.len - 2) catch
            return PkcsError.HostMemory;

        @memcpy(plain_message, decrypt_request_response[0 .. decrypt_request_response.len - 2]);

        return plain_message;
    }
};

pub fn connect(
    allocator: std.mem.Allocator,
    smart_card_client: *pcsc.Client,
    reader_name: [*:0]const u8,
) PkcsError!Card {
    const smart_handle = smart_card_client.connect(reader_name, .SHARED, .ANY) catch |err|
        return pkcs_error.formPCSC(err);

    const card = Card{ .smart_card = smart_handle };

    try card.initCrypto(allocator);

    return card;
}
