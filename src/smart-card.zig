const std = @import("std");
const pcsc = @import("pcsc");

const apdu = @import("apdu.zig");
const pkcs_error = @import("pkcs_error.zig");

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
    ) PkcsError!void {
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

        const response = try self.transmit(allocator, data_unit);
        defer allocator.free(response);

        if (!responseOK(response))
            return PkcsError.DeviceError;
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

        std.mem.copyForwards(u8, out, response[0..response.len]);

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

        if (rsp.len < 2)
            return PkcsError.DeviceError;

        const rsp_len = rsp.len - 2;
        const result = allocator.alloc(u8, rsp_len) catch
            return PkcsError.HostMemory;
        std.mem.copyForwards(u8, result, rsp[0..rsp_len]);

        return result;
    }

    pub fn readCertificateFile(
        self: *Card,
        allocator: std.mem.Allocator,
        file_name: []const u8,
    ) PkcsError![]u8 {
        try self.selectFile(allocator, file_name, 0x00, 0x00, 0);

        const head_data = try self.read(allocator, 0, 2);
        defer allocator.free(head_data);

        if (head_data.len < 2)
            return PkcsError.DeviceError;

        var offset: u16 = 0;
        var length: u16 = std.mem.readInt(u16, @ptrCast(head_data), std.builtin.Endian.little) + 2;

        var list = std.ArrayList(u8).initCapacity(allocator, length) catch
            return PkcsError.HostMemory;
        defer list.deinit(allocator);

        while (length > 0) {
            const data = try self.read(allocator, offset, length);
            defer allocator.free(data);

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
        try self.selectFile(allocator, &file_name, 0x04, 0x00, 0);
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

        if (!responseOK(response)) {
            defer allocator.free(response);
            return PkcsError.DeviceError;
        }

        return response;
    }

    pub fn verifyPin(self: *const Card, allocator: std.mem.Allocator, pin: []const u8) PkcsError!void {
        if (!validatePin(pin))
            return PkcsError.PinIncorrect;

        const padded_pin = try padPin(pin);

        const data_unit = apdu.build(allocator, 0x00, 0x20, 0x00, 0x80, &padded_pin, 0) catch
            return PkcsError.HostMemory;
        defer allocator.free(data_unit);

        const response = try self.transmit(allocator, data_unit);
        defer allocator.free(response);

        if (responseIs(response, [_]u8{ 0x63, 0xC0 }))
            return PkcsError.PinLocked;

        if (responseIs(response, [_]u8{ 0x69, 0x83 }))
            return PkcsError.PinLocked;

        if (!responseOK(response))
            return PkcsError.PinIncorrect;
    }

    pub fn setPin(
        self: *const Card,
        allocator: std.mem.Allocator,
        old_pin: []const u8,
        new_pin: []const u8,
    ) PkcsError!void {
        if (!validatePin(old_pin))
            return PkcsError.PinIncorrect;

        if (!validatePin(new_pin))
            return PkcsError.PinIncorrect;

        try self.verifyPin(allocator, old_pin);

        var data: [16]u8 = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

        const padded_old_pin = try padPin(old_pin);
        const padded_new_pin = try padPin(new_pin);

        std.mem.copyForwards(u8, data[0..8], &padded_old_pin);
        std.mem.copyForwards(u8, data[8..16], &padded_new_pin);

        const data_unit = apdu.build(allocator, 0x00, 0x24, 0x00, 0x80, &data, 0) catch
            return PkcsError.HostMemory;
        defer allocator.free(data_unit);

        const response = try self.transmit(allocator, data_unit);
        defer allocator.free(response);

        if (!responseOK(response))
            return PkcsError.FunctionFailed;
    }

    pub fn sign(
        self: *const Card,
        allocator: std.mem.Allocator,
        key_id: u8,
        plain_sign: bool,
        sign_request: []u8,
    ) PkcsError![]u8 {
        const algorithm_id: u8 = if (plain_sign) 0 else 2;

        const body = [_]u8{ 0x80, 0x01, algorithm_id, 0x84, 0x02, 0x60, key_id };

        const select_key_data_unit = apdu.build(allocator, 0, 0x22, 0x41, 0xb6, body[0..body.len], 0) catch
            return PkcsError.HostMemory;
        defer allocator.free(select_key_data_unit);

        const select_key_response = try self.transmit(allocator, select_key_data_unit);
        defer allocator.free(select_key_response);

        if (!responseOK(select_key_response))
            return PkcsError.GeneralError;

        const sign_request_data_unit = apdu.build(allocator, 0, 0x2a, 0x9e, 0x00, sign_request, 0x100) catch
            return PkcsError.HostMemory;
        defer allocator.free(sign_request_data_unit);

        const sign_request_response = try self.transmit(allocator, sign_request_data_unit);
        defer allocator.free(sign_request_response);

        if (!responseOK(sign_request_response))
            return PkcsError.GeneralError;

        if (sign_request_response.len <= 2)
            return PkcsError.GeneralError;

        const signature = allocator.alloc(u8, sign_request_response.len - 2) catch
            return PkcsError.HostMemory;

        std.mem.copyForwards(u8, signature, sign_request_response[0 .. sign_request_response.len - 2]);

        return signature;
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

fn responseIs(rsp: []const u8, expected: [2]u8) bool {
    if (rsp.len < 2) return false;
    const sw1 = rsp[rsp.len - 2];
    const sw2 = rsp[rsp.len - 1];
    return sw1 == expected[0] and sw2 == expected[1];
}

fn responseOK(rsp: []const u8) bool {
    return responseIs(rsp, [_]u8{ 0x90, 0x00 });
}

fn padPin(pin: []const u8) PkcsError![8]u8 {
    var padded_pin: [8]u8 = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0 };

    for (pin, 0..) |p, i| {
        padded_pin[i] = p;
    }

    return padded_pin;
}

fn validatePin(pin: []const u8) bool {
    if (pin.len < 4 or pin.len > 8)
        return false;

    for (pin) |p| {
        if (p < '0' or p > '9')
            return false;
    }

    return true;
}

test "Pad pin" {
    const test_cases = [_]struct {
        pin: []const u8,
        expected: []const u8,
    }{
        .{ .pin = &.{}, .expected = &.{ 0, 0, 0, 0, 0, 0, 0, 0 } },
        .{ .pin = &.{1}, .expected = &.{ 1, 0, 0, 0, 0, 0, 0, 0 } },
        .{ .pin = &.{ 1, 2, 3 }, .expected = &.{ 1, 2, 3, 0, 0, 0, 0, 0 } },
        .{ .pin = &.{ 1, 2, 3, 4, 5, 6, 7, 8 }, .expected = &.{ 1, 2, 3, 4, 5, 6, 7, 8 } },
    };

    for (test_cases) |tc| {
        const result = try padPin(tc.pin);
        try std.testing.expectEqualSlices(u8, tc.expected, result[0..]);
    }
}
