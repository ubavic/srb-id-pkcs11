const std = @import("std");

const PkcsError = @import("pkcs_error.zig").PkcsError;

const pkcs = @cImport({
    @cInclude("pkcs.h");
});

const sc = @cImport({
    @cInclude("pcsclite.h");
    @cInclude("winscard.h");
    @cInclude("wintypes.h");
});

const apdu = @import("apdu.zig");

pub const Card = struct {
    card_handle: sc.SCARDHANDLE,
    active_card_protocol: sc.DWORD,

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
        ) catch {
            return PkcsError.HostMemory;
        };
        defer allocator.free(data_unit);

        const response = try self.transmit(allocator, data_unit);
        defer allocator.free(response);

        if (!responseOK(response)) {
            return PkcsError.DeviceError;
        }
    }

    // Allocates result buffer
    fn transmit(
        self: *const Card,
        allocator: std.mem.Allocator,
        data_unit: []u8,
    ) PkcsError![]u8 {
        var buf: [256 + 2]u8 = undefined;
        var buf_len: sc.DWORD = buf.len;

        const rv = sc.SCardTransmit(
            self.card_handle,
            @ptrCast(&self.active_card_protocol),
            data_unit.ptr,
            data_unit.len,
            null,
            &buf,
            &buf_len,
        );

        try scToPkcsError(rv);

        const out = allocator.alloc(u8, buf_len) catch
            return PkcsError.HostMemory;

        std.mem.copyForwards(u8, out, buf[0..buf_len]);

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
        defer list.deinit();

        while (length > 0) {
            const data = try self.read(allocator, offset, length);
            defer allocator.free(data);

            if (data.len == 0)
                break;

            list.appendSlice(data) catch
                return PkcsError.HostMemory;

            offset += @intCast(data.len);
            length -= @intCast(data.len);
        }

        const slice = list.toOwnedSlice() catch
            return PkcsError.HostMemory;

        return slice;
    }

    pub fn disconnect(
        self: *Card,
    ) PkcsError!void {
        const rv = sc.SCardDisconnect(self.card_handle, sc.SCARD_LEAVE_CARD);
        try scToPkcsError(rv);
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
};

pub fn connect(
    allocator: std.mem.Allocator,
    smart_card_context_handle: sc.SCARDHANDLE,
    reader_name: []const u8,
) PkcsError!Card {
    var card_handle: sc.SCARDHANDLE = 0;
    var active_protocol: sc.DWORD = 0;

    const rv = sc.SCardConnect(
        smart_card_context_handle,
        reader_name.ptr,
        sc.SCARD_SHARE_SHARED,
        sc.SCARD_PROTOCOL_T0 | sc.SCARD_PROTOCOL_T1,
        &card_handle,
        &active_protocol,
    );

    try scToPkcsError(rv);

    const card = Card{
        .card_handle = card_handle,
        .active_card_protocol = active_protocol,
    };

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

fn scToPkcsError(err: sc.LONG) PkcsError!void {
    return switch (err) {
        sc.SCARD_S_SUCCESS => {},
        sc.SCARD_E_NO_SMARTCARD => PkcsError.TokenNoPresent,
        else => PkcsError.DeviceError,
    };
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
