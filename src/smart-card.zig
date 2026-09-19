const std = @import("std");
const pcsc = @import("pcsc");

const apdu = @import("apdu.zig");
const pkcs_error = @import("pkcs_error.zig");

const PkcsError = pkcs_error.PkcsError;

// Two-level protection for card access:
//
// 1. A process-wide lock (`card_ops_busy`) serializes every PC/SC
//    interaction made by this module. libpcsclite serializes all calls of
//    one process behind a single internal mutex, and pcscd parks
//    SCardConnect while any connection holds a transaction. If one thread
//    sits inside a transaction while another thread issues SCardConnect,
//    the connect blocks holding libpcsclite's mutex and the transaction
//    holder can no longer transmit: instant deadlock. The lock makes that
//    overlap impossible.
//
// 2. A PC/SC transaction per operation gives exclusive card access across
//    processes, so a multi-APDU sequence (file selection followed by
//    chunked reads, key selection followed by signing) is never
//    interleaved with another client's traffic. Interleaving corrupts the
//    card's logical state and can kill the T=1 link on flaky readers.
var card_ops_busy: std.atomic.Value(bool) = std.atomic.Value(bool).init(false);

pub fn lockCardOps() void {
    while (card_ops_busy.swap(true, .acquire))
        std.Thread.yield() catch {};
}

pub fn unlockCardOps() void {
    card_ops_busy.store(false, .release);
}

// Optional diagnostics, enabled by setting SRB_ID_DEBUG in the environment:
// writes card status words to stderr so a browser launched with stderr
// redirected to a file reveals exactly which APDU the card rejects.
// Never logs PINs or request payloads.
fn debugSw(tag: []const u8, rsp: []const u8) void {
    if (std.c.getenv("SRB_ID_DEBUG") == null) return;
    var buf: [128]u8 = undefined;
    const sw1: u8 = if (rsp.len >= 2) rsp[rsp.len - 2] else 0;
    const sw2: u8 = if (rsp.len >= 2) rsp[rsp.len - 1] else 0;
    const msg = std.fmt.bufPrint(&buf, "[srb-id] {s}: len={d} SW={x:0>2}{x:0>2}\n", .{ tag, rsp.len, sw1, sw2 }) catch return;
    _ = std.c.write(2, msg.ptr, msg.len);
}

fn debugMsg(tag: []const u8) void {
    if (std.c.getenv("SRB_ID_DEBUG") == null) return;
    var buf: [128]u8 = undefined;
    const msg = std.fmt.bufPrint(&buf, "[srb-id] {s}\n", .{tag}) catch return;
    _ = std.c.write(2, msg.ptr, msg.len);
}

const OpGuard = struct {
    transaction: ?pcsc.Card.Transaction,
    locked: bool,

    fn release(self: OpGuard) void {
        if (self.transaction) |t|
            t.end(.LEAVE) catch {};
        if (self.locked)
            unlockCardOps();
    }
};

// Full guard: in-process lock plus cross-process transaction.
fn beginOp(card: pcsc.Card) OpGuard {
    lockCardOps();
    return .{ .transaction = card.transaction() catch null, .locked = true };
}

// Transaction-only guard for callers that already hold the card-ops lock.
fn beginTx(card: pcsc.Card) OpGuard {
    return .{ .transaction = card.transaction() catch null, .locked = false };
}

pub const CardsTokenInfo = struct {
    token_label: [32]u8 = [_]u8{0x20} ** 32,
    token_serial_number: [16]u8 = [_]u8{0x20} ** 16,
};

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
        defer std.crypto.secureZero(u8, data_unit);

        const response = try self.transmit(allocator, data_unit);
        defer allocator.free(response);
        defer std.crypto.secureZero(u8, response);

        if (!responseOK(response))
            return PkcsError.DeviceError;
    }

    // A session's connection can go stale while it sits idle: when any
    // client resets the card, PC/SC fails the next use of every other
    // handle with RESET_CARD (or UNPOWERED_CARD) until that handle is
    // reconnected. Reconnect, reselect the applet (the reset cleared the
    // card's selection state), and let the caller retry.
    fn recoverConnection(self: *const Card, allocator: std.mem.Allocator) bool {
        debugMsg("stale handle: reconnecting");
        @constCast(&self.smart_card).reconnect(.SHARED, .LEAVE) catch
            return false;

        const aid = [_]u8{ 0xA0, 0x00, 0x00, 0x00, 0x63, 0x50, 0x4B, 0x43, 0x53, 0x2D, 0x31, 0x35 };
        const data_unit = apdu.build(allocator, 0x00, 0xA4, 0x04, 0x00, &aid, 0) catch
            return true;
        defer allocator.free(data_unit);

        var buf: [pcsc.max_buffer_len]u8 = undefined;
        _ = self.smart_card.transmit(data_unit, &buf) catch
            return false;

        return true;
    }

    // Allocates result buffer
    fn transmit(
        self: *const Card,
        allocator: std.mem.Allocator,
        data_unit: []u8,
    ) PkcsError![]u8 {
        var buf: [pcsc.max_buffer_len]u8 = undefined;
        const response = self.smart_card.transmit(data_unit, &buf) catch |err| blk: {
            switch (err) {
                pcsc.Err.ResetCard, pcsc.Err.UnpoweredCard => {
                    if (!self.recoverConnection(allocator))
                        return pkcs_error.formPCSC(err);

                    break :blk self.smart_card.transmit(data_unit, &buf) catch |retry_err|
                        return pkcs_error.formPCSC(retry_err);
                },
                else => return pkcs_error.formPCSC(err),
            }
        };

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

        if (rsp.len < 2)
            return PkcsError.DeviceError;

        const rsp_len = rsp.len - 2;
        const result = allocator.alloc(u8, rsp_len) catch
            return PkcsError.HostMemory;
        @memcpy(result, rsp[0..rsp_len]);

        return result;
    }

    pub fn readCertificateFile(
        self: *Card,
        allocator: std.mem.Allocator,
        file_name: []const u8,
    ) PkcsError![]u8 {
        const guard = beginOp(self.smart_card);
        defer guard.release();

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
    ) PkcsError!CardsTokenInfo {
        // Caller (reader refresh) already holds the card-ops lock.
        const guard = beginTx(self.smart_card);
        defer guard.release();

        try initCryptoUnlocked(self, allocator);

        const file_name = [_]u8{ 0x70, 0xf3 };
        try self.selectFile(allocator, &file_name, 0, 0, 0);

        const data = try self.read(allocator, 0, 52);
        defer allocator.free(data);
        defer std.crypto.secureZero(u8, data);

        return parseTokenInfo(data);
    }

    pub fn disconnect(
        self: *Card,
    ) PkcsError!void {
        lockCardOps();
        defer unlockCardOps();

        self.smart_card.disconnect(.LEAVE) catch |err|
            return pkcs_error.formPCSC(err);
    }

    // Caller must hold the card-ops lock (see `connect`).
    pub fn initCrypto(
        self: *const Card,
        allocator: std.mem.Allocator,
    ) PkcsError!void {
        const guard = beginTx(self.smart_card);
        defer guard.release();

        try self.initCryptoUnlocked(allocator);
    }

    fn initCryptoUnlocked(
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
        const guard = beginOp(self.smart_card);
        defer guard.release();

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
        const guard = beginOp(self.smart_card);
        defer guard.release();

        try self.verifyPinUnlocked(allocator, pin);
    }

    fn verifyPinUnlocked(self: *const Card, allocator: std.mem.Allocator, pin: []const u8) PkcsError!void {
        if (!validatePin(pin))
            return PkcsError.PinIncorrect;

        var padded_pin = try padPin(pin);
        defer std.crypto.secureZero(u8, &padded_pin);

        const data_unit = apdu.build(allocator, 0x00, 0x20, 0x00, 0x80, &padded_pin, 0) catch
            return PkcsError.HostMemory;
        defer allocator.free(data_unit);
        defer std.crypto.secureZero(u8, data_unit);

        const response = try self.transmit(allocator, data_unit);
        defer allocator.free(response);
        defer std.crypto.secureZero(u8, response);

        debugSw("pin-verify", response);

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

        try validateNewPin(new_pin);

        const guard = beginOp(self.smart_card);
        defer guard.release();

        try self.verifyPinUnlocked(allocator, old_pin);

        var data: [16]u8 = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        defer std.crypto.secureZero(u8, &data);

        var padded_old_pin = try padPin(old_pin);
        defer std.crypto.secureZero(u8, &padded_old_pin);

        var padded_new_pin = try padPin(new_pin);
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
        const guard = beginOp(self.smart_card);
        defer guard.release();

        const algorithm_id: u8 = if (plain_sign) 0 else 2;

        const body = [_]u8{ 0x80, 0x01, algorithm_id, 0x84, 0x02, 0x60, key_id };

        const select_key_data_unit = apdu.build(allocator, 0, 0x22, 0x41, 0xb6, body[0..body.len], 0) catch
            return PkcsError.HostMemory;
        defer allocator.free(select_key_data_unit);

        const select_key_response = try self.transmit(allocator, select_key_data_unit);
        defer allocator.free(select_key_response);

        debugSw("sign-mse", select_key_response);

        if (!responseOK(select_key_response))
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

        debugSw("sign-pso", sign_request_response);

        if (!responseOK(sign_request_response))
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
        key_id: u8,
        decrypt_request: []u8,
    ) PkcsError![]u8 {
        const guard = beginOp(self.smart_card);
        defer guard.release();

        if (decrypt_request.len >= 256)
            return PkcsError.GeneralError;

        const body = [_]u8{ 0x80, 0x01, 0x00, 0x84, 0x02, 0x60, key_id };

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

        if (!responseOK(decrypt_request_response))
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
    lockCardOps();
    defer unlockCardOps();

    const smart_handle = smart_card_client.connect(reader_name, .SHARED, .ANY) catch |err|
        return pkcs_error.formPCSC(err);

    const card = Card{ .smart_card = smart_handle };

    errdefer card.smart_card.disconnect(.LEAVE) catch {};

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

fn validateNewPin(pin: []const u8) PkcsError!void {
    if (pin.len < 4 or pin.len > 8)
        return PkcsError.PinLenRange;

    for (pin) |p| {
        if (p < '0' or p > '9')
            return PkcsError.PinInvalid;
    }
}

fn parseTokenInfo(data: []const u8) CardsTokenInfo {
    var token_info = CardsTokenInfo{};

    if (data.len <= 48)
        return token_info;

    @memcpy(&token_info.token_label, data[0..32]);

    var pos: usize = 0;
    for (32..48) |i| {
        if (data[i] == 0x00)
            break;

        token_info.token_serial_number[pos] = data[i];

        pos += 1;
    }

    return token_info;
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

test "validate pin" {
    const test_cases = [_]struct {
        pin: []const u8,
        expected: bool,
    }{
        .{ .pin = "", .expected = false },
        .{ .pin = "1", .expected = false },
        .{ .pin = "123456789", .expected = false },
        .{ .pin = "123A", .expected = false },
        .{ .pin = "abcd", .expected = false },
        .{ .pin = "01w1", .expected = false },
        .{ .pin = "#+()", .expected = false },
        .{ .pin = "4321", .expected = true },
        .{ .pin = "0000", .expected = true },
        .{ .pin = "01234567", .expected = true },
    };

    for (test_cases) |tc|
        try std.testing.expect(validatePin(tc.pin) == tc.expected);
}

test "validate new pin" {
    const test_cases = [_]struct {
        pin: []const u8,
        expected: PkcsError,
    }{
        .{ .pin = "", .expected = PkcsError.PinLenRange },
        .{ .pin = "1", .expected = PkcsError.PinLenRange },
        .{ .pin = "123456789", .expected = PkcsError.PinLenRange },
        .{ .pin = "123A", .expected = PkcsError.PinInvalid },
        .{ .pin = "abcd", .expected = PkcsError.PinInvalid },
        .{ .pin = "01w1", .expected = PkcsError.PinInvalid },
        .{ .pin = "#+()", .expected = PkcsError.PinInvalid },
    };

    for (test_cases) |tc|
        try std.testing.expectError(tc.expected, validateNewPin(tc.pin));
}

test "Response OK" {
    const test_cases = [_]struct {
        pin: []const u8,
        expected: bool,
    }{
        .{ .pin = &.{}, .expected = false },
        .{ .pin = &.{1}, .expected = false },
        .{ .pin = &.{ 0, 0 }, .expected = false },
        .{ .pin = &.{ 1, 2, 3 }, .expected = false },
        .{ .pin = &.{ 0x90, 0x00, 0x00 }, .expected = false },
        .{ .pin = &.{ 0x00, 0x00, 0x00, 0x90, 0x10 }, .expected = false },
        .{ .pin = &.{ 0x90, 0x00 }, .expected = true },
        .{ .pin = &.{ 0x00, 0x90, 0x00 }, .expected = true },
    };

    for (test_cases) |tc| {
        try std.testing.expect(responseOK(tc.pin) == tc.expected);
    }
}

test "Parse token info" {
    const test_cases = [_]struct {
        data: []const u8,
        expected: CardsTokenInfo,
    }{
        .{ .data = &.{}, .expected = CardsTokenInfo{} }, //
        .{ .data = &.{0x10}, .expected = CardsTokenInfo{} },
        .{ .data = &([_]u8{0x10} ** 48), .expected = CardsTokenInfo{} },
        .{
            .data = &([_]u8{0x20} ** 49),
            .expected = CardsTokenInfo{
                .token_label = [_]u8{0x20} ** 32,
                .token_serial_number = [_]u8{0x20} ** 16,
            },
        },
        .{
            .data = &[_]u8{
                0x4E, 0x65, 0x74, 0x53, 0x65, 0x54, 0x27, 0x73, //
                0x20, 0x43, 0x61, 0x72, 0x64, 0x45, 0x64, 0x67,
                0x65, 0x20, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x20,
                0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
                0x49, 0x44, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
                0x37, 0x38, 0x39, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x90, 0x00,
            },
            .expected = CardsTokenInfo{
                .token_label = [_]u8{
                    0x4E, 0x65, 0x74, 0x53, 0x65, 0x54, 0x27, 0x73, //
                    0x20, 0x43, 0x61, 0x72, 0x64, 0x45, 0x64, 0x67,
                    0x65, 0x20, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x20,
                    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
                },
                .token_serial_number = [_]u8{
                    0x49, 0x44, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, //
                    0x37, 0x38, 0x39, 0x20, 0x20, 0x20, 0x20, 0x20,
                },
            },
        },
    };

    for (test_cases) |tc| {
        const parsed_token_info = parseTokenInfo(tc.data);
        try std.testing.expectEqualSlices(u8, &tc.expected.token_label, &parsed_token_info.token_label);
        try std.testing.expectEqualSlices(u8, &tc.expected.token_serial_number, &parsed_token_info.token_serial_number);
    }
}
