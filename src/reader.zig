const std = @import("std");
const pcsc = @import("pcsc");

const atr = @import("atr.zig");
const pkcs = @import("pkcs.zig");
const state = @import("state.zig");
const smart_card = @import("smart-card.zig");
const pkcs_error = @import("pkcs_error.zig");

const PkcsError = pkcs_error.PkcsError;

var next_reader_id: pkcs.CK_SLOT_ID = 1;

pub var reader_states: std.AutoHashMap(pkcs.CK_SLOT_ID, ReaderState) = undefined;

var reader_names_buf: [pcsc.max_readers * pcsc.max_reader_name_len]u8 = undefined;

pub var lock = std.Thread.RwLock{};

pub const UserType = enum {
    None,
    User,
    SecurityOfficer,
};

pub const ReaderState = struct {
    name: [:0]const u8,
    active: bool,
    card_present: bool,
    recognized: bool,
    token_label: [32]u8 = undefined,
    token_serial_number: [16]u8 = undefined,
    user_type: UserType,

    pub fn refreshCardPresent(
        self: *ReaderState,
        allocator: std.mem.Allocator,
        smart_card_client: *pcsc.Client,
    ) PkcsError!void {
        @memset(&self.*.token_label, 0x20);
        @memset(&self.*.token_serial_number, 0x20);

        const card = smart_card_client.connect(self.name.ptr, .SHARED, .ANY) catch |err| {
            switch (err) {
                pcsc.Err.NoSmartCard => {
                    self.card_present = false;
                    return;
                },
                pcsc.Err.UnpoweredCard, pcsc.Err.UnresponsiveCard, pcsc.Err.ReaderUnavailable => return PkcsError.DeviceError,
                else => return PkcsError.GeneralError,
            }
        };

        defer card.disconnect(.LEAVE) catch {};

        self.card_present = true;

        const card_state = card.state() catch
            return PkcsError.GeneralError;

        self.recognized = atr.validATR(card_state.atr.buf[0..card_state.atr.len]);

        if (!self.recognized)
            return;

        var idCard = smart_card.Card{ .smart_card = card };
        const token_info = idCard.readTokenInfo(allocator) catch {
            self.recognized = false;
            return;
        };

        self.*.token_label = token_info.token_label;
        self.*.token_serial_number = token_info.token_serial_number;
    }

    pub fn writeShortName(self: *const ReaderState) [64]u8 {
        var buffer: [64]u8 = [_]u8{' '} ** 64;

        var open_index = std.mem.findScalar(u8, self.name, '[');
        var close_index = std.mem.findScalar(u8, self.name, ']');

        if (open_index == null or close_index == null or open_index.? > close_index.?) {
            const len = @min(self.name.len, buffer.len - 1);
            @memcpy(buffer[0..len], self.name[0..len]);
            return buffer;
        }

        while (open_index.? > 0) {
            if (self.name[open_index.? - 1] == ' ')
                open_index.? -= 1
            else
                break;
        }

        @memcpy(buffer[0..open_index.?], self.name[0..open_index.?]);

        while (close_index.? < self.name.len - 1) {
            if (self.name[close_index.?] == ' ')
                close_index.? += 1
            else if (self.name[close_index.?] == ']')
                close_index.? += 1
            else
                break;
        }

        if (open_index.? > 0)
            open_index.? += 1;

        const len = @min(self.name.len - close_index.?, buffer.len - 1 - open_index.?);

        @memcpy(buffer[open_index.? .. open_index.? + len], self.name[close_index.? .. close_index.? + len]);

        return buffer;
    }
};

pub fn refreshStatuses(allocator: std.mem.Allocator, smart_card_client: *pcsc.Client) PkcsError!void {
    var readers_name_iterator = smart_card_client.readerNamesBuf(&reader_names_buf) catch |err|
        return pkcs_error.formPCSC(err);

    resetStates();

    while (readers_name_iterator.next()) |reader_name| {
        addIfNotExists(allocator, reader_name) catch
            return PkcsError.GeneralError;
    }

    var reader_iterator = reader_states.iterator();
    while (reader_iterator.next()) |reader_state_entry| {
        if (!reader_state_entry.value_ptr.active)
            continue;

        try reader_state_entry.value_ptr.*.refreshCardPresent(allocator, smart_card_client);
    }
}

fn addIfNotExists(allocator: std.mem.Allocator, reader_name: [*:0]const u8) std.mem.Allocator.Error!void {
    const reader_name_slice = std.mem.sliceTo(reader_name, 0);

    var iter = reader_states.iterator();
    while (iter.next()) |entry| {
        if (std.mem.eql(u8, entry.value_ptr.name, reader_name_slice)) {
            entry.value_ptr.*.active = true;
            return;
        }
    }

    const allocated_name = try allocator.allocSentinel(u8, reader_name_slice.len, 0);

    @memcpy(allocated_name, reader_name_slice);
    try reader_states.put(
        next_reader_id,
        ReaderState{
            .name = allocated_name,
            .active = true,
            .card_present = false,
            .recognized = false,
            .user_type = UserType.None,
        },
    );

    next_reader_id += 1;
}

fn resetStates() void {
    var it = reader_states.iterator();
    while (it.next()) |entry| {
        entry.value_ptr.*.active = false;
        entry.value_ptr.*.card_present = false;
    }
}

fn parseMultiString(allocator: std.mem.Allocator, input: [*:0]const u8) std.mem.Allocator.Error![][:0]const u8 {
    var list = std.ArrayList([:0]const u8){};
    errdefer list.deinit(allocator);

    var i: usize = 0;
    while (true) {
        const start = input + i;
        const len = std.mem.len(start);

        if (len == 0)
            break;

        const slice = input[i .. i + len :0];
        try list.append(allocator, slice);

        i += len + 1;
    }

    return try list.toOwnedSlice(allocator);
}

pub fn setUserType(slot_id: pkcs.CK_SLOT_ID, user_type: UserType) void {
    lock.lock();
    defer lock.unlock();

    const reader_entry = reader_states.getPtr(slot_id) orelse
        return;

    reader_entry.user_type = user_type;
}

pub fn getUserType(slot_id: pkcs.CK_SLOT_ID) UserType {
    lock.lockShared();
    defer lock.unlockShared();

    const reader_entry = reader_states.get(slot_id) orelse
        return UserType.None;

    return reader_entry.user_type;
}

pub fn deinit(allocator: std.mem.Allocator) void {
    var it = reader_states.valueIterator();
    while (it.next()) |reader_state| {
        allocator.free(reader_state.name);
    }

    next_reader_id = 1;

    reader_states.deinit();
}

test "init and deinit readers" {
    reader_states = std.AutoHashMap(pkcs.CK_SLOT_ID, ReaderState).init(std.testing.allocator);

    try addIfNotExists(std.testing.allocator, "reader1");
    try addIfNotExists(std.testing.allocator, "reader2");

    deinit(std.testing.allocator);

    try std.testing.expectEqual(1, next_reader_id);
}

test "add if not exists" {
    reader_states = std.AutoHashMap(pkcs.CK_SLOT_ID, ReaderState).init(std.testing.allocator);

    try addIfNotExists(std.testing.allocator, "reader1");
    try addIfNotExists(std.testing.allocator, "reader2");
    try addIfNotExists(std.testing.allocator, "reader2");
    try addIfNotExists(std.testing.allocator, "reader3");
    try addIfNotExists(std.testing.allocator, "reader2");

    try std.testing.expectEqual(3, reader_states.count());

    deinit(std.testing.allocator);
}

test "set and get user types" {
    reader_states = std.AutoHashMap(pkcs.CK_SLOT_ID, ReaderState).init(std.testing.allocator);

    try addIfNotExists(std.testing.allocator, "reader1");
    try addIfNotExists(std.testing.allocator, "reader2");

    setUserType(1, UserType.SecurityOfficer);
    setUserType(2, UserType.User);

    try std.testing.expectEqual(UserType.SecurityOfficer, getUserType(1));
    try std.testing.expectEqual(UserType.User, getUserType(2));

    setUserType(1, UserType.None);
    setUserType(2, UserType.None);

    try std.testing.expectEqual(UserType.None, getUserType(1));
    try std.testing.expectEqual(UserType.None, getUserType(2));

    deinit(std.testing.allocator);
}

test "reader short name" {
    const test_cases = [_]struct {
        name: [:0]const u8,
        expected: []const u8,
    }{
        .{ .name = "", .expected = "" },
        .{ .name = "reader0", .expected = "reader0" },
        .{ .name = "reader1 ABC", .expected = "reader1 ABC" },
        .{ .name = "reader2 ABC [XYZ]", .expected = "reader2 ABC" },
        .{ .name = "[XYZ] reader3", .expected = "reader3" },
        .{ .name = "reader4 ABC - 123 [XYZ] model", .expected = "reader4 ABC - 123 model" },
        .{ .name = "123456789012345678901234567890[23456789]ABCDEFGHIJABCDEFGHIJ321", .expected = "123456789012345678901234567890 ABCDEFGHIJABCDEFGHIJ321" },
        .{ .name = "123456789012345678901234567890[23456789]ABCDEFGHIJABCDEFGHIJABCDEFGHIJ1234567890", .expected = "123456789012345678901234567890 ABCDEFGHIJABCDEFGHIJABCDEFGHIJ12 " },
    };

    for (test_cases) |tc| {
        const reader_state = ReaderState{
            .active = true,
            .card_present = true,
            .recognized = true,
            .user_type = .User,
            .name = tc.name,
        };

        const output = reader_state.writeShortName();
        const min = @min(tc.expected.len, output.len);
        try std.testing.expectEqualSlices(u8, tc.expected[0..min], output[0..min]);
    }
}

test "reader short name should not be null terminated" {
    const test_cases = [_]struct {
        name: [:0]const u8,
    }{
        .{ .name = "" },
        .{ .name = "reader" },
        .{ .name = "reader ABC - 123 [XYZ] model" },
    };

    for (test_cases) |tc| {
        const reader_state = ReaderState{
            .active = true,
            .card_present = true,
            .recognized = true,
            .user_type = .User,
            .name = tc.name,
        };

        const output = reader_state.writeShortName();
        try std.testing.expect(!std.mem.containsAtLeastScalar2(u8, &output, 0x00, 1));
    }
}
