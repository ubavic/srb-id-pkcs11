const std = @import("std");
const pcsc = @import("pcsc");

const atr = @import("atr.zig");
const pkcs = @import("pkcs.zig").pkcs;
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

    pub fn writeShortName(self: *const ReaderState, output: []u8) void {
        const open_index = std.mem.indexOfScalar(u8, self.name, '[');
        const close_index = std.mem.indexOfScalar(u8, self.name, ']');

        if (open_index == null or close_index == null or close_index.? <= open_index.?) {
            const len = @min(self.name.len, output.len);
            @memcpy(output[0..len], self.name[0..len]);
            if (len < output.len) output[len] = 0;
            return;
        }

        const before = self.name[0..open_index.?];
        const after = self.name[(close_index.? + 1)..];

        const trimmed_before = std.mem.trimRight(u8, before, " ");
        const trimmed_after = std.mem.trimLeft(u8, after, " ");

        var idx: usize = 0;

        if (idx + trimmed_before.len <= output.len) {
            @memcpy(output[idx..][0..trimmed_before.len], trimmed_before);
            idx += trimmed_before.len;
        }

        if (trimmed_after.len > 0 and idx < output.len) {
            output[idx] = ' ';
            idx += 1;
        }

        if (idx + trimmed_after.len <= output.len) {
            @memcpy(output[idx..][0..trimmed_after.len], trimmed_after);
            idx += trimmed_after.len;
        }

        if (idx < output.len)
            output[idx] = 0;
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

    std.mem.copyForwards(u8, allocated_name, reader_name_slice);
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

    const reader_entry = reader_states.getPtr(slot_id);
    if (reader_entry == null)
        return;

    reader_entry.?.*.user_type = user_type;
}

pub fn getUserType(slot_id: pkcs.CK_SLOT_ID) UserType {
    lock.lockShared();
    defer lock.unlockShared();

    const reader_entry = reader_states.get(slot_id);
    if (reader_entry == null)
        return UserType.None;

    return reader_entry.?.user_type;
}
