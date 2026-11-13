const std = @import("std");

const PaddedPin = @import("smart-card/PaddedPin.zig");
const pkcs = @import("pkcs.zig");
const reader = @import("smart-card/reader.zig");
const session = @import("session/session.zig");
const State = @import("ModuleState.zig");

pub fn getSlotList(
    state: *State,
    token_present: pkcs.CK_BBOOL,
    slot_list: ?[*]pkcs.CK_SLOT_ID,
    slot_count: ?*pkcs.CK_ULONG,
) error{
    ArgumentsBad,
    BufferTooSmall,
    CryptokiNotInitialized,
    GeneralError,
    HostMemory,
}!void {
    state.lock.lockSharedUncancelable(state.io);
    defer state.lock.unlockShared(state.io);

    if (!state.initialized)
        return error.CryptokiNotInitialized;

    if (slot_count == null)
        return error.ArgumentsBad;

    const only_with_token = token_present == pkcs.CK_TRUE;

    reader.lock.lockUncancelable(state.io);
    defer reader.lock.unlock(state.io);

    if (slot_list == null or !reader.scanned)
        try reader.refreshStatuses(state.allocator, &state.smart_card_client);

    var count: usize = 0;
    var iter = reader.reader_states.iterator();
    while (iter.next()) |entry| {
        if (entry.value_ptr.*.active and (!only_with_token or entry.value_ptr.*.card_present))
            count += 1;
    }

    defer slot_count.?.* = @intCast(count);

    if (slot_list == null)
        return;

    if (slot_count.?.* < count)
        return error.BufferTooSmall;

    var i: usize = 0;
    iter = reader.reader_states.iterator();
    while (iter.next()) |entry| {
        if (entry.value_ptr.*.active and (!only_with_token or entry.value_ptr.*.card_present)) {
            slot_list.?[i] = entry.key_ptr.*;
            i += 1;
        }
    }
}

pub fn getSlotInfo(
    state: *State,
    slot_ID: pkcs.CK_SLOT_ID,
    slot_info: ?*pkcs.CK_SLOT_INFO,
) error{
    ArgumentsBad,
    CryptokiNotInitialized,
    DeviceError,
    GeneralError,
    SlotIdInvalid,
}!void {
    state.lock.lockSharedUncancelable(state.io);
    defer state.lock.unlockShared(state.io);

    if (!state.initialized)
        return error.CryptokiNotInitialized;

    if (slot_info == null)
        return error.ArgumentsBad;

    reader.lock.lockUncancelable(state.io);
    defer reader.lock.unlock(state.io);

    var reader_state = reader.reader_states.getPtr(slot_ID) orelse
        return error.SlotIdInvalid;

    if (!reader_state.active)
        return error.SlotIdInvalid;

    @memcpy(&slot_info.?.slotDescription, &reader_state.writeShortName());
    @memset(&slot_info.?.manufacturerID, ' ');

    try reader_state.refreshCardPresent(state.allocator, &state.smart_card_client);

    slot_info.?.flags = pkcs.CKF_HW_SLOT | pkcs.CKF_REMOVABLE_DEVICE;
    if (reader_state.card_present)
        slot_info.?.flags |= pkcs.CKF_TOKEN_PRESENT;

    slot_info.?.hardwareVersion.major = 0x01;
    slot_info.?.hardwareVersion.minor = 0x00;
    slot_info.?.firmwareVersion.major = 0x01;
    slot_info.?.firmwareVersion.minor = 0x00;
}

pub fn getTokenInfo(
    state: *State,
    slot_id: pkcs.CK_SLOT_ID,
    token_info: ?*pkcs.CK_TOKEN_INFO,
) error{
    ArgumentsBad,
    CryptokiNotInitialized,
    DeviceError,
    GeneralError,
    SlotIdInvalid,
    TokenNoPresent,
    TokenNotRecognized,
}!void {
    state.lock.lockSharedUncancelable(state.io);
    defer state.lock.unlockShared(state.io);

    if (!state.initialized)
        return error.CryptokiNotInitialized;

    if (token_info == null)
        return error.ArgumentsBad;

    reader.lock.lockUncancelable(state.io);
    defer reader.lock.unlock(state.io);

    var reader_state = reader.reader_states.getPtr(slot_id) orelse
        return error.SlotIdInvalid;

    if (!reader_state.active)
        return error.SlotIdInvalid;

    try reader_state.refreshCardPresent(state.allocator, &state.smart_card_client);

    if (!reader_state.card_present)
        return error.TokenNoPresent;

    if (!reader_state.recognized)
        return error.TokenNotRecognized;

    @memcpy(&token_info.?.label, &reader_state.token_label);
    @memcpy(&token_info.?.serialNumber, &reader_state.token_serial_number);

    //TODO: Following two values should not be hardcoded
    @memset(&token_info.?.manufacturerID, 0x20);
    std.mem.copyForwards(u8, &token_info.?.manufacturerID, "NetSeT Global Solutions");

    @memset(&token_info.?.model, 0x20);
    std.mem.copyForwards(u8, &token_info.?.model, "SSCD v1");

    token_info.?.ulMinPinLen = 4;
    token_info.?.ulMaxPinLen = 8;
    token_info.?.flags = pkcs.CKF_TOKEN_INITIALIZED | pkcs.CKF_USER_PIN_INITIALIZED | pkcs.CKF_LOGIN_REQUIRED | pkcs.CKF_RNG;
    token_info.?.ulMaxSessionCount = pkcs.CK_EFFECTIVELY_INFINITE;
    token_info.?.ulMaxRwSessionCount = pkcs.CK_EFFECTIVELY_INFINITE;

    var session_count: usize = 0;
    var rw_session_count: usize = 0;
    try session.countSessions(state.io, slot_id, &session_count, &rw_session_count);
    token_info.?.ulSessionCount = @intCast(session_count);
    token_info.?.ulRwSessionCount = @intCast(rw_session_count);

    token_info.?.hardwareVersion.major = 1;
    token_info.?.hardwareVersion.minor = 0;
    token_info.?.firmwareVersion.major = 1;
    token_info.?.firmwareVersion.minor = 0;

    token_info.?.ulTotalPublicMemory = pkcs.CK_UNAVAILABLE_INFORMATION;
    token_info.?.ulFreePublicMemory = pkcs.CK_UNAVAILABLE_INFORMATION;
    token_info.?.ulTotalPrivateMemory = pkcs.CK_UNAVAILABLE_INFORMATION;
    token_info.?.ulFreePrivateMemory = pkcs.CK_UNAVAILABLE_INFORMATION;
}

pub fn getMechanismList(
    state: *State,
    slot_id: pkcs.CK_SLOT_ID,
    mechanism_list: ?[*]pkcs.CK_MECHANISM_TYPE,
    count: ?*pkcs.CK_ULONG,
) error{
    ArgumentsBad,
    BufferTooSmall,
    CryptokiNotInitialized,
    DeviceError,
    GeneralError,
    SlotIdInvalid,
    TokenNoPresent,
    TokenNotRecognized,
}!void {
    state.lock.lockSharedUncancelable(state.io);
    defer state.lock.unlockShared(state.io);

    if (count == null)
        return error.ArgumentsBad;

    const mechanisms = [_]pkcs.CK_MECHANISM_TYPE{
        // pkcs.CKM_RSA_PKCS_KEY_PAIR_GEN,
        pkcs.CKM_RSA_PKCS,
        pkcs.CKM_RSA_X_509,
        pkcs.CKM_MD5_RSA_PKCS,
        pkcs.CKM_SHA1_RSA_PKCS,
        pkcs.CKM_RIPEMD160_RSA_PKCS,
        pkcs.CKM_SHA256_RSA_PKCS,
        pkcs.CKM_SHA384_RSA_PKCS,
        pkcs.CKM_SHA512_RSA_PKCS,
        pkcs.CKM_MD5,
        pkcs.CKM_SHA_1,
        pkcs.CKM_RIPEMD160,
        pkcs.CKM_SHA256,
        pkcs.CKM_SHA384,
        pkcs.CKM_SHA512,
    };

    if (!state.initialized)
        return error.CryptokiNotInitialized;

    reader.lock.lockSharedUncancelable(state.io);
    defer reader.lock.unlockShared(state.io);

    const reader_state = reader.reader_states.getPtr(slot_id) orelse
        return error.SlotIdInvalid;

    if (!reader_state.active)
        return error.SlotIdInvalid;

    if (!reader_state.card_present)
        return error.TokenNoPresent;

    if (!reader_state.recognized)
        return error.TokenNotRecognized;

    if (mechanism_list != null) {
        if (count.?.* < mechanisms.len)
            return error.BufferTooSmall;

        for (mechanisms, 0..) |m, i| {
            mechanism_list.?[i] = m;
        }
    }

    count.?.* = mechanisms.len;
}

pub fn getMechanismInfo(
    state: *State,
    slot_id: pkcs.CK_SLOT_ID,
    mechanism_type: pkcs.CK_MECHANISM_TYPE,
    mechanism_info: ?*pkcs.CK_MECHANISM_INFO,
) error{
    ArgumentsBad,
    CryptokiNotInitialized,
    DeviceError,
    GeneralError,
    MechanismInvalid,
    SlotIdInvalid,
    TokenNoPresent,
    TokenNotRecognized,
}!void {
    state.lock.lockSharedUncancelable(state.io);
    defer state.lock.unlockShared(state.io);

    if (!state.initialized)
        return error.CryptokiNotInitialized;

    reader.lock.lockSharedUncancelable(state.io);
    defer reader.lock.unlockShared(state.io);

    const reader_state = reader.reader_states.get(slot_id) orelse
        return error.SlotIdInvalid;

    if (!reader_state.active)
        return error.SlotIdInvalid;

    if (!reader_state.card_present)
        return error.TokenNoPresent;

    if (!reader_state.recognized)
        return error.TokenNotRecognized;

    if (mechanism_info == null)
        return error.ArgumentsBad;

    switch (mechanism_type) {
        pkcs.CKM_RSA_PKCS_KEY_PAIR_GEN => {
            mechanism_info.?.ulMinKeySize = 1024;
            mechanism_info.?.ulMaxKeySize = 2048;
            mechanism_info.?.flags = pkcs.CKF_HW | pkcs.CKF_GENERATE_KEY_PAIR;
        },
        pkcs.CKM_RSA_PKCS,
        pkcs.CKM_RSA_X_509,
        pkcs.CKM_MD5_RSA_PKCS,
        pkcs.CKM_SHA1_RSA_PKCS,
        pkcs.CKM_RIPEMD160_RSA_PKCS,
        pkcs.CKM_SHA256_RSA_PKCS,
        pkcs.CKM_SHA384_RSA_PKCS,
        pkcs.CKM_SHA512_RSA_PKCS,
        => {
            mechanism_info.?.ulMinKeySize = 1024;
            mechanism_info.?.ulMaxKeySize = 2048;
            mechanism_info.?.flags = pkcs.CKF_HW | pkcs.CKF_SIGN | pkcs.CKF_VERIFY;
        },
        pkcs.CKM_MD5,
        pkcs.CKM_SHA_1,
        pkcs.CKM_RIPEMD160,
        pkcs.CKM_SHA256,
        pkcs.CKM_SHA384,
        pkcs.CKM_SHA512,
        => {
            mechanism_info.?.ulMinKeySize = 0;
            mechanism_info.?.ulMaxKeySize = 0;
            mechanism_info.?.flags = pkcs.CKF_DIGEST;
        },
        else => return error.MechanismInvalid,
    }
}

pub fn initToken(
    _: *State,
    _: pkcs.CK_SLOT_ID,
    _: ?*pkcs.CK_UTF8CHAR,
    _: pkcs.CK_ULONG,
    _: ?*pkcs.CK_UTF8CHAR,
) error{
    FunctionNotSupported,
}!void {
    return error.FunctionNotSupported;
}

pub fn initPIN(
    _: *State,
    _: pkcs.CK_SESSION_HANDLE,
    _: ?[*]pkcs.CK_UTF8CHAR,
    _: pkcs.CK_ULONG,
) error{
    FunctionNotSupported,
}!void {
    return error.FunctionNotSupported;
}

pub fn setPIN(
    state: *State,
    session_handle: pkcs.CK_SESSION_HANDLE,
    old_pin: ?[*]pkcs.CK_UTF8CHAR,
    old_pin_len: pkcs.CK_ULONG,
    new_pin: ?[*]pkcs.CK_UTF8CHAR,
    new_pin_len: pkcs.CK_ULONG,
) error{
    ArgumentsBad,
    CryptokiNotInitialized,
    DeviceError,
    DeviceRemoved,
    FunctionFailed,
    GeneralError,
    HostMemory,
    PinInvalid,
    PinIncorrect,
    PinLenRange,
    PinLocked,
    SessionHandleInvalid,
    SessionReadOnly,
    TokenNoPresent,
    TokenNotRecognized,
}!void {
    state.lock.lockSharedUncancelable(state.io);
    defer state.lock.unlockShared(state.io);

    const current_session = try session.getSession(state.io, session_handle, false);

    if (!current_session.write_enabled)
        return error.SessionReadOnly;

    if (old_pin == null or new_pin == null)
        return error.ArgumentsBad;

    const padded_old_pin = try PaddedPin.construct(old_pin.?[0..old_pin_len]);

    const padded_new_pin = try PaddedPin.construct(new_pin.?[0..new_pin_len]);

    try current_session.setPin(state.allocator, state.io, &padded_old_pin, &padded_new_pin);
}

pub fn waitForSlotEvent(
    _: *State,
    _: pkcs.CK_FLAGS,
    _: ?*pkcs.CK_SLOT_ID,
    _: ?*anyopaque,
) error{
    FunctionNotSupported,
}!void {
    return error.FunctionNotSupported;
}
