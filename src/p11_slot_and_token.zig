const std = @import("std");

const session = @import("session.zig");
const state = @import("state.zig");
const reader = @import("reader.zig");
const pkcs = @import("pkcs.zig").pkcs;
const pkcs_error = @import("pkcs_error.zig");

pub export fn C_GetSlotList(
    token_present: pkcs.CK_BBOOL,
    slot_list: ?[*]pkcs.CK_SLOT_ID,
    slot_count: ?*pkcs.CK_ULONG,
) pkcs.CK_RV {
    state.lock.lockShared();
    defer state.lock.unlockShared();

    if (!state.initialized)
        return pkcs.CKR_CRYPTOKI_NOT_INITIALIZED;

    if (slot_count == null)
        return pkcs.CKR_ARGUMENTS_BAD;

    if (slot_list == null) {
        reader.refreshStatuses(state.allocator, &state.smart_card_client) catch |err|
            return pkcs_error.toRV(err);
    }

    const only_with_token = token_present == pkcs.CK_TRUE;

    var count: u32 = 0;
    var iter = reader.reader_states.iterator();
    while (iter.next()) |entry| {
        if (entry.value_ptr.*.active and (!only_with_token or entry.value_ptr.*.card_present))
            count += 1;
    }

    if (slot_list != null) {
        if (slot_count.?.* < count)
            return pkcs.CKR_BUFFER_TOO_SMALL;

        var i: usize = 0;
        iter = reader.reader_states.iterator();
        while (iter.next()) |entry| {
            if (entry.value_ptr.*.active and (!only_with_token or entry.value_ptr.*.card_present)) {
                slot_list.?[i] = entry.key_ptr.*;
                i += 1;
            }
        }
    }

    slot_count.?.* = count;
    return pkcs.CKR_OK;
}

pub export fn C_GetSlotInfo(
    slot_ID: pkcs.CK_SLOT_ID,
    slot_info: ?*pkcs.CK_SLOT_INFO,
) pkcs.CK_RV {
    state.lock.lockShared();
    defer state.lock.unlockShared();

    if (!state.initialized)
        return pkcs.CKR_CRYPTOKI_NOT_INITIALIZED;

    if (slot_info == null)
        return pkcs.CKR_ARGUMENTS_BAD;

    reader.lock.lock();
    defer reader.lock.unlock();

    const reader_entry = reader.reader_states.getPtr(slot_ID);
    if (reader_entry == null)
        return pkcs.CKR_SLOT_ID_INVALID;

    var reader_state = reader_entry.?;

    reader_state.writeShortName(&slot_info.?.slotDescription);
    @memset(&slot_info.?.manufacturerID, ' ');

    reader_state.refreshCardPresent(&state.smart_card_client) catch |err|
        return pkcs_error.toRV(err);

    slot_info.?.flags = pkcs.CKF_HW_SLOT | pkcs.CKF_REMOVABLE_DEVICE;
    if (reader_state.card_present)
        slot_info.?.flags = slot_info.?.flags | pkcs.CKF_TOKEN_PRESENT;

    slot_info.?.hardwareVersion.major = 0x01;
    slot_info.?.hardwareVersion.minor = 0x00;
    slot_info.?.firmwareVersion.major = 0x01;
    slot_info.?.firmwareVersion.minor = 0x00;

    return pkcs.CKR_OK;
}

pub export fn C_GetTokenInfo(
    slot_id: pkcs.CK_SLOT_ID,
    token_info: ?*pkcs.CK_TOKEN_INFO,
) pkcs.CK_RV {
    state.lock.lockShared();
    defer state.lock.unlockShared();

    if (!state.initialized)
        return pkcs.CKR_CRYPTOKI_NOT_INITIALIZED;

    if (token_info == null)
        return pkcs.CKR_ARGUMENTS_BAD;

    reader.lock.lock();
    defer reader.lock.unlock();

    const reader_entry = reader.reader_states.getPtr(slot_id);
    if (reader_entry == null)
        return pkcs.CKR_SLOT_ID_INVALID;

    var reader_state = reader_entry.?;

    reader_state.refreshCardPresent(&state.smart_card_client) catch |err|
        return pkcs_error.toRV(err);

    @memset(&token_info.?.label, 0);
    std.mem.copyForwards(u8, &token_info.?.label, "NetSeT's CardEdge Token");

    @memset(&token_info.?.manufacturerID, 0);
    std.mem.copyForwards(u8, &token_info.?.manufacturerID, "NetSeT Global Solutions");

    @memset(&token_info.?.model, 0);
    std.mem.copyForwards(u8, &token_info.?.model, "SSCD v1");

    @memset(&token_info.?.serialNumber, 0); // TODO

    token_info.?.ulMinPinLen = 4;
    token_info.?.ulMaxPinLen = 8;
    token_info.?.flags = pkcs.CKF_TOKEN_INITIALIZED | pkcs.CKF_USER_PIN_INITIALIZED | pkcs.CKF_LOGIN_REQUIRED | pkcs.CKF_RNG;
    token_info.?.ulMaxSessionCount = pkcs.CK_EFFECTIVELY_INFINITE;
    token_info.?.ulMaxSessionCount = pkcs.CK_EFFECTIVELY_INFINITE;
    session.countSessions(slot_id, &token_info.?.ulSessionCount, &token_info.?.ulRwSessionCount);
    token_info.?.hardwareVersion.major = 1;
    token_info.?.hardwareVersion.minor = 0;
    token_info.?.firmwareVersion.major = 1;
    token_info.?.firmwareVersion.minor = 0;

    token_info.?.ulTotalPublicMemory = pkcs.CK_UNAVAILABLE_INFORMATION;
    token_info.?.ulFreePublicMemory = pkcs.CK_UNAVAILABLE_INFORMATION;
    token_info.?.ulTotalPrivateMemory = pkcs.CK_UNAVAILABLE_INFORMATION;
    token_info.?.ulFreePrivateMemory = pkcs.CK_UNAVAILABLE_INFORMATION;

    return pkcs.CKR_OK;
}

pub export fn C_GetMechanismList(
    slot_id: pkcs.CK_SLOT_ID,
    mechanism_list: ?[*]pkcs.CK_MECHANISM_TYPE,
    count: ?*pkcs.CK_ULONG,
) pkcs.CK_RV {
    state.lock.lockShared();
    defer state.lock.unlockShared();

    const mechanisms = [_]pkcs.CK_MECHANISM_TYPE{
        // pkcs.CKM_RSA_PKCS_KEY_PAIR_GEN,
        pkcs.CKM_RSA_PKCS,
        // pkcs.CKM_RSA_X_509,
        pkcs.CKM_MD5_RSA_PKCS,
        pkcs.CKM_SHA1_RSA_PKCS,
        // pkcs.CKM_RIPEMD160_RSA_PKCS,
        pkcs.CKM_SHA256_RSA_PKCS,
        pkcs.CKM_SHA384_RSA_PKCS,
        pkcs.CKM_SHA512_RSA_PKCS,
        pkcs.CKM_MD5,
        pkcs.CKM_SHA_1,
        // pkcs.CKM_RIPEMD160,
        pkcs.CKM_SHA256,
        pkcs.CKM_SHA384,
        pkcs.CKM_SHA512,
    };

    if (!state.initialized)
        return pkcs.CKR_CRYPTOKI_NOT_INITIALIZED;

    reader.lock.lockShared();
    defer reader.lock.unlockShared();

    const reader_entry = reader.reader_states.getPtr(slot_id);
    if (reader_entry == null)
        return pkcs.CKR_SLOT_ID_INVALID;

    const reader_state = reader_entry.?;

    if (!reader_state.card_present)
        return pkcs.CKR_DEVICE_REMOVED;

    if (!reader_state.recognized)
        return pkcs.CKR_TOKEN_NOT_RECOGNIZED;

    if (mechanism_list != null) {
        if (count.?.* < mechanisms.len)
            return pkcs.CKR_BUFFER_TOO_SMALL;

        for (mechanisms, 0..) |m, i| {
            mechanism_list.?[i] = m;
        }
    }

    count.?.* = mechanisms.len;
    return pkcs.CKR_OK;
}

pub export fn C_GetMechanismInfo(
    slot_id: pkcs.CK_SLOT_ID,
    mechanism_type: pkcs.CK_MECHANISM_TYPE,
    mechanism_info: ?*pkcs.CK_MECHANISM_INFO,
) pkcs.CK_RV {
    state.lock.lockShared();
    defer state.lock.unlockShared();

    if (!state.initialized)
        return pkcs.CKR_CRYPTOKI_NOT_INITIALIZED;

    reader.lock.lockShared();
    defer reader.lock.unlockShared();

    const reader_entry = reader.reader_states.get(slot_id);
    if (reader_entry == null)
        return pkcs.CKR_SLOT_ID_INVALID;

    const reader_state = reader_entry.?;

    if (!reader_state.card_present)
        return pkcs.CKR_DEVICE_REMOVED;

    if (!reader_state.recognized)
        return pkcs.CKR_TOKEN_NOT_RECOGNIZED;

    if (mechanism_info == null)
        return pkcs.CKR_ARGUMENTS_BAD;

    switch (mechanism_type) {
        pkcs.CKM_RSA_PKCS_KEY_PAIR_GEN => {
            mechanism_info.?.ulMinKeySize = 1024;
            mechanism_info.?.ulMaxKeySize = 2048;
            mechanism_info.?.flags = pkcs.CKF_HW | pkcs.CKF_GENERATE_KEY_PAIR;
        },
        pkcs.CKM_RSA_PKCS,
        //pkcs.CKM_RSA_X_509,
        pkcs.CKM_MD5_RSA_PKCS,
        pkcs.CKM_SHA1_RSA_PKCS,
        //pkcs.CKM_RIPEMD160_RSA_PKCS,
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
        //pkcs.CKM_RIPEMD160,
        pkcs.CKM_SHA256,
        pkcs.CKM_SHA384,
        pkcs.CKM_SHA512,
        => {
            mechanism_info.?.ulMinKeySize = 0;
            mechanism_info.?.ulMaxKeySize = 0;
            mechanism_info.?.flags = pkcs.CKF_DIGEST;
        },
        else => return pkcs.CKR_MECHANISM_INVALID,
    }

    return pkcs.CKR_OK;
}

pub export fn C_InitToken(
    _: pkcs.CK_SLOT_ID,
    _: ?*pkcs.CK_UTF8CHAR,
    _: pkcs.CK_ULONG,
    _: ?*pkcs.CK_UTF8CHAR,
) pkcs.CK_RV {
    return pkcs.CKR_FUNCTION_NOT_SUPPORTED;
}

pub export fn C_InitPIN(
    _: pkcs.CK_SESSION_HANDLE,
    _: pkcs.CK_UTF8CHAR_PTR,
    _: pkcs.CK_ULONG,
) pkcs.CK_RV {
    return pkcs.CKR_FUNCTION_NOT_SUPPORTED;
}

pub export fn C_SetPIN(
    session_handle: pkcs.CK_SESSION_HANDLE,
    old_pin: pkcs.CK_UTF8CHAR_PTR,
    old_pin_len: pkcs.CK_ULONG,
    new_pin: pkcs.CK_UTF8CHAR_PTR,
    new_pin_len: pkcs.CK_ULONG,
) pkcs.CK_RV {
    state.lock.lockShared();
    defer state.lock.unlockShared();

    const current_session = session.getSession(session_handle, false) catch |err|
        return pkcs_error.toRV(err);

    if (!current_session.write_enabled)
        return pkcs.CKR_SESSION_READ_ONLY;

    if (old_pin == null or new_pin == null)
        return pkcs.CKR_ARGUMENTS_BAD;

    current_session.card.setPin(state.allocator, old_pin[0..old_pin_len], new_pin[0..new_pin_len]) catch |err|
        return pkcs_error.toRV(err);
    return pkcs.CKR_OK;
}

pub export fn C_WaitForSlotEvent(
    flags: pkcs.CK_FLAGS,
    slot: ?*pkcs.CK_SLOT_ID,
    reserved: ?*anyopaque,
) pkcs.CK_RV {
    _ = flags;
    _ = slot;
    _ = reserved;
    return pkcs.CKR_FUNCTION_NOT_SUPPORTED;
}
