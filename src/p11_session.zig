const pkcs = @cImport({
    @cInclude("pkcs.h");
});

const pcsc = @cImport({
    @cInclude("pcsclite.h");
    @cInclude("winscard.h");
    @cInclude("wintypes.h");
});

const pkcs_error = @import("pkcs_error.zig");
const state = @import("state.zig");
const reader = @import("reader.zig");
const session = @import("session.zig");

pub export fn C_OpenSession(
    slot_id: pkcs.CK_SLOT_ID,
    flags: pkcs.CK_FLAGS,
    _: ?*anyopaque,
    _: pkcs.CK_NOTIFY,
    session_handle: ?*pkcs.CK_SESSION_HANDLE,
) pkcs.CK_RV {
    state.lock.lockShared();
    defer state.lock.unlockShared();

    if (!state.initialized)
        return pkcs.CKR_CRYPTOKI_NOT_INITIALIZED;

    if ((flags & pkcs.CKF_SERIAL_SESSION) == 0)
        return pkcs.CKR_SESSION_PARALLEL_NOT_SUPPORTED;

    if (session_handle == null)
        return pkcs.CKR_ARGUMENTS_BAD;

    const write_enabled = (flags & pkcs.CKF_RW_SESSION) != 0;

    session_handle.?.* = session.newSession(state.allocator, slot_id, write_enabled) catch |err|
        return pkcs_error.toRV(err);

    return pkcs.CKR_OK;
}

pub export fn C_CloseSession(session_handle: pkcs.CK_SESSION_HANDLE) pkcs.CK_RV {
    state.lock.lockShared();
    defer state.lock.unlockShared();

    if (!state.initialized)
        return pkcs.CKR_CRYPTOKI_NOT_INITIALIZED;

    session.closeSession(session_handle) catch |err|
        return pkcs_error.toRV(err);

    return pkcs.CKR_OK;
}

pub export fn C_CloseAllSessions(slot_id: pkcs.CK_SLOT_ID) pkcs.CK_RV {
    state.lock.lockShared();
    defer state.lock.unlockShared();

    if (!state.initialized)
        return pkcs.CKR_CRYPTOKI_NOT_INITIALIZED;

    reader.lock.lock();
    defer reader.lock.unlock();

    if (!reader.reader_states.contains(slot_id))
        return pkcs.CKR_SLOT_ID_INVALID;

    return session.closeAllSessions(slot_id);

    // TODO: refresh reader status;
}

pub export fn C_GetSessionInfo(
    session_handle: pkcs.CK_SESSION_HANDLE,
    session_info: ?*pkcs.CK_SESSION_INFO,
) pkcs.CK_RV {
    state.lock.lockShared();
    defer state.lock.unlockShared();

    if (!state.initialized)
        return pkcs.CKR_CRYPTOKI_NOT_INITIALIZED;

    if (session_info == null)
        return pkcs.CKR_ARGUMENTS_BAD;

    const current_session = session.getSession(session_handle, false) catch |err|
        return pkcs_error.toRV(err);

    if (current_session.closed)
        return pkcs.CKR_SESSION_CLOSED;

    session_info.?.slotID = current_session.reader_id;
    session_info.?.flags = pkcs.CKF_SERIAL_SESSION | (if (current_session.write_enabled) pkcs.CKF_RW_SESSION else 0);

    return pkcs.CKR_OK;
}

// not supported in the original module
pub export fn C_GetOperationState(
    session_handle: pkcs.CK_SESSION_HANDLE,
    operationS_state: ?[*]pkcs.CK_BYTE,
    operation_state_len: ?*pkcs.CK_ULONG,
) pkcs.CK_RV {
    _ = session_handle;
    _ = operationS_state;
    _ = operation_state_len;

    return pkcs.CKR_FUNCTION_NOT_SUPPORTED;
}

// not supported in the original module
pub export fn C_SetOperationState(
    session_handle: pkcs.CK_SESSION_HANDLE,
    operation_state: ?[*]const pkcs.CK_BYTE,
    operation_state_len: pkcs.CK_ULONG,
    encryption_key: pkcs.CK_OBJECT_HANDLE,
    authentication_key: pkcs.CK_OBJECT_HANDLE,
) pkcs.CK_RV {
    _ = session_handle;
    _ = operation_state;
    _ = operation_state_len;
    _ = encryption_key;
    _ = authentication_key;

    return pkcs.CKR_FUNCTION_NOT_SUPPORTED;
}

pub export fn C_Login(
    session_handle: pkcs.CK_SESSION_HANDLE,
    user_type: pkcs.CK_USER_TYPE,
    pin: ?[*]const pkcs.CK_UTF8CHAR,
    pin_length: pkcs.CK_ULONG,
) pkcs.CK_RV {
    state.lock.lockShared();
    defer state.lock.unlockShared();

    const current_session = session.getSession(session_handle, false) catch |err|
        return pkcs_error.toRV(err);

    // Difference form the standard.
    if (user_type != pkcs.CKU_USER)
        return pkcs.CKR_USER_TYPE_INVALID;

    if (pin == null)
        return pkcs.CKR_ARGUMENTS_BAD;

    if (current_session.loggedIn())
        return pkcs.CKR_USER_ALREADY_LOGGED_IN;

    const pin_casted: [*]const u8 = @ptrCast(pin);
    current_session.login(pin_casted[0..pin_length]) catch |err|
        return pkcs_error.toRV(err);

    return pkcs.CKR_OK;
}

pub export fn C_Logout(session_handle: pkcs.CK_SESSION_HANDLE) pkcs.CK_RV {
    state.lock.lockShared();
    defer state.lock.unlockShared();

    const current_session = session.getSession(session_handle, false) catch |err|
        return pkcs_error.toRV(err);

    if (!current_session.loggedIn())
        return pkcs.CKR_USER_NOT_LOGGED_IN;

    current_session.logout();

    return pkcs.CKR_OK;
}
