const PaddedPin = @import("smart-card/PaddedPin.zig");
const pkcs = @import("pkcs.zig");
const reader = @import("smart-card/reader.zig");
const session = @import("session/session.zig");
const State = @import("ModuleState.zig");

pub fn openSession(
    state: *State,
    slot_id: pkcs.CK_SLOT_ID,
    flags: pkcs.CK_FLAGS,
    _: ?*anyopaque,
    _: pkcs.CK_NOTIFY,
    session_handle: ?*pkcs.CK_SESSION_HANDLE,
) error{
    ArgumentsBad,
    CryptokiNotInitialized,
    DeviceError,
    DeviceRemoved,
    FunctionFailed,
    GeneralError,
    HostMemory,
    SlotIdInvalid,
    SessionParallelNotSupported,
    TokenNoPresent,
    TokenNotRecognized,
}!void {
    state.lock.lockSharedUncancelable(state.io);
    defer state.lock.unlockShared(state.io);

    if (!state.initialized)
        return error.CryptokiNotInitialized;

    if ((flags & pkcs.CKF_SERIAL_SESSION) == 0)
        return error.SessionParallelNotSupported;

    if (session_handle == null)
        return error.ArgumentsBad;

    const write_enabled = (flags & pkcs.CKF_RW_SESSION) != 0;
    session_handle.?.* = try session.newSession(state.allocator, state.io, &state.smart_card_client, slot_id, write_enabled);
}

pub fn closeSession(
    state: *State,
    session_handle: pkcs.CK_SESSION_HANDLE,
) error{
    CryptokiNotInitialized,
    FunctionFailed,
    GeneralError,
    SessionClosed,
    SessionHandleInvalid,
}!void {
    state.lock.lockSharedUncancelable(state.io);
    defer state.lock.unlockShared(state.io);

    if (!state.initialized)
        return error.CryptokiNotInitialized;

    try session.closeSession(state.allocator, state.io, session_handle);
}

pub fn closeAllSessions(
    state: *State,
    slot_id: pkcs.CK_SLOT_ID,
) error{
    CryptokiNotInitialized,
    FunctionFailed,
    GeneralError,
    HostMemory,
    SlotIdInvalid,
}!void {
    state.lock.lockSharedUncancelable(state.io);
    defer state.lock.unlockShared(state.io);

    if (!state.initialized)
        return error.CryptokiNotInitialized;

    reader.lock.lockUncancelable(state.io);
    defer reader.lock.unlock(state.io);

    if (!reader.reader_states.contains(slot_id))
        return error.SlotIdInvalid;

    try session.closeAllSessions(state.allocator, state.io, slot_id);

    // TODO: refresh reader status;
}

pub fn getSessionInfo(
    state: *State,
    session_handle: pkcs.CK_SESSION_HANDLE,
    session_info: ?*pkcs.CK_SESSION_INFO,
) error{
    ArgumentsBad,
    CryptokiNotInitialized,
    FunctionFailed,
    GeneralError,
    HostMemory,
    SessionClosed,
    SessionHandleInvalid,
}!void {
    state.lock.lockSharedUncancelable(state.io);
    defer state.lock.unlockShared(state.io);

    if (!state.initialized)
        return error.CryptokiNotInitialized;

    if (session_info == null)
        return error.ArgumentsBad;

    const current_session = try session.getSession(state.io, session_handle, false);

    if (current_session.closed)
        return error.SessionClosed;

    session_info.?.slotID = current_session.reader_id;
    session_info.?.flags = pkcs.CKF_SERIAL_SESSION | (if (current_session.write_enabled) pkcs.CKF_RW_SESSION else 0);

    const user_type = reader.getUserType(state.io, current_session.reader_id);
    session_info.?.state = switch (user_type) {
        reader.UserType.None => if (current_session.write_enabled) pkcs.CKS_RW_PUBLIC_SESSION else pkcs.CKS_RO_PUBLIC_SESSION,
        reader.UserType.User => if (current_session.write_enabled) pkcs.CKS_RW_USER_FUNCTIONS else pkcs.CKS_RO_USER_FUNCTIONS,
        reader.UserType.SecurityOfficer => pkcs.CKS_RW_SO_FUNCTIONS,
    };

    session_info.?.ulDeviceError = 0;
}

// not supported in the original module
pub fn getOperationState(
    _: *State,
    _: pkcs.CK_SESSION_HANDLE,
    _: ?[*]pkcs.CK_BYTE,
    _: ?*pkcs.CK_ULONG,
) error{
    FunctionNotSupported,
}!void {
    return error.FunctionNotSupported;
}

// not supported in the original module
pub fn setOperationState(
    _: *State,
    _: pkcs.CK_SESSION_HANDLE,
    _: ?[*]const pkcs.CK_BYTE,
    _: pkcs.CK_ULONG,
    _: pkcs.CK_OBJECT_HANDLE,
    _: pkcs.CK_OBJECT_HANDLE,
) error{
    FunctionNotSupported,
}!void {
    return error.FunctionNotSupported;
}

pub fn login(
    state: *State,
    session_handle: pkcs.CK_SESSION_HANDLE,
    user_type: pkcs.CK_USER_TYPE,
    pin: ?[*]const pkcs.CK_UTF8CHAR,
    pin_length: pkcs.CK_ULONG,
) error{
    ArgumentsBad,
    CryptokiNotInitialized,
    DeviceError,
    DeviceRemoved,
    FunctionFailed,
    GeneralError,
    HostMemory,
    PinIncorrect,
    PinLocked,
    SessionClosed,
    SessionHandleInvalid,
    UserAlreadyLoggedIn,
    UserTypeInvalid,
}!void {
    state.lock.lockSharedUncancelable(state.io);
    defer state.lock.unlockShared(state.io);

    if (!state.initialized)
        return error.CryptokiNotInitialized;

    const current_session = try session.getSession(state.io, session_handle, false);

    // Difference form the standard.
    if (user_type != pkcs.CKU_USER)
        return error.UserTypeInvalid;

    if (pin == null)
        return error.ArgumentsBad;

    if (current_session.loggedIn(state.io))
        return error.UserAlreadyLoggedIn;

    const padded_pin = PaddedPin.construct(pin.?[0..pin_length]) catch
        return error.PinIncorrect;

    try current_session.login(state.io, &padded_pin);

    current_session.resetOperation();
}

pub fn logout(
    state: *State,
    session_handle: pkcs.CK_SESSION_HANDLE,
) error{
    CryptokiNotInitialized,
    FunctionFailed,
    SessionHandleInvalid,
    UserNotLoggedIn,
}!void {
    state.lock.lockSharedUncancelable(state.io);
    defer state.lock.unlockShared(state.io);

    if (!state.initialized)
        return error.CryptokiNotInitialized;

    const current_session = try session.getSession(state.io, session_handle, false);

    if (!current_session.loggedIn(state.io))
        return error.UserNotLoggedIn;

    current_session.logout(state.io);

    current_session.resetOperation();
}
