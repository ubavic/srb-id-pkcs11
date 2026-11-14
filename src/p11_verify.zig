const std = @import("std");

const hasher = @import("session/hasher.zig");
const operation = @import("session/operation.zig");
const pkcs = @import("pkcs.zig");
const session = @import("session/session.zig");
const State = @import("ModuleState.zig");

pub fn verifyInit(
    state: *State,
    session_handle: pkcs.CK_SESSION_HANDLE,
    mechanism: ?*pkcs.CK_MECHANISM,
    key: pkcs.CK_OBJECT_HANDLE,
) error{
    ArgumentsBad,
    CryptokiNotInitialized,
    FunctionFailed,
    GeneralError,
    KeyFunctionNotPermitted,
    KeyHandleInvalid,
    MechanismInvalid,
    OperationActive,
    SessionHandleInvalid,
    UserNotLoggedIn,
}!void {
    state.lock.lockSharedUncancelable(state.io);
    defer state.lock.unlockShared(state.io);

    if (!state.initialized)
        return error.CryptokiNotInitialized;

    const current_session = try session.getSession(state.io, session_handle, false);

    try current_session.assertNoOperation();

    const found_object = current_session.getObject(state.io, key) catch
        return error.KeyHandleInvalid;

    if (found_object.* != .public_key)
        return error.KeyHandleInvalid;

    // if (std.mem.indexOfScalar(pkcs.CK_MECHANISM_TYPE, current_object.public_key.allowed_mechanisms, mechanism.?.*.mechanism) == null)
    //    return pkcs.CKR_KEY_TYPE_INCONSISTENT;

    if (found_object.public_key.verify != pkcs.CK_TRUE)
        return error.KeyFunctionNotPermitted;

    const public_key = std.crypto.Certificate.rsa.PublicKey.fromBytes(
        found_object.public_key.public_exponent,
        found_object.public_key.modulus,
    ) catch return error.GeneralError;

    const verify_operation = try operation.Verify.init(mechanism, public_key);

    current_session.operation = .{ .verify = verify_operation };
}

pub fn verify(
    state: *State,
    session_handle: pkcs.CK_SESSION_HANDLE,
    data: ?[*]const pkcs.CK_BYTE,
    data_len: pkcs.CK_ULONG,
    signature: ?[*]const pkcs.CK_BYTE,
    signature_len: pkcs.CK_ULONG,
) error{
    ArgumentsBad,
    CryptokiNotInitialized,
    DataLenRange,
    FunctionCanceled,
    FunctionFailed,
    GeneralError,
    HostMemory,
    OperationNotInitialized,
    SessionHandleInvalid,
    SignatureInvalid,
    SignatureLenRange,
}!void {
    state.lock.lockSharedUncancelable(state.io);
    defer state.lock.unlockShared(state.io);

    if (!state.initialized)
        return error.CryptokiNotInitialized;

    const current_session = try session.getSession(state.io, session_handle, false);
    const current_operation = try current_session.assertOperation(.verify);

    defer current_session.resetOperation();

    if (data == null)
        return error.ArgumentsBad;

    if (signature == null)
        return error.ArgumentsBad;

    if (current_operation.multipart_operation)
        return error.FunctionCanceled;

    if (signature_len != current_operation.keySizeBytes())
        return error.SignatureLenRange;

    current_operation.update(current_session.allocator, data.?[0..data_len]) catch
        return error.HostMemory;

    try current_operation.verify(current_session.allocator, signature.?[0..signature_len]);
}

pub fn verifyUpdate(
    state: *State,
    session_handle: pkcs.CK_SESSION_HANDLE,
    part: ?[*]const pkcs.CK_BYTE,
    part_len: pkcs.CK_ULONG,
) error{
    ArgumentsBad,
    CryptokiNotInitialized,
    DataLenRange,
    FunctionFailed,
    GeneralError,
    HostMemory,
    OperationNotInitialized,
    SessionHandleInvalid,
}!void {
    state.lock.lockSharedUncancelable(state.io);
    defer state.lock.unlockShared(state.io);

    if (!state.initialized)
        return error.CryptokiNotInitialized;

    const current_session = try session.getSession(state.io, session_handle, false);
    const current_operation = try current_session.assertOperation(.verify);

    if (part == null) {
        current_session.resetOperation();
        return error.ArgumentsBad;
    }

    current_operation.multipart_operation = true;
    current_operation.update(current_session.allocator, part.?[0..part_len]) catch
        return error.HostMemory;
}

pub fn verifyFinal(
    state: *State,
    session_handle: pkcs.CK_SESSION_HANDLE,
    signature: ?[*]const pkcs.CK_BYTE,
    signature_len: pkcs.CK_ULONG,
) error{
    ArgumentsBad,
    CryptokiNotInitialized,
    DataLenRange,
    FunctionFailed,
    GeneralError,
    HostMemory,
    OperationNotInitialized,
    SessionHandleInvalid,
    SignatureInvalid,
    SignatureLenRange,
}!void {
    state.lock.lockSharedUncancelable(state.io);
    defer state.lock.unlockShared(state.io);

    if (!state.initialized)
        return error.CryptokiNotInitialized;

    const current_session = try session.getSession(state.io, session_handle, false);
    const current_operation = try current_session.assertOperation(.verify);

    defer current_session.resetOperation();

    if (signature == null)
        return error.ArgumentsBad;

    if (signature_len != current_operation.keySizeBytes())
        return error.SignatureLenRange;

    try current_operation.verify(current_session.allocator, signature.?[0..signature_len]);
}

pub fn verifyRecoverInit(
    _: *State,
    session_handle: pkcs.CK_SESSION_HANDLE,
    mechanism: ?*pkcs.CK_MECHANISM,
    key: pkcs.CK_OBJECT_HANDLE,
) error{
    FunctionNotSupported,
}!void {
    _ = session_handle;
    _ = mechanism;
    _ = key;

    return error.FunctionNotSupported;
}

pub fn verifyRecover(
    _: *State,
    session_handle: pkcs.CK_SESSION_HANDLE,
    signature: ?[*]const pkcs.CK_BYTE,
    signature_len: pkcs.CK_ULONG,
    data: ?[*]pkcs.CK_BYTE,
    data_len: ?*pkcs.CK_ULONG,
) error{
    FunctionNotSupported,
}!void {
    _ = session_handle;
    _ = signature;
    _ = signature_len;
    _ = data;
    _ = data_len;

    return error.FunctionNotSupported;
}
