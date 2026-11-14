const std = @import("std");

const hasher = @import("session/hasher.zig");
const operation = @import("session/operation.zig");
const pkcs = @import("pkcs.zig");
const session = @import("session/session.zig");
const State = @import("ModuleState.zig");

pub fn signInit(
    state: *State,
    session_handle: pkcs.CK_SESSION_HANDLE,
    mechanism: ?*pkcs.CK_MECHANISM,
    key: pkcs.CK_OBJECT_HANDLE,
) error{
    ArgumentsBad,
    CryptokiNotInitialized,
    FunctionFailed,
    KeyHandleInvalid,
    KeyFunctionNotPermitted,
    MechanismInvalid,
    OperationActive,
    SessionHandleInvalid,
    UserNotLoggedIn,
}!void {
    state.lock.lockSharedUncancelable(state.io);
    defer state.lock.unlockShared(state.io);

    if (!state.initialized)
        return error.CryptokiNotInitialized;

    const current_session = try session.getSession(state.io, session_handle, true);

    if (mechanism == null)
        return error.ArgumentsBad;

    try current_session.assertNoOperation();

    const found_object = current_session.getObject(state.io, key) catch
        return error.KeyHandleInvalid;

    if (found_object.* != .private_key)
        return error.KeyHandleInvalid;

    // if (std.mem.indexOfScalar(pkcs.CK_MECHANISM_TYPE, current_object.private_key.allowed_mechanisms, mechanism.?.*.mechanism) == null)
    //     return pkcs.CKR_KEY_TYPE_INCONSISTENT;

    if (found_object.private_key.sign != pkcs.CK_TRUE)
        return error.KeyFunctionNotPermitted;

    const sign_operation = try operation.Sign.init(
        mechanism,
        found_object.private_key.modulus.len,
        key,
    );

    current_session.operation = .{ .sign = sign_operation };
}

pub fn sign(
    state: *State,
    session_handle: pkcs.CK_SESSION_HANDLE,
    data: ?[*]pkcs.CK_BYTE,
    data_len: pkcs.CK_ULONG,
    signature: ?[*]pkcs.CK_BYTE,
    signature_len: ?*pkcs.CK_ULONG,
) error{
    ArgumentsBad,
    BufferTooSmall,
    CryptokiNotInitialized,
    DataLenRange,
    DeviceError,
    DeviceRemoved,
    FunctionCanceled,
    FunctionFailed,
    GeneralError,
    HostMemory,
    OperationNotInitialized,
    SessionHandleInvalid,
    UserNotLoggedIn,
}!void {
    state.lock.lockSharedUncancelable(state.io);
    defer state.lock.unlockShared(state.io);

    if (!state.initialized)
        return error.CryptokiNotInitialized;

    const current_session = try session.getSession(state.io, session_handle, true);
    const current_operation = try current_session.assertOperation(.sign);

    if (current_operation.multipart_operation) {
        current_session.resetOperation();
        return error.FunctionCanceled;
    }

    if (signature_len == null) {
        current_session.resetOperation();
        return error.ArgumentsBad;
    }

    const required_signature_size = current_operation.keySizeBytes();
    if (signature == null) {
        signature_len.?.* = @intCast(required_signature_size);
        return;
    }

    if (signature_len.?.* < required_signature_size)
        return error.BufferTooSmall;

    defer current_session.resetOperation();

    if (data == null)
        return error.ArgumentsBad;

    current_operation.update(current_session.allocator, data.?[0..data_len]) catch
        return error.HostMemory;

    const sign_request = try current_operation.createSignRequest(current_session.allocator);
    defer current_session.allocator.free(sign_request);

    const key_object = current_session.getObject(state.io, current_operation.private_key) catch
        return error.GeneralError;

    const computed_signature = try current_session.card.sign(
        current_session.allocator,
        key_object.fileName(),
        current_operation.sign_type != .DigestAndSign,
        sign_request,
    );
    defer current_session.allocator.free(computed_signature);

    if (computed_signature.len > signature_len.?.*)
        return error.GeneralError;

    signature_len.?.* = @intCast(computed_signature.len);
    @memcpy(signature.?, computed_signature);
}

pub fn signUpdate(
    state: *State,
    session_handle: pkcs.CK_SESSION_HANDLE,
    part: ?[*]pkcs.CK_BYTE,
    part_len: pkcs.CK_ULONG,
) error{
    ArgumentsBad,
    CryptokiNotInitialized,
    FunctionFailed,
    HostMemory,
    OperationNotInitialized,
    SessionHandleInvalid,
    UserNotLoggedIn,
}!void {
    state.lock.lockSharedUncancelable(state.io);
    defer state.lock.unlockShared(state.io);

    const current_session = try session.getSession(state.io, session_handle, true);
    const current_operation = try current_session.assertOperation(.sign);

    if (part == null) {
        current_session.resetOperation();
        return error.ArgumentsBad;
    }

    current_operation.multipart_operation = true;
    current_operation.update(current_session.allocator, part.?[0..part_len]) catch
        return error.HostMemory;
}

pub fn signFinal(
    state: *State,
    session_handle: pkcs.CK_SESSION_HANDLE,
    signature: ?[*]pkcs.CK_BYTE,
    signature_len: ?*pkcs.CK_ULONG,
) error{
    ArgumentsBad,
    BufferTooSmall,
    CryptokiNotInitialized,
    DataLenRange,
    DeviceError,
    DeviceRemoved,
    FunctionFailed,
    GeneralError,
    HostMemory,
    OperationNotInitialized,
    SessionHandleInvalid,
    UserNotLoggedIn,
}!void {
    state.lock.lockSharedUncancelable(state.io);
    defer state.lock.unlockShared(state.io);

    const current_session = try session.getSession(state.io, session_handle, true);
    const current_operation = try current_session.assertOperation(.sign);

    if (signature_len == null) {
        current_session.resetOperation();
        return error.ArgumentsBad;
    }

    const required_signature_size = current_operation.keySizeBytes();
    if (signature == null) {
        signature_len.?.* = @intCast(required_signature_size);
        return;
    }

    if (signature_len.?.* < required_signature_size)
        return error.BufferTooSmall;

    defer current_session.resetOperation();

    const sign_request = try current_operation.createSignRequest(current_session.allocator);
    defer current_session.allocator.free(sign_request);

    const key_object = current_session.getObject(state.io, current_operation.private_key) catch
        return error.GeneralError;

    const computed_signature = try current_session.card.sign(
        current_session.allocator,
        key_object.fileName(),
        current_operation.sign_type != .DigestAndSign,
        sign_request,
    );
    defer current_session.allocator.free(computed_signature);

    if (computed_signature.len > signature_len.?.*)
        return error.GeneralError;

    signature_len.?.* = @intCast(computed_signature.len);
    @memcpy(signature.?, computed_signature);
}

pub fn signRecoverInit(
    _: *State,
    _: pkcs.CK_SESSION_HANDLE,
    _: ?*pkcs.CK_MECHANISM,
    _: pkcs.CK_OBJECT_HANDLE,
) error{
    FunctionNotSupported,
}!void {
    return error.FunctionNotSupported;
}

pub fn signRecover(
    _: *State,
    _: pkcs.CK_SESSION_HANDLE,
    _: ?[*]const pkcs.CK_BYTE,
    _: pkcs.CK_ULONG,
    _: ?[*]pkcs.CK_BYTE,
    _: ?*pkcs.CK_ULONG,
) error{
    FunctionNotSupported,
}!void {
    return error.FunctionNotSupported;
}
