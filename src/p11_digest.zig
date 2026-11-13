const std = @import("std");

const hasher = @import("session/hasher.zig");
const operation = @import("session/operation.zig");
const pkcs = @import("pkcs.zig");
const session = @import("session/session.zig");
const State = @import("ModuleState.zig");

pub fn digestInit(
    state: *State,
    session_handle: pkcs.CK_SESSION_HANDLE,
    mechanism: ?*pkcs.CK_MECHANISM,
) error{
    ArgumentsBad,
    CryptokiNotInitialized,
    GeneralError,
    FunctionFailed,
    MechanismInvalid,
    OperationActive,
    SessionHandleInvalid,
}!void {
    state.lock.lockSharedUncancelable(state.io);
    defer state.lock.unlockShared(state.io);

    if (!state.initialized)
        return error.CryptokiNotInitialized;

    const current_session = try session.getSession(state.io, session_handle, false);
    try current_session.assertNoOperation();

    const digest_operation = try operation.Digest.init(mechanism);
    current_session.operation = .{ .digest = digest_operation };
}

pub fn digest(
    state: *State,
    session_handle: pkcs.CK_SESSION_HANDLE,
    data: ?[*]pkcs.CK_BYTE,
    data_len: pkcs.CK_ULONG,
    data_digest: ?[*]pkcs.CK_BYTE,
    data_digest_len: ?*pkcs.CK_ULONG,
) error{
    ArgumentsBad,
    BufferTooSmall,
    CryptokiNotInitialized,
    FunctionCanceled,
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
    try current_session.assertOperation(operation.Type.Digest);

    const current_operation = &current_session.operation.digest;

    if (current_operation.multipart_operation) {
        current_session.resetOperation();
        return error.FunctionCanceled;
    }

    if (data_digest_len == null) {
        current_session.resetOperation();
        return error.ArgumentsBad;
    }

    const required_digest_size = current_operation.hasher.digestLength();

    if (data_digest == null) {
        data_digest_len.?.* = @intCast(required_digest_size);
        return;
    }

    if (data_digest_len.?.* < required_digest_size) {
        data_digest_len.?.* = @intCast(required_digest_size);
        return error.BufferTooSmall;
    }

    defer current_session.resetOperation();

    if (data == null)
        return error.ArgumentsBad;

    current_operation.hasher.update(data.?[0..data_len]);
    _ = try current_operation.hasher.finalize(data_digest.?[0..required_digest_size]);
    data_digest_len.?.* = @intCast(required_digest_size);
}

pub fn digestUpdate(
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
}!void {
    state.lock.lockSharedUncancelable(state.io);
    defer state.lock.unlockShared(state.io);

    if (!state.initialized)
        return error.CryptokiNotInitialized;

    const current_session = try session.getSession(state.io, session_handle, false);
    try current_session.assertOperation(operation.Type.Digest);

    const current_operation = &current_session.operation.digest;

    if (part == null) {
        current_session.resetOperation();
        return error.ArgumentsBad;
    }

    current_operation.multipart_operation = true;
    current_operation.hasher.update(part.?[0..part_len]);
}

pub fn digestKey(
    _: *State,
    _: pkcs.CK_SESSION_HANDLE,
    _: pkcs.CK_OBJECT_HANDLE,
) error{
    FunctionNotSupported,
}!void {
    return error.FunctionNotSupported;
}

pub fn digestFinal(
    state: *State,
    session_handle: pkcs.CK_SESSION_HANDLE,
    data_digest: ?[*]pkcs.CK_BYTE,
    data_digest_len: ?*pkcs.CK_ULONG,
) error{
    ArgumentsBad,
    BufferTooSmall,
    CryptokiNotInitialized,
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
    try current_session.assertOperation(operation.Type.Digest);

    var current_operation = &current_session.operation.digest;

    if (data_digest_len == null) {
        current_session.resetOperation();
        return error.ArgumentsBad;
    }

    const required_digest_size = current_operation.hasher.digestLength();
    if (data_digest == null) {
        data_digest_len.?.* = @intCast(required_digest_size);
        return;
    }

    if (data_digest_len.?.* < required_digest_size) {
        data_digest_len.?.* = @intCast(required_digest_size);
        return error.BufferTooSmall;
    }

    defer current_session.resetOperation();

    _ = try current_operation.hasher.finalize(data_digest.?[0..required_digest_size]);
    data_digest_len.?.* = @intCast(required_digest_size);
}
