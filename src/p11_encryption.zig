const std = @import("std");

const operation = @import("session/operation.zig");
const pkcs = @import("pkcs.zig");
const session = @import("session/session.zig");
const State = @import("ModuleState.zig");

pub fn encryptInit(
    state: *State,
    session_handle: pkcs.CK_SESSION_HANDLE,
    mechanism: ?*pkcs.CK_MECHANISM,
    key: pkcs.CK_OBJECT_HANDLE,
) error{
    ArgumentsBad,
    CryptokiNotInitialized,
    FunctionFailed,
    GeneralError,
    KeyHandleInvalid,
    KeyFunctionNotPermitted,
    MechanismInvalid,
    MechanismParamInvalid,
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

    if (found_object.public_key.encrypt != pkcs.CK_TRUE)
        return error.KeyFunctionNotPermitted;

    const public_key = std.crypto.Certificate.rsa.PublicKey.fromBytes(
        found_object.public_key.public_exponent,
        found_object.public_key.modulus,
    ) catch return error.GeneralError;

    const encrypt_operation = try operation.Encrypt.init(mechanism, public_key);

    current_session.operation = .{ .encrypt = encrypt_operation };
}

pub fn encrypt(
    state: *State,
    session_handle: pkcs.CK_SESSION_HANDLE,
    data: ?[*]const pkcs.CK_BYTE,
    data_len: pkcs.CK_ULONG,
    encrypted_data: ?[*]pkcs.CK_BYTE,
    encrypted_data_len: ?*pkcs.CK_ULONG,
) error{
    ArgumentsBad,
    BufferTooSmall,
    CryptokiNotInitialized,
    DataLenRange,
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

    try current_session.assertOperation(operation.Type.Encrypt); //?

    const current_operation = &current_session.operation.encrypt;

    if (current_operation.multipart_operation) {
        current_session.resetOperation();
        return error.FunctionCanceled;
    }

    if (encrypted_data_len == null) {
        current_session.resetOperation();
        return error.ArgumentsBad;
    }

    const required_encrypted_data_size = current_operation.keySizeBytes();

    if (encrypted_data == null) {
        encrypted_data_len.?.* = @intCast(required_encrypted_data_size);
        return;
    }

    if (encrypted_data_len.?.* < required_encrypted_data_size)
        return error.BufferTooSmall;

    defer current_session.resetOperation();

    if (data == null)
        return error.ArgumentsBad;

    _ = try current_operation.update(current_session.allocator, data.?[0..data_len]);

    const computed_encrypted_data = try current_operation.encrypt(current_session.allocator, state.io);
    defer current_session.allocator.free(computed_encrypted_data);

    if (computed_encrypted_data.len > encrypted_data_len.?.*)
        return error.GeneralError;

    encrypted_data_len.?.* = @intCast(computed_encrypted_data.len);
    @memcpy(encrypted_data.?, computed_encrypted_data[0..computed_encrypted_data.len]);
}

pub fn encryptUpdate(
    state: *State,
    session_handle: pkcs.CK_SESSION_HANDLE,
    part: ?[*]const pkcs.CK_BYTE,
    part_len: pkcs.CK_ULONG,
    encrypted_part: ?[*]pkcs.CK_BYTE,
    encrypted_part_len: ?*pkcs.CK_ULONG,
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

    try current_session.assertOperation(operation.Type.Encrypt);

    const current_operation = &current_session.operation.encrypt;

    if (encrypted_part_len == null) {
        current_session.resetOperation();
        return error.ArgumentsBad;
    }

    if (encrypted_part == null) {
        encrypted_part_len.?.* = 0;
        return;
    }

    if (part == null) {
        current_session.resetOperation();
        return error.ArgumentsBad;
    }

    current_operation.multipart_operation = true;
    const encrypted = current_operation.update(current_session.allocator, part.?[0..part_len]) catch
        return error.HostMemory;

    if (encrypted.len > encrypted_part_len.?.*)
        return error.GeneralError;

    encrypted_part_len.?.* = @intCast(encrypted.len);
    @memcpy(encrypted_part.?, encrypted);
}

pub fn encryptFinal(
    state: *State,
    session_handle: pkcs.CK_SESSION_HANDLE,
    last_encrypted_part: ?[*]pkcs.CK_BYTE,
    last_encrypted_part_len: ?*pkcs.CK_ULONG,
) error{
    ArgumentsBad,
    BufferTooSmall,
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

    try current_session.assertOperation(operation.Type.Encrypt);

    const current_operation = &current_session.operation.encrypt;

    if (last_encrypted_part_len == null) {
        current_session.resetOperation();
        return error.ArgumentsBad;
    }

    const required_encrypted_data_size = current_operation.keySizeBytes();

    if (last_encrypted_part == null) {
        last_encrypted_part_len.?.* = @intCast(required_encrypted_data_size);
        return;
    }

    if (last_encrypted_part_len.?.* < required_encrypted_data_size)
        return error.BufferTooSmall;

    defer current_session.resetOperation();

    const computed_encrypted_data = try current_operation.encrypt(current_session.allocator, state.io);
    defer current_session.allocator.free(computed_encrypted_data);

    if (computed_encrypted_data.len > last_encrypted_part_len.?.*)
        return error.GeneralError;

    last_encrypted_part_len.?.* = @intCast(computed_encrypted_data.len);
    @memcpy(last_encrypted_part.?, computed_encrypted_data[0..computed_encrypted_data.len]);
}
