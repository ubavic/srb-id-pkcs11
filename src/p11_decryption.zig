const std = @import("std");

const operation = @import("session/operation.zig");
const pkcs = @import("pkcs.zig");
const session = @import("session/session.zig");
const state = @import("state.zig");

pub fn decryptInit(
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
    MechanismParamInvalid,
    OperationActive,
    SessionHandleInvalid,
    UserNotLoggedIn,
}!void {
    state.lock.lockSharedUncancelable(state.io);
    defer state.lock.unlockShared(state.io);

    const current_session = try session.getSession(session_handle, true);

    try current_session.assertNoOperation();

    const found_object = current_session.getObject(key) catch
        return error.KeyHandleInvalid;

    if (found_object.* != .private_key)
        return error.KeyHandleInvalid;

    if (found_object.private_key.decrypt != pkcs.CK_TRUE)
        return error.KeyFunctionNotPermitted;

    const decrypt_operation = try operation.Decrypt.init(
        mechanism,
        key,
        found_object.private_key.modulus.len,
    );

    current_session.operation = .{ .decrypt = decrypt_operation };
}

pub fn decrypt(
    session_handle: pkcs.CK_SESSION_HANDLE,
    encrypted_data: ?[*]const pkcs.CK_BYTE,
    encrypted_data_len: pkcs.CK_ULONG,
    data: ?[*]pkcs.CK_BYTE,
    data_len: ?*pkcs.CK_ULONG,
) error{
    ArgumentsBad,
    BufferTooSmall,
    CryptokiNotInitialized,
    DataLenRange,
    DeviceError,
    DeviceRemoved,
    EncryptedDataLenRange,
    EncryptedDataInvalid,
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

    const current_session = try session.getSession(session_handle, true);

    try current_session.assertOperation(operation.Type.Decrypt);

    const current_operation = &current_session.operation.decrypt;

    if (current_operation.multipart_operation) {
        current_session.resetOperation();
        return error.FunctionCanceled;
    }

    if (data_len == null) {
        current_session.resetOperation();
        return error.ArgumentsBad;
    }

    const required_data_size = current_operation.keySizeBytes();

    if (data == null) {
        data_len.?.* = @intCast(required_data_size);
        return;
    }

    if (data_len.?.* < required_data_size)
        return error.BufferTooSmall;

    defer current_session.resetOperation();

    if (encrypted_data == null)
        return error.ArgumentsBad;

    _ = current_operation.update(current_session.allocator, encrypted_data.?[0..encrypted_data_len]) catch
        return error.HostMemory;

    const decrypt_request = try current_operation.createDecryptRequest(current_session.allocator);
    defer current_session.allocator.free(decrypt_request);

    if (decrypt_request.len != current_operation.key_size)
        return error.EncryptedDataLenRange;

    const key_object = current_session.getObject(current_operation.private_key) catch
        return error.GeneralError;

    const computed_data = try current_session.card.decrypt(current_session.allocator, key_object.fileName(), decrypt_request);
    defer current_session.allocator.free(computed_data);
    defer std.crypto.secureZero(u8, computed_data);

    const message = try current_operation.stripPad(computed_data);

    if (message.len > data_len.?.*)
        return error.GeneralError;

    data_len.?.* = @intCast(message.len);
    @memcpy(data.?, message);
}

pub fn decryptUpdate(
    session_handle: pkcs.CK_SESSION_HANDLE,
    encrypted_part: ?[*]const pkcs.CK_BYTE,
    encrypted_part_len: pkcs.CK_ULONG,
    part: ?[*]pkcs.CK_BYTE,
    part_len: ?*pkcs.CK_ULONG,
) error{
    ArgumentsBad,
    CryptokiNotInitialized,
    FunctionFailed,
    GeneralError,
    HostMemory,
    OperationNotInitialized,
    SessionHandleInvalid,
    UserNotLoggedIn,
}!void {
    state.lock.lockSharedUncancelable(state.io);
    defer state.lock.unlockShared(state.io);

    const current_session = try session.getSession(session_handle, true);

    try current_session.assertOperation(operation.Type.Decrypt);

    const current_operation = &current_session.operation.decrypt;

    if (part_len == null) {
        current_session.resetOperation();
        return error.ArgumentsBad;
    }

    if (part == null) {
        part_len.?.* = 0;
        return;
    }

    if (encrypted_part == null) {
        current_session.resetOperation();
        return error.ArgumentsBad;
    }

    current_operation.multipart_operation = true;
    const decrypted_part = current_operation.update(current_session.allocator, encrypted_part.?[0..encrypted_part_len]) catch
        return error.HostMemory;

    if (decrypted_part.len > part_len.?.*)
        return error.GeneralError;

    part_len.?.* = @intCast(decrypted_part.len);
    @memcpy(part.?, decrypted_part);
}

pub fn decryptFinal(
    session_handle: pkcs.CK_SESSION_HANDLE,
    last_part: ?[*]pkcs.CK_BYTE,
    last_part_len: ?*pkcs.CK_ULONG,
) error{
    ArgumentsBad,
    BufferTooSmall,
    CryptokiNotInitialized,
    DataLenRange,
    DeviceError,
    DeviceRemoved,
    EncryptedDataLenRange,
    EncryptedDataInvalid,
    FunctionFailed,
    GeneralError,
    HostMemory,
    OperationNotInitialized,
    SessionHandleInvalid,
    UserNotLoggedIn,
}!void {
    state.lock.lockSharedUncancelable(state.io);
    defer state.lock.unlockShared(state.io);

    const current_session = try session.getSession(session_handle, true);

    try current_session.assertOperation(operation.Type.Decrypt);

    const current_operation = &current_session.operation.decrypt;

    if (last_part_len == null) {
        current_session.resetOperation();
        return error.ArgumentsBad;
    }

    const required_data_size = current_operation.keySizeBytes();

    if (last_part == null) {
        last_part_len.?.* = @intCast(required_data_size);
        return;
    }

    if (last_part_len.?.* < required_data_size)
        return error.BufferTooSmall;

    defer current_session.resetOperation();

    const decrypt_request = try current_operation.createDecryptRequest(current_session.allocator);
    defer current_session.allocator.free(decrypt_request);

    if (decrypt_request.len != current_operation.key_size)
        return error.EncryptedDataLenRange;

    const key_object = current_session.getObject(current_operation.private_key) catch
        return error.GeneralError;

    const computed_data = try current_session.card.decrypt(current_session.allocator, key_object.fileName(), decrypt_request);
    defer current_session.allocator.free(computed_data);
    defer std.crypto.secureZero(u8, computed_data);

    const message = try current_operation.stripPad(computed_data);

    if (message.len > last_part_len.?.*)
        return error.GeneralError;

    last_part_len.?.* = @intCast(message.len);
    @memcpy(last_part.?, message);
}
