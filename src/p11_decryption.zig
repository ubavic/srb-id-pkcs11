const std = @import("std");

const consts = @import("consts.zig");
const operation = @import("operation.zig");
const pkcs = @import("pkcs.zig").pkcs;
const pkcs_error = @import("pkcs_error.zig");
const session = @import("session.zig");
const state = @import("state.zig");

pub export fn C_DecryptInit(
    session_handle: pkcs.CK_SESSION_HANDLE,
    mechanism: ?*pkcs.CK_MECHANISM,
    key: pkcs.CK_OBJECT_HANDLE,
) pkcs.CK_RV {
    state.lock.lockShared();
    defer state.lock.unlockShared();

    const current_session = session.getSession(session_handle, false) catch |err|
        return pkcs_error.toRV(err);

    if (mechanism == null)
        return pkcs.CKR_ARGUMENTS_BAD;

    var raw: bool = undefined;

    switch (mechanism.?.mechanism) {
        pkcs.CKM_RSA_PKCS => raw = false,
        pkcs.CKM_RSA_X_509 => raw = true,
        else => return pkcs.CKR_MECHANISM_INVALID,
    }

    if (mechanism.?.ulParameterLen != 0)
        return pkcs.CKR_MECHANISM_PARAM_INVALID;

    current_session.assertNoOperation() catch |err|
        return pkcs_error.toRV(err);

    const found_object = current_session.getObject(key) catch
        return pkcs.CKR_KEY_HANDLE_INVALID;

    switch (found_object.*) {
        .private_key => {
            if (found_object.private_key.decrypt != pkcs.CK_TRUE)
                return pkcs.CKR_KEY_FUNCTION_NOT_PERMITTED;
        },
        else => return pkcs.CKR_KEY_HANDLE_INVALID,
    }

    current_session.operation = operation.Operation{
        .decrypt = operation.Decrypt{
            .private_key = key,
            .multipart_operation = false,
            .msg_buffer = std.ArrayList(u8){},
            .raw = raw,
        },
    };

    return pkcs.CKR_OK;
}

pub export fn C_Decrypt(
    session_handle: pkcs.CK_SESSION_HANDLE,
    encrypted_data: ?[*]const pkcs.CK_BYTE,
    encrypted_data_len: pkcs.CK_ULONG,
    data: ?[*]pkcs.CK_BYTE,
    data_len: ?*pkcs.CK_ULONG,
) pkcs.CK_RV {
    state.lock.lockShared();
    defer state.lock.unlockShared();

    const current_session = session.getSession(session_handle, false) catch |err|
        return pkcs_error.toRV(err);

    current_session.assertOperation(operation.Type.Decrypt) catch |err|
        return pkcs_error.toRV(err);

    const current_operation = &current_session.operation.decrypt;

    if (current_operation.multipart_operation) {
        current_session.resetOperation();
        return pkcs.CKR_FUNCTION_CANCELED;
    }

    if (data_len == null) {
        current_session.resetOperation();
        return pkcs.CKR_ARGUMENTS_BAD;
    }

    const required_data_size = operation.encrypted_data_size;
    if (data == null) {
        data_len.?.* = required_data_size;
        return pkcs.CKR_OK;
    }

    if (data_len.?.* < required_data_size)
        return pkcs.CKR_BUFFER_TOO_SMALL;

    defer current_session.resetOperation();

    if (encrypted_data == null)
        return pkcs.CKR_ARGUMENTS_BAD;

    _ = current_operation.update(current_session.allocator, encrypted_data.?[0..encrypted_data_len]) catch
        return pkcs.CKR_HOST_MEMORY;

    const decrypt_request = current_operation.createDecryptRequest(current_session.allocator) catch |err|
        return pkcs_error.toRV(err);

    const key_id = consts.getCardIdFormPrivateKey(current_operation.private_key) catch |err|
        return pkcs_error.toRV(err);

    const computed_data = current_session.card.decrypt(current_session.allocator, key_id, decrypt_request) catch |err|
        return pkcs_error.toRV(err);
    defer current_session.allocator.free(computed_data);
    defer std.crypto.secureZero(u8, computed_data);

    const message = current_operation.stripPad(computed_data) catch |err|
        return pkcs_error.toRV(err);

    data_len.?.* = @intCast(message.len);
    @memcpy(data.?, message);

    return pkcs.CKR_OK;
}

pub export fn C_DecryptUpdate(
    session_handle: pkcs.CK_SESSION_HANDLE,
    encrypted_part: ?[*]const pkcs.CK_BYTE,
    encrypted_part_len: pkcs.CK_ULONG,
    part: ?[*]pkcs.CK_BYTE,
    part_len: ?*pkcs.CK_ULONG,
) pkcs.CK_RV {
    state.lock.lockShared();
    defer state.lock.unlockShared();

    const current_session = session.getSession(session_handle, true) catch |err|
        return pkcs_error.toRV(err);

    current_session.assertOperation(operation.Type.Decrypt) catch |err|
        return pkcs_error.toRV(err);

    const current_operation = &current_session.operation.decrypt;

    if (part_len == null) {
        current_session.resetOperation();
        return pkcs.CKR_ARGUMENTS_BAD;
    }

    if (part == null) {
        part_len.?.* = 0;
        return pkcs.CKR_OK;
    }

    if (encrypted_part == null) {
        current_session.resetOperation();
        return pkcs.CKR_ARGUMENTS_BAD;
    }

    current_operation.multipart_operation = true;
    const decrypted_part = current_operation.update(current_session.allocator, encrypted_part.?[0..encrypted_part_len]) catch
        return pkcs.CKR_HOST_MEMORY;

    if (decrypted_part.len > part_len.?.*)
        return pkcs.CKR_GENERAL_ERROR;

    part_len.?.* = @intCast(decrypted_part.len);
    @memcpy(part.?, decrypted_part);

    return pkcs.CKR_OK;
}

pub export fn C_DecryptFinal(
    session_handle: pkcs.CK_SESSION_HANDLE,
    last_part: ?[*]pkcs.CK_BYTE,
    last_part_len: ?*pkcs.CK_ULONG,
) pkcs.CK_RV {
    state.lock.lockShared();
    defer state.lock.unlockShared();

    const current_session = session.getSession(session_handle, true) catch |err|
        return pkcs_error.toRV(err);

    current_session.assertOperation(operation.Type.Decrypt) catch |err|
        return pkcs_error.toRV(err);

    const current_operation = &current_session.operation.decrypt;

    if (last_part_len == null) {
        current_session.resetOperation();
        return pkcs.CKR_ARGUMENTS_BAD;
    }

    const required_data_size = operation.encrypted_data_size;

    if (last_part == null) {
        last_part_len.?.* = required_data_size;
        return pkcs.CKR_OK;
    }

    if (last_part_len.?.* < required_data_size)
        return pkcs.CKR_BUFFER_TOO_SMALL;

    defer current_session.resetOperation();

    const decrypt_request = current_operation.createDecryptRequest(current_session.allocator) catch |err|
        return pkcs_error.toRV(err);

    const key_id = consts.getCardIdFormPrivateKey(current_operation.private_key) catch |err|
        return pkcs_error.toRV(err);

    const computed_data = current_session.card.decrypt(current_session.allocator, key_id, decrypt_request) catch |err|
        return pkcs_error.toRV(err);
    defer current_session.allocator.free(computed_data);
    defer std.crypto.secureZero(u8, computed_data);

    const message = current_operation.stripPad(computed_data) catch |err|
        return pkcs_error.toRV(err);

    last_part_len.?.* = @intCast(message.len);
    @memcpy(last_part.?, message);

    return pkcs.CKR_OK;
}
