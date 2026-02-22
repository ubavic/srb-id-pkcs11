const std = @import("std");

const consts = @import("consts.zig");
const operation = @import("operation.zig");
const object = @import("object.zig");
const pkcs = @import("pkcs.zig").pkcs;
const pkcs_error = @import("pkcs_error.zig");
const session = @import("session.zig");
const state = @import("state.zig");

pub export fn C_EncryptInit(
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

    var raw = false;

    switch (mechanism.?.mechanism) {
        pkcs.CKM_RSA_PKCS => {},
        pkcs.CKM_RSA_X_509 => raw = true,
        else => return pkcs.CKR_MECHANISM_INVALID,
    }

    if (mechanism.?.ulParameterLen != 0)
        return pkcs.CKR_MECHANISM_PARAM_INVALID;

    current_session.assertNoOperation() catch |err|
        return pkcs_error.toRV(err);

    var public_key: ?*object.PublicKeyObject = null;
    for (current_session.objects) |*current_object| {
        if (current_object.handle() == key) {
            switch (current_object.*) {
                .public_key => {
                    if (current_object.public_key.encrypt != pkcs.CK_TRUE)
                        return pkcs.CKR_KEY_FUNCTION_NOT_PERMITTED;

                    public_key = &current_object.*.public_key;
                },
                else => return pkcs.CKR_KEY_HANDLE_INVALID,
            }

            break;
        }
    }

    if (public_key == null)
        return pkcs.CKR_KEY_HANDLE_INVALID;

    const modulus = current_session.allocator.dupe(u8, public_key.?.*.modulus) catch
        return pkcs.CKR_HOST_MEMORY;

    const exponent = current_session.allocator.dupe(u8, public_key.?.*.public_exponent) catch
        return pkcs.CKR_HOST_MEMORY;

    current_session.operation = operation.Operation{
        .encrypt = operation.Encrypt{
            .public_key = key,
            .multipart_operation = false,
            .msg_buffer = std.ArrayList(u8){},
            .raw = raw,
            .modulus = modulus,
            .exponent = exponent,
        },
    };

    return pkcs.CKR_OK;
}

pub export fn C_Encrypt(
    session_handle: pkcs.CK_SESSION_HANDLE,
    data: ?[*]const pkcs.CK_BYTE,
    data_len: pkcs.CK_ULONG,
    encrypted_data: ?[*]pkcs.CK_BYTE,
    encrypted_data_len: ?*pkcs.CK_ULONG,
) pkcs.CK_RV {
    state.lock.lockShared();
    defer state.lock.unlockShared();

    const current_session = session.getSession(session_handle, true) catch |err|
        return pkcs_error.toRV(err);

    current_session.assertOperation(operation.Type.Encrypt) catch |err|
        return pkcs_error.toRV(err);

    const current_operation = &current_session.operation.encrypt;

    if (current_operation.multipart_operation) {
        current_session.resetOperation();
        return pkcs.CKR_FUNCTION_CANCELED;
    }

    if (encrypted_data_len == null) {
        current_session.resetOperation();
        return pkcs.CKR_ARGUMENTS_BAD;
    }

    const required_encrypted_data_size = operation.encrypted_data_size;
    if (encrypted_data == null) {
        encrypted_data_len.?.* = required_encrypted_data_size;
        return pkcs.CKR_OK;
    }

    if (encrypted_data_len.?.* < required_encrypted_data_size)
        return pkcs.CKR_BUFFER_TOO_SMALL;

    defer current_session.resetOperation();

    if (data == null)
        return pkcs.CKR_ARGUMENTS_BAD;

    _ = current_operation.update(current_session.allocator, data.?[0..data_len]) catch |err|
        return pkcs_error.toRV(err);

    const computed_encrypted_data = current_operation.encrypt(current_session.allocator) catch |err|
        return pkcs_error.toRV(err);

    if (computed_encrypted_data.len > encrypted_data_len.?.*)
        return pkcs.CKR_GENERAL_ERROR;

    encrypted_data_len.?.* = @intCast(computed_encrypted_data.len);
    @memcpy(encrypted_data.?, computed_encrypted_data[0..computed_encrypted_data.len]);

    return pkcs.CKR_OK;
}

pub export fn C_EncryptUpdate(
    session_handle: pkcs.CK_SESSION_HANDLE,
    part: ?[*]const pkcs.CK_BYTE,
    part_len: pkcs.CK_ULONG,
    encrypted_part: ?[*]pkcs.CK_BYTE,
    encrypted_part_len: ?*pkcs.CK_ULONG,
) pkcs.CK_RV {
    state.lock.lockShared();
    defer state.lock.unlockShared();

    const current_session = session.getSession(session_handle, true) catch |err|
        return pkcs_error.toRV(err);

    current_session.assertOperation(operation.Type.Encrypt) catch |err|
        return pkcs_error.toRV(err);

    const current_operation = &current_session.operation.encrypt;

    if (encrypted_part_len == null) {
        current_session.resetOperation();
        return pkcs.CKR_ARGUMENTS_BAD;
    }

    if (encrypted_part == null) {
        encrypted_part_len.?.* = 0;
        return pkcs.CKR_OK;
    }

    if (part == null) {
        current_session.resetOperation();
        return pkcs.CKR_ARGUMENTS_BAD;
    }

    current_operation.multipart_operation = true;
    const encrypted = current_operation.update(current_session.allocator, part.?[0..part_len]) catch
        return pkcs.CKR_HOST_MEMORY;

    if (encrypted.len > encrypted_part_len.?.*)
        return pkcs.CKR_GENERAL_ERROR;

    encrypted_part_len.?.* = @intCast(encrypted.len);
    @memcpy(encrypted_part.?, encrypted);

    return pkcs.CKR_OK;
}

pub export fn C_EncryptFinal(
    session_handle: pkcs.CK_SESSION_HANDLE,
    last_encrypted_part: ?[*]pkcs.CK_BYTE,
    last_encrypted_part_len: ?*pkcs.CK_ULONG,
) pkcs.CK_RV {
    state.lock.lockShared();
    defer state.lock.unlockShared();

    const current_session = session.getSession(session_handle, true) catch |err|
        return pkcs_error.toRV(err);

    current_session.assertOperation(operation.Type.Encrypt) catch |err|
        return pkcs_error.toRV(err);

    _ = &current_session.operation.encrypt;

    const required_encrypted_data_size = operation.encrypted_data_size;
    if (last_encrypted_part == null) {
        last_encrypted_part_len.?.* = required_encrypted_data_size;
        return pkcs.CKR_OK;
    }

    if (last_encrypted_part_len.?.* < required_encrypted_data_size)
        return pkcs.CKR_BUFFER_TOO_SMALL;

    defer current_session.resetOperation();

    const computed_encrypted_data = &[_]u8{1};

    if (computed_encrypted_data.len > last_encrypted_part_len.?.*)
        return pkcs.CKR_GENERAL_ERROR;

    last_encrypted_part_len.?.* = @intCast(computed_encrypted_data.len);
    @memcpy(last_encrypted_part.?, computed_encrypted_data);

    return pkcs.CKR_OK;
}
