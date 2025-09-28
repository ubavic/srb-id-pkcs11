const std = @import("std");

const consts = @import("consts.zig");
const operation = @import("operation.zig");
const pkcs = @import("pkcs.zig").pkcs;
const pkcs_error = @import("pkcs_error.zig");
const state = @import("state.zig");
const session = @import("session.zig");
const hasher = @import("hasher.zig");

pub export fn C_SignInit(
    session_handle: pkcs.CK_SESSION_HANDLE,
    mechanism: ?*pkcs.CK_MECHANISM,
    key: pkcs.CK_OBJECT_HANDLE,
) pkcs.CK_RV {
    state.lock.lockShared();
    defer state.lock.unlockShared();

    const current_session = session.getSession(session_handle, true) catch |err|
        return pkcs_error.toRV(err);

    if (mechanism == null)
        return pkcs.CKR_ARGUMENTS_BAD;

    current_session.assertNoOperation() catch |err|
        return pkcs_error.toRV(err);

    const hash_mechanism = hasher.fromSignMechanism(mechanism.?.mechanism) catch |err|
        return pkcs_error.toRV(err);

    var hash: ?hasher.Hasher = null;
    var msg_buffer: ?std.ArrayList(u8) = null;
    if (hash_mechanism != null) {
        hash = hasher.createAndInit(hash_mechanism.?, current_session.allocator) catch
            return pkcs.CKR_HOST_MEMORY;
    } else {
        msg_buffer = std.ArrayList(u8){};
    }

    var key_found = false;
    for (current_session.objects) |current_object| {
        if (current_object.handle() == key) {
            switch (current_object) {
                .private_key => {
                    // if (std.mem.indexOfScalar(pkcs.CK_MECHANISM_TYPE, current_object.private_key.allowed_mechanisms, mechanism.?.*.mechanism) == null)
                    //     return pkcs.CKR_KEY_TYPE_INCONSISTENT;

                    if (current_object.private_key.sign != pkcs.CK_TRUE)
                        return pkcs.CKR_KEY_FUNCTION_NOT_PERMITTED;
                },
                .certificate, .public_key => return pkcs.CKR_KEY_HANDLE_INVALID,
            }

            key_found = true;
            break;
        }
    }

    if (!key_found)
        return pkcs.CKR_KEY_HANDLE_INVALID;

    current_session.operation = operation.Operation{
        .sign = operation.Sign{
            .private_key = key,
            .hasher = hash,
            .msg_buffer = msg_buffer,
            .multipart_operation = false,
        },
    };

    return pkcs.CKR_OK;
}

pub export fn C_Sign(
    session_handle: pkcs.CK_SESSION_HANDLE,
    data: ?[*]pkcs.CK_BYTE,
    data_len: pkcs.CK_ULONG,
    signature: ?[*]pkcs.CK_BYTE,
    signature_len: ?*pkcs.CK_ULONG,
) pkcs.CK_RV {
    state.lock.lockShared();
    defer state.lock.unlockShared();

    const current_session = session.getSession(session_handle, true) catch |err|
        return pkcs_error.toRV(err);

    current_session.assertOperation(operation.Type.Sign) catch |err|
        return pkcs_error.toRV(err);

    const current_operation = &current_session.operation.sign;

    if (current_operation.multipart_operation) {
        current_session.resetOperation();
        return pkcs.CKR_FUNCTION_CANCELED;
    }

    if (signature_len == null) {
        current_session.resetOperation();
        return pkcs.CKR_ARGUMENTS_BAD;
    }

    const required_signature_size = operation.signature_size;
    if (signature == null) {
        signature_len.?.* = required_signature_size;
        return pkcs.CKR_OK;
    }

    if (signature_len.?.* < required_signature_size)
        return pkcs.CKR_BUFFER_TOO_SMALL;

    defer current_session.resetOperation();

    if (data == null)
        return pkcs.CKR_ARGUMENTS_BAD;

    current_operation.update(current_session.allocator, data.?[0..data_len]) catch
        return pkcs.CKR_HOST_MEMORY;

    const sign_request = current_operation.createSignRequest(current_session.allocator) catch |err|
        return pkcs_error.toRV(err);
    defer current_session.allocator.free(sign_request);

    const key_id = consts.getCardIdFormPrivateKey(current_operation.private_key) catch |err|
        return pkcs_error.toRV(err);

    const computed_signature = current_session.card.sign(
        current_session.allocator,
        key_id,
        current_operation.hasher == null,
        sign_request,
    ) catch |err|
        return pkcs_error.toRV(err);
    defer current_session.allocator.free(computed_signature);

    if (computed_signature.len > signature_len.?.*)
        return pkcs.CKR_GENERAL_ERROR;

    signature_len.?.* = computed_signature.len;
    @memcpy(signature.?, computed_signature);

    return pkcs.CKR_OK;
}

pub export fn C_SignUpdate(
    session_handle: pkcs.CK_SESSION_HANDLE,
    part: ?[*]pkcs.CK_BYTE,
    part_len: pkcs.CK_ULONG,
) pkcs.CK_RV {
    state.lock.lockShared();
    defer state.lock.unlockShared();

    const current_session = session.getSession(session_handle, true) catch |err|
        return pkcs_error.toRV(err);

    current_session.assertOperation(operation.Type.Sign) catch |err|
        return pkcs_error.toRV(err);

    const current_operation = &current_session.operation.sign;

    if (part == null) {
        current_session.resetOperation();
        return pkcs.CKR_ARGUMENTS_BAD;
    }

    current_operation.multipart_operation = true;
    current_operation.update(current_session.allocator, part.?[0..part_len]) catch
        return pkcs.CKR_HOST_MEMORY;

    return pkcs.CKR_OK;
}

pub export fn C_SignFinal(
    session_handle: pkcs.CK_SESSION_HANDLE,
    signature: ?[*]pkcs.CK_BYTE,
    signature_len: ?*pkcs.CK_ULONG,
) pkcs.CK_RV {
    state.lock.lockShared();
    defer state.lock.unlockShared();

    const current_session = session.getSession(session_handle, true) catch |err|
        return pkcs_error.toRV(err);

    current_session.assertOperation(operation.Type.Sign) catch |err|
        return pkcs_error.toRV(err);

    const current_operation = &current_session.operation.sign;

    const required_signature_size = operation.signature_size;
    if (signature == null) {
        signature_len.?.* = required_signature_size;
        return pkcs.CKR_OK;
    }

    if (signature_len.?.* < required_signature_size)
        return pkcs.CKR_BUFFER_TOO_SMALL;

    defer current_session.resetOperation();

    const sign_request = current_operation.createSignRequest(current_session.allocator) catch |err|
        return pkcs_error.toRV(err);
    defer current_session.allocator.free(sign_request);

    const key_id = consts.getCardIdFormPrivateKey(current_operation.private_key) catch |err|
        return pkcs_error.toRV(err);

    const computed_signature = current_session.card.sign(
        current_session.allocator,
        key_id,
        current_operation.hasher == null,
        sign_request,
    ) catch |err|
        return pkcs_error.toRV(err);
    defer current_session.allocator.free(computed_signature);

    if (computed_signature.len > signature_len.?.*)
        return pkcs.CKR_GENERAL_ERROR;

    signature_len.?.* = computed_signature.len;
    @memcpy(signature.?, computed_signature);

    return pkcs.CKR_OK;
}

pub export fn C_SignRecoverInit(
    session_handle: pkcs.CK_SESSION_HANDLE,
    mechanism: ?*pkcs.CK_MECHANISM,
    key: pkcs.CK_OBJECT_HANDLE,
) pkcs.CK_RV {
    _ = session_handle;
    _ = mechanism;
    _ = key;

    return pkcs.CKR_FUNCTION_NOT_SUPPORTED;
}

pub export fn C_SignRecover(
    session_handle: pkcs.CK_SESSION_HANDLE,
    data: ?[*]const pkcs.CK_BYTE,
    data_len: pkcs.CK_ULONG,
    signature: ?[*]pkcs.CK_BYTE,
    signature_len: ?*pkcs.CK_ULONG,
) pkcs.CK_RV {
    _ = session_handle;
    _ = data;
    _ = data_len;
    _ = signature;
    _ = signature_len;

    return pkcs.CKR_FUNCTION_NOT_SUPPORTED;
}
