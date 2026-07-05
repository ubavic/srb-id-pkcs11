const std = @import("std");

const operation = @import("operation.zig");
const pkcs = @import("pkcs.zig");
const pkcs_error = @import("pkcs_error.zig");
const state = @import("state.zig");
const session = @import("session.zig");
const hasher = @import("hasher.zig");

pub export fn C_VerifyInit(
    session_handle: pkcs.CK_SESSION_HANDLE,
    mechanism: ?*pkcs.CK_MECHANISM,
    key: pkcs.CK_OBJECT_HANDLE,
) pkcs.CK_RV {
    state.lock.lockSharedUncancelable(state.io);
    defer state.lock.unlockShared(state.io);

    const current_session = session.getSession(session_handle, false) catch |err|
        return pkcs_error.toRV(err);

    if (mechanism == null)
        return pkcs.CKR_ARGUMENTS_BAD;

    current_session.assertNoOperation() catch |err|
        return pkcs_error.toRV(err);

    const found_object = current_session.getObject(key) catch
        return pkcs.CKR_KEY_HANDLE_INVALID;

    switch (found_object.*) {
        .public_key => {
            // if (std.mem.indexOfScalar(pkcs.CK_MECHANISM_TYPE, current_object.public_key.allowed_mechanisms, mechanism.?.*.mechanism) == null)
            //    return pkcs.CKR_KEY_TYPE_INCONSISTENT;

            if (found_object.public_key.verify != pkcs.CK_TRUE)
                return pkcs.CKR_KEY_FUNCTION_NOT_PERMITTED;
        },
        else => return pkcs.CKR_KEY_HANDLE_INVALID,
    }

    const public_key = std.crypto.Certificate.rsa.PublicKey.fromBytes(
        found_object.public_key.public_exponent,
        found_object.public_key.modulus,
    ) catch return pkcs.CKR_GENERAL_ERROR;

    const verify_operation = operation.Verify.init(
        mechanism.?.mechanism,
        public_key,
    ) catch |err|
        return pkcs_error.toRV(err);

    current_session.operation = operation.Operation{
        .verify = verify_operation,
    };

    return pkcs.CKR_OK;
}

pub export fn C_Verify(
    session_handle: pkcs.CK_SESSION_HANDLE,
    data: ?[*]const pkcs.CK_BYTE,
    data_len: pkcs.CK_ULONG,
    signature: ?[*]const pkcs.CK_BYTE,
    signature_len: pkcs.CK_ULONG,
) pkcs.CK_RV {
    state.lock.lockSharedUncancelable(state.io);
    defer state.lock.unlockShared(state.io);

    const current_session = session.getSession(session_handle, false) catch |err|
        return pkcs_error.toRV(err);

    defer current_session.resetOperation();

    current_session.assertOperation(operation.Type.Verify) catch |err|
        return pkcs_error.toRV(err);

    const current_operation = &current_session.operation.verify;

    if (data == null)
        return pkcs.CKR_ARGUMENTS_BAD;

    if (signature == null)
        return pkcs.CKR_ARGUMENTS_BAD;

    if (current_operation.multipart_operation)
        return pkcs.CKR_FUNCTION_CANCELED;

    if (signature_len != current_operation.keySizeBytes())
        return pkcs.CKR_SIGNATURE_LEN_RANGE;

    current_operation.update(current_session.allocator, data.?[0..data_len]) catch
        return pkcs.CKR_HOST_MEMORY;

    current_operation.verify(current_session.allocator, signature.?[0..signature_len]) catch |err|
        return pkcs_error.toRV(err);

    return pkcs.CKR_OK;
}

pub export fn C_VerifyUpdate(
    session_handle: pkcs.CK_SESSION_HANDLE,
    part: ?[*]const pkcs.CK_BYTE,
    part_len: pkcs.CK_ULONG,
) pkcs.CK_RV {
    state.lock.lockSharedUncancelable(state.io);
    defer state.lock.unlockShared(state.io);

    const current_session = session.getSession(session_handle, false) catch |err|
        return pkcs_error.toRV(err);

    current_session.assertOperation(operation.Type.Verify) catch |err|
        return pkcs_error.toRV(err);

    const current_operation = &current_session.operation.verify;

    if (part == null) {
        current_session.resetOperation();
        return pkcs.CKR_ARGUMENTS_BAD;
    }

    current_operation.multipart_operation = true;
    current_operation.update(current_session.allocator, part.?[0..part_len]) catch
        return pkcs.CKR_HOST_MEMORY;

    return pkcs.CKR_OK;
}

pub export fn C_VerifyFinal(
    session_handle: pkcs.CK_SESSION_HANDLE,
    signature: ?[*]const pkcs.CK_BYTE,
    signature_len: pkcs.CK_ULONG,
) pkcs.CK_RV {
    state.lock.lockSharedUncancelable(state.io);
    defer state.lock.unlockShared(state.io);

    const current_session = session.getSession(session_handle, false) catch |err|
        return pkcs_error.toRV(err);

    defer current_session.resetOperation();

    current_session.assertOperation(operation.Type.Verify) catch |err|
        return pkcs_error.toRV(err);

    const current_operation = &current_session.operation.verify;

    if (signature == null)
        return pkcs.CKR_ARGUMENTS_BAD;

    if (signature_len != current_operation.keySizeBytes())
        return pkcs.CKR_SIGNATURE_LEN_RANGE;

    current_operation.verify(current_session.allocator, signature.?[0..signature_len]) catch |err|
        return pkcs_error.toRV(err);

    return pkcs.CKR_OK;
}

pub export fn C_VerifyRecoverInit(
    session_handle: pkcs.CK_SESSION_HANDLE,
    mechanism: ?*pkcs.CK_MECHANISM,
    key: pkcs.CK_OBJECT_HANDLE,
) pkcs.CK_RV {
    _ = session_handle;
    _ = mechanism;
    _ = key;

    return pkcs.CKR_FUNCTION_NOT_SUPPORTED;
}

pub export fn C_VerifyRecover(
    session_handle: pkcs.CK_SESSION_HANDLE,
    signature: ?[*]const pkcs.CK_BYTE,
    signature_len: pkcs.CK_ULONG,
    data: ?[*]pkcs.CK_BYTE,
    data_len: ?*pkcs.CK_ULONG,
) pkcs.CK_RV {
    _ = session_handle;
    _ = signature;
    _ = signature_len;
    _ = data;
    _ = data_len;

    return pkcs.CKR_FUNCTION_NOT_SUPPORTED;
}
