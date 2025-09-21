const std = @import("std");

const operation = @import("operation.zig");
const pkcs_error = @import("pkcs_error.zig");
const state = @import("state.zig");
const session = @import("session.zig");
const hasher = @import("hasher.zig");

const pkcs = @cImport({
    @cInclude("pkcs.h");
});

pub export fn C_VerifyInit(
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

    const hash_mechanism = hasher.fromMechanism(mechanism.?.mechanism) catch |err|
        return pkcs_error.toRV(err);

    var hash: ?hasher.Hasher = null;
    if (hash_mechanism != null) {
        hash = hasher.createAndInit(hash_mechanism.?, current_session.allocator) catch
            return pkcs.CKR_HOST_MEMORY;
    } else return pkcs.CKR_MECHANISM_INVALID; // TODO

    var key_found = false;
    for (current_session.objects) |current_object| {
        if (current_object.handle() == key) {
            switch (current_object) {
                .public_key => {
                    // if (std.mem.indexOfScalar(pkcs.CK_MECHANISM_TYPE, current_object.public_key.allowed_mechanisms, mechanism.?.*.mechanism) == null)
                    //    return pkcs.CKR_KEY_TYPE_INCONSISTENT;

                    if (current_object.public_key.verify != pkcs.CK_TRUE)
                        return pkcs.CKR_KEY_FUNCTION_NOT_PERMITTED;
                },
                .certificate, .private_key => return pkcs.CKR_KEY_HANDLE_INVALID,
            }

            key_found = true;
            break;
        }
    }

    if (!key_found)
        return pkcs.CKR_KEY_HANDLE_INVALID;

    current_session.operation = operation.Operation{
        .verify = operation.Verify{
            .hasher = hash,
            .multipart_operation = false,
            .private_key = key,
        },
    };

    return pkcs.CKR_FUNCTION_NOT_SUPPORTED;
}

pub export fn C_Verify(
    session_handle: pkcs.CK_SESSION_HANDLE,
    data: ?[*]const pkcs.CK_BYTE,
    data_len: pkcs.CK_ULONG,
    signature: ?[*]const pkcs.CK_BYTE,
    signature_len: pkcs.CK_ULONG,
) pkcs.CK_RV {
    state.lock.lockShared();
    defer state.lock.unlockShared();

    const current_session = session.getSession(session_handle, true) catch |err|
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

    if (signature_len != current_operation.signatureSize())
        return pkcs.CKR_SIGNATURE_LEN_RANGE;

    current_operation.update(data.?[0..data_len]);

    const sign_request = current_operation.createSignRequest(current_session.allocator) catch
        return pkcs.CKR_HOST_MEMORY;
    defer current_session.allocator.free(sign_request);

    const computed_signature = current_session.card.sign(0x0, sign_request) catch |err|
        return pkcs_error.toRV(err);
    defer current_session.allocator.free(computed_signature);

    if (!std.mem.eql(u8, computed_signature, signature.?[0..signature_len]))
        return pkcs.CKR_SIGNATURE_INVALID;

    return pkcs.CKR_OK;
}

pub export fn C_VerifyUpdate(
    session_handle: pkcs.CK_SESSION_HANDLE,
    part: ?[*]const pkcs.CK_BYTE,
    part_len: pkcs.CK_ULONG,
) pkcs.CK_RV {
    state.lock.lockShared();
    defer state.lock.unlockShared();

    const current_session = session.getSession(session_handle, true) catch |err|
        return pkcs_error.toRV(err);

    current_session.assertOperation(operation.Type.Verify) catch |err|
        return pkcs_error.toRV(err);

    const current_operation = &current_session.operation.verify;

    if (part == null) {
        current_session.resetOperation();
        return pkcs.CKR_ARGUMENTS_BAD;
    }

    current_operation.multipart_operation = true;
    current_operation.update(part.?[0..part_len]);

    return pkcs.CKR_OK;
}

pub export fn C_VerifyFinal(
    session_handle: pkcs.CK_SESSION_HANDLE,
    signature: ?[*]const pkcs.CK_BYTE,
    signature_len: pkcs.CK_ULONG,
) pkcs.CK_RV {
    state.lock.lockShared();
    defer state.lock.unlockShared();

    const current_session = session.getSession(session_handle, true) catch |err|
        return pkcs_error.toRV(err);

    defer current_session.resetOperation();

    current_session.assertOperation(operation.Type.Verify) catch |err|
        return pkcs_error.toRV(err);

    const current_operation = &current_session.operation.verify;

    if (signature == null)
        return pkcs.CKR_ARGUMENTS_BAD;

    if (signature_len != current_operation.signatureSize())
        return pkcs.CKR_SIGNATURE_LEN_RANGE;

    const sign_request = current_operation.createSignRequest(current_session.allocator) catch
        return pkcs.CKR_HOST_MEMORY;
    defer current_session.allocator.free(sign_request);

    const computed_signature = current_session.card.sign(0x0, sign_request) catch |err|
        return pkcs_error.toRV(err);
    defer current_session.allocator.free(computed_signature);

    if (!std.mem.eql(u8, computed_signature, signature.?[0..signature_len]))
        return pkcs.CKR_SIGNATURE_INVALID;

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
