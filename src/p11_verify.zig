const std = @import("std");

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

    if (hash_mechanism != null) {
        current_session.hasher = hasher.createAndInit(hash_mechanism.?, current_session.allocator) catch
            return pkcs.CKR_HOST_MEMORY;
    } else return pkcs.CKR_MECHANISM_INVALID;

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

    current_session.operation_key = key;
    current_session.operation = session.Operation.Verify;

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
    defer current_session.resetSignSession();

    current_session.assertOperation(session.Operation.Verify) catch |err|
        return pkcs_error.toRV(err);

    if (data == null)
        return pkcs.CKR_ARGUMENTS_BAD;

    if (signature == null)
        return pkcs.CKR_ARGUMENTS_BAD;

    if (current_session.multipart_operation)
        return pkcs.CKR_FUNCTION_CANCELED;

    if (signature_len != current_session.signatureSize())
        return pkcs.CKR_SIGNATURE_LEN_RANGE;

    current_session.signUpdate(data.?[0..data_len]);

    const computed_signature = current_session.signFinalize() catch
        return pkcs.CKR_HOST_MEMORY;
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

    current_session.assertOperation(session.Operation.Verify) catch |err|
        return pkcs_error.toRV(err);

    if (part == null) {
        current_session.resetSignSession();
        return pkcs.CKR_ARGUMENTS_BAD;
    }

    current_session.multipart_operation = true;
    current_session.signUpdate(part.?[0..part_len]);

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

    defer current_session.resetSignSession();

    current_session.assertOperation(session.Operation.Verify) catch |err|
        return pkcs_error.toRV(err);

    if (signature == null)
        return pkcs.CKR_ARGUMENTS_BAD;

    if (signature_len != current_session.signatureSize())
        return pkcs.CKR_SIGNATURE_LEN_RANGE;

    const computed_signature = current_session.signFinalize() catch
        return pkcs.CKR_HOST_MEMORY;
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
