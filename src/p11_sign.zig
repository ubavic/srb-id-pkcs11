const std = @import("std");

const pkcs_error = @import("pkcs_error.zig");
const state = @import("state.zig");
const session = @import("session.zig");
const hasher = @import("hasher.zig");

const pkcs = @cImport({
    @cInclude("pkcs.h");
});

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
                .private_key => {
                    if (std.mem.indexOfScalar(pkcs.CK_MECHANISM_TYPE, current_object.private_key.allowed_mechanisms, mechanism.?.*.mechanism) == null)
                        return pkcs.CKR_KEY_TYPE_INCONSISTENT;

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

    current_session.operation_key = key;
    current_session.operation = session.Operation.Sign;

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

    current_session.assertOperation(session.Operation.Sign) catch |err|
        return pkcs_error.toRV(err);

    if (current_session.multipart_operation) {
        current_session.resetSignSession();
        return pkcs.CKR_FUNCTION_CANCELED;
    }

    if (signature_len == null) {
        current_session.resetSignSession();
        return pkcs.CKR_ARGUMENTS_BAD;
    }

    const required_signature_size = current_session.signatureSize();
    if (signature == null) {
        signature_len.?.* = required_signature_size;
        return pkcs.CKR_OK;
    }

    if (data == null) {
        current_session.resetSignSession();
        return pkcs.CKR_ARGUMENTS_BAD;
    }

    if (signature_len.?.* < required_signature_size)
        return pkcs.CKR_BUFFER_TOO_SMALL;

    current_session.signUpdate(data.?[0..data_len]);
    const computed_signature = current_session.signFinalize() catch {
        current_session.resetSignSession();
        return pkcs.CKR_HOST_MEMORY;
    };
    defer current_session.allocator.free(computed_signature);

    @memcpy(signature.?, computed_signature);

    current_session.resetSignSession();

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

    current_session.assertOperation(session.Operation.Sign) catch |err|
        return pkcs_error.toRV(err);

    if (part == null) {
        current_session.resetSignSession();
        return pkcs.CKR_ARGUMENTS_BAD;
    }

    current_session.multipart_operation = true;
    current_session.signUpdate(part.?[0..part_len]);

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

    current_session.assertOperation(session.Operation.Sign) catch |err|
        return pkcs_error.toRV(err);

    const required_signature_size = current_session.signatureSize();
    if (signature == null) {
        signature_len.?.* = required_signature_size;
        return pkcs.CKR_OK;
    }

    if (signature_len.?.* < required_signature_size)
        return pkcs.CKR_BUFFER_TOO_SMALL;

    defer current_session.resetSignSession();

    const computed_signature = current_session.signFinalize() catch
        return pkcs.CKR_HOST_MEMORY;

    @memcpy(signature.?, computed_signature);
    current_session.allocator.free(computed_signature);

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
