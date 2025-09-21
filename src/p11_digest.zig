const std = @import("std");

const pkcs = @cImport({
    @cInclude("pkcs.h");
});

const operation = @import("operation.zig");
const pkcs_error = @import("pkcs_error.zig");
const state = @import("state.zig");
const session = @import("session.zig");
const hasher = @import("hasher.zig");

pub export fn C_DigestInit(
    session_handle: pkcs.CK_SESSION_HANDLE,
    mechanism: ?*pkcs.CK_MECHANISM,
) pkcs.CK_RV {
    state.lock.lockShared();
    defer state.lock.unlockShared();

    const current_session = session.getSession(session_handle, false) catch |err|
        return pkcs_error.toRV(err);

    if (mechanism == null)
        return pkcs.CKR_ARGUMENTS_BAD;

    var hash_mechanism: hasher.HasherType = undefined;

    switch (mechanism.?.*.mechanism) {
        pkcs.CKM_MD5 => {
            hash_mechanism = hasher.HasherType.md5;
        },
        pkcs.CKM_SHA_1 => {
            hash_mechanism = hasher.HasherType.sha1;
        },
        pkcs.CKM_SHA256 => {
            hash_mechanism = hasher.HasherType.sha256;
        },
        pkcs.CKM_SHA384 => {
            hash_mechanism = hasher.HasherType.sha384;
        },
        pkcs.CKM_SHA512 => {
            hash_mechanism = hasher.HasherType.sha512;
        },
        else => {
            return pkcs.CKR_MECHANISM_INVALID;
        },
    }

    current_session.assertNoOperation() catch |err|
        return pkcs_error.toRV(err);

    const hash = hasher.createAndInit(hash_mechanism, current_session.allocator) catch
        return pkcs.CKR_HOST_MEMORY;

    current_session.operation = operation.Operation{
        .digest = operation.Digest{
            .hasher = hash,
            .multipart_operation = false,
        },
    };

    return pkcs.CKR_OK;
}

pub export fn C_Digest(
    session_handle: pkcs.CK_SESSION_HANDLE,
    data: ?[*]pkcs.CK_BYTE,
    data_len: pkcs.CK_ULONG,
    data_digest: ?[*]pkcs.CK_BYTE,
    data_digest_len: ?*pkcs.CK_ULONG,
) pkcs.CK_RV {
    state.lock.lockShared();
    defer state.lock.unlockShared();

    const current_session = session.getSession(session_handle, false) catch |err|
        return pkcs_error.toRV(err);

    current_session.assertOperation(operation.Type.Digest) catch |err|
        return pkcs_error.toRV(err);

    const current_operation = &current_session.operation.digest;

    if (current_operation.multipart_operation) {
        current_session.resetOperation();
        return pkcs.CKR_FUNCTION_CANCELED;
    }

    if (data_digest_len == null) {
        current_session.resetOperation();
        return pkcs.CKR_ARGUMENTS_BAD;
    }

    const required_digest_size = current_operation.hasher.digestLength();
    if (data_digest == null) {
        data_digest_len.?.* = required_digest_size;
        return pkcs.CKR_OK;
    }

    if (data == null) {
        current_session.resetOperation();
        return pkcs.CKR_ARGUMENTS_BAD;
    }

    if (data_digest_len.?.* < required_digest_size)
        return pkcs.CKR_BUFFER_TOO_SMALL;

    current_operation.hasher.update(data.?[0..data_len]);
    const computed_digest = current_operation.hasher.finalize(current_session.allocator) catch {
        current_session.resetOperation();
        return pkcs.CKR_HOST_MEMORY;
    };

    @memcpy(data_digest.?, computed_digest);
    current_session.allocator.free(computed_digest);

    current_session.resetOperation();

    return pkcs.CKR_OK;
}

pub export fn C_DigestUpdate(
    session_handle: pkcs.CK_SESSION_HANDLE,
    part: ?[*]pkcs.CK_BYTE,
    part_len: pkcs.CK_ULONG,
) pkcs.CK_RV {
    state.lock.lockShared();
    defer state.lock.unlockShared();

    const current_session = session.getSession(session_handle, false) catch |err|
        return pkcs_error.toRV(err);

    current_session.assertOperation(operation.Type.Digest) catch |err|
        return pkcs_error.toRV(err);

    const current_operation = &current_session.operation.digest;

    if (part == null) {
        current_session.resetOperation();
        return pkcs.CKR_ARGUMENTS_BAD;
    }

    current_operation.multipart_operation = true;
    current_operation.hasher.update(part.?[0..part_len]);

    return pkcs.CKR_OK;
}

pub export fn C_DigestKey(
    session_handle: pkcs.CK_SESSION_HANDLE,
    key: pkcs.CK_OBJECT_HANDLE,
) pkcs.CK_RV {
    _ = session_handle;
    _ = key;

    return pkcs.CKR_FUNCTION_NOT_SUPPORTED;
}

pub export fn C_DigestFinal(
    session_handle: pkcs.CK_SESSION_HANDLE,
    data_digest: ?[*]pkcs.CK_BYTE,
    data_digest_len: ?*pkcs.CK_ULONG,
) pkcs.CK_RV {
    state.lock.lockShared();
    defer state.lock.unlockShared();

    const current_session = session.getSession(session_handle, false) catch |err|
        return pkcs_error.toRV(err);

    current_session.assertOperation(operation.Type.Digest) catch |err|
        return pkcs_error.toRV(err);

    var current_operation = &current_session.operation.digest;

    const required_digest_size = current_operation.hasher.digestLength();
    if (data_digest == null) {
        data_digest_len.?.* = required_digest_size;
        return pkcs.CKR_OK;
    }

    if (data_digest_len.?.* < required_digest_size)
        return pkcs.CKR_BUFFER_TOO_SMALL;

    defer current_session.resetOperation();

    const computed_digest = current_operation.hasher.finalize(current_session.allocator) catch
        return pkcs.CKR_HOST_MEMORY;

    @memcpy(data_digest.?, computed_digest);
    current_session.allocator.free(computed_digest);

    return pkcs.CKR_OK;
}
