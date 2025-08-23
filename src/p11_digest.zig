const std = @import("std");

const pkcs = @cImport({
    @cInclude("pkcs.h");
});

const pkcs_error = @import("pkcs_error.zig");
const state = @import("state.zig");
const session = @import("session.zig");
const hasher = @import("hasher.zig");

pub export fn digestInit(
    session_handle: pkcs.CK_SESSION_HANDLE,
    mechanism: ?*pkcs.CK_MECHANISM,
) pkcs.CK_RV {
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

    current_session.hasher = hasher.createAndInit(hash_mechanism, current_session.allocator) catch
        return pkcs.CKR_HOST_MEMORY;

    current_session.operation = session.Operation.Digest;

    return pkcs.CKR_OK;
}

pub export fn digest(
    session_handle: pkcs.CK_SESSION_HANDLE,
    data: ?[*]pkcs.CK_BYTE,
    data_len: pkcs.CK_ULONG,
    data_digest: ?[*]pkcs.CK_BYTE,
    data_digest_len: ?*pkcs.CK_ULONG,
) pkcs.CK_RV {
    const current_session = session.getSession(session_handle, false) catch |err|
        return pkcs_error.toRV(err);

    current_session.assertOperation(session.Operation.Digest) catch |err|
        return pkcs_error.toRV(err);

    if (current_session.multipart_operation) {
        current_session.resetDigestSession();
        return pkcs.CKR_FUNCTION_CANCELED;
    }

    if (data_digest_len == null) {
        current_session.resetDigestSession();
        return pkcs.CKR_ARGUMENTS_BAD;
    }

    const required_digest_size = current_session.hasher.digestLength();
    if (data_digest == null) {
        data_digest_len.?.* = required_digest_size;
        return pkcs.CKR_OK;
    }

    if (data == null) {
        current_session.resetDigestSession();
        return pkcs.CKR_ARGUMENTS_BAD;
    }

    if (data_digest_len.?.* < required_digest_size)
        return pkcs.CKR_BUFFER_TOO_SMALL;

    const casted_data: [*]u8 = @ptrCast(data);

    current_session.hasher.update(casted_data[0..data_len]);
    const computed_digest = current_session.hasher.finalize(current_session.allocator) catch {
        current_session.resetDigestSession();
        return pkcs.CKR_HOST_MEMORY;
    };

    const data_digest_casted: [*]u8 = @ptrCast(data_digest);

    @memcpy(data_digest_casted, computed_digest);
    current_session.allocator.free(computed_digest);

    current_session.resetDigestSession();

    return pkcs.CKR_OK;
}

pub export fn digestUpdate(
    session_handle: pkcs.CK_SESSION_HANDLE,
    part: ?[*]pkcs.CK_BYTE,
    part_len: pkcs.CK_ULONG,
) pkcs.CK_RV {
    const current_session = session.getSession(session_handle, false) catch |err|
        return pkcs_error.toRV(err);

    current_session.assertOperation(session.Operation.Digest) catch |err|
        return pkcs_error.toRV(err);

    if (part == null) {
        current_session.resetDigestSession();
        return pkcs.CKR_ARGUMENTS_BAD;
    }

    current_session.multipart_operation = true;

    const casted_part: [*]u8 = @ptrCast(part);
    current_session.hasher.update(casted_part[0..part_len]);

    return pkcs.CKR_OK;
}

pub export fn digestKey(
    session_handle: pkcs.CK_SESSION_HANDLE,
    key: pkcs.CK_OBJECT_HANDLE,
) pkcs.CK_RV {
    _ = session_handle;
    _ = key;

    return pkcs.CKR_FUNCTION_NOT_SUPPORTED;
}

pub export fn digestFinal(
    session_handle: pkcs.CK_SESSION_HANDLE,
    data_digest: ?[*]pkcs.CK_BYTE,
    data_digest_len: ?*pkcs.CK_ULONG,
) pkcs.CK_RV {
    const current_session = session.getSession(session_handle, false) catch |err|
        return pkcs_error.toRV(err);

    current_session.assertOperation(session.Operation.Digest) catch |err|
        return pkcs_error.toRV(err);

    const required_digest_size = current_session.hasher.digestLength();
    if (data_digest == null) {
        data_digest_len.?.* = required_digest_size;
        return pkcs.CKR_OK;
    }

    if (data_digest_len.?.* < required_digest_size)
        return pkcs.CKR_BUFFER_TOO_SMALL;

    const computed_digest = current_session.hasher.finalize(current_session.allocator) catch {
        current_session.resetDigestSession();
        return pkcs.CKR_HOST_MEMORY;
    };

    const data_digest_casted: [*]u8 = @ptrCast(data_digest);

    @memcpy(data_digest_casted, computed_digest);
    current_session.allocator.free(computed_digest);

    current_session.resetDigestSession();

    return pkcs.CKR_OK;
}
