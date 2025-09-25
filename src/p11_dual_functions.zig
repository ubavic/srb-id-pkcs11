const pkcs = @import("pkcs.zig").pkcs;

pub export fn C_DigestEncryptUpdate(
    session_handle: pkcs.CK_SESSION_HANDLE,
    part: ?[*]const pkcs.CK_BYTE,
    part_len: pkcs.CK_ULONG,
    encrypted_part: ?[*]pkcs.CK_BYTE,
    encrypted_part_len: ?*pkcs.CK_ULONG,
) pkcs.CK_RV {
    _ = session_handle;
    _ = part;
    _ = part_len;
    _ = encrypted_part;
    _ = encrypted_part_len;
    return pkcs.CKR_FUNCTION_NOT_SUPPORTED;
}

pub export fn C_DecryptDigestUpdate(
    session_handle: pkcs.CK_SESSION_HANDLE,
    encrypted_part: ?[*]const pkcs.CK_BYTE,
    encrypted_part_len: pkcs.CK_ULONG,
    part: ?[*]pkcs.CK_BYTE,
    part_len: ?*pkcs.CK_ULONG,
) pkcs.CK_RV {
    _ = session_handle;
    _ = encrypted_part;
    _ = encrypted_part_len;
    _ = part;
    _ = part_len;
    return pkcs.CKR_FUNCTION_NOT_SUPPORTED;
}

pub export fn C_SignEncryptUpdate(
    session_handle: pkcs.CK_SESSION_HANDLE,
    part: ?[*]const pkcs.CK_BYTE,
    part_len: pkcs.CK_ULONG,
    encrypted_part: ?[*]pkcs.CK_BYTE,
    encrypted_part_len: ?*pkcs.CK_ULONG,
) pkcs.CK_RV {
    _ = session_handle;
    _ = part;
    _ = part_len;
    _ = encrypted_part;
    _ = encrypted_part_len;
    return pkcs.CKR_FUNCTION_NOT_SUPPORTED;
}

pub export fn C_DecryptVerifyUpdate(
    session_handle: pkcs.CK_SESSION_HANDLE,
    encrypted_part: ?[*]const pkcs.CK_BYTE,
    encrypted_part_len: pkcs.CK_ULONG,
    part: ?[*]pkcs.CK_BYTE,
    part_len: ?*pkcs.CK_ULONG,
) pkcs.CK_RV {
    _ = session_handle;
    _ = encrypted_part;
    _ = encrypted_part_len;
    _ = part;
    _ = part_len;
    return pkcs.CKR_FUNCTION_NOT_SUPPORTED;
}
