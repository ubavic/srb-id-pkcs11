const pkcs = @import("pkcs.zig").pkcs;

pub export fn C_DecryptInit(
    session_handle: pkcs.CK_SESSION_HANDLE,
    mechanism: ?*pkcs.CK_MECHANISM,
    key: pkcs.CK_OBJECT_HANDLE,
) pkcs.CK_RV {
    _ = session_handle;
    _ = mechanism;
    _ = key;
    return pkcs.CKR_FUNCTION_NOT_SUPPORTED;
}

pub export fn C_Decrypt(
    session_handle: pkcs.CK_SESSION_HANDLE,
    encrypted_data: ?[*]const pkcs.CK_BYTE,
    encrypted_data_len: pkcs.CK_ULONG,
    data: ?[*]pkcs.CK_BYTE,
    data_len: ?*pkcs.CK_ULONG,
) pkcs.CK_RV {
    _ = session_handle;
    _ = encrypted_data;
    _ = encrypted_data_len;
    _ = data;
    _ = data_len;
    return pkcs.CKR_FUNCTION_NOT_SUPPORTED;
}

pub export fn C_DecryptUpdate(
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

pub export fn C_DecryptFinal(
    session_handle: pkcs.CK_SESSION_HANDLE,
    last_part: ?[*]pkcs.CK_BYTE,
    last_part_len: ?*pkcs.CK_ULONG,
) pkcs.CK_RV {
    _ = session_handle;
    _ = last_part;
    _ = last_part_len;
    return pkcs.CKR_FUNCTION_NOT_SUPPORTED;
}
