const pkcs = @cImport({
    @cInclude("pkcs.h");
});

pub export fn C_GenerateKey(
    session_handle: pkcs.CK_SESSION_HANDLE,
    mechanism: ?*pkcs.CK_MECHANISM,
    template: ?[*]pkcs.CK_ATTRIBUTE,
    count: pkcs.CK_ULONG,
    key_handle: ?*pkcs.CK_OBJECT_HANDLE,
) pkcs.CK_RV {
    _ = session_handle;
    _ = mechanism;
    _ = template;
    _ = count;
    _ = key_handle;
    return pkcs.CKR_FUNCTION_NOT_SUPPORTED;
}

pub export fn C_GenerateKeyPair(
    session_handle: pkcs.CK_SESSION_HANDLE,
    mechanism: ?*pkcs.CK_MECHANISM,
    public_key_template: ?[*]pkcs.CK_ATTRIBUTE,
    public_key_attribute_count: pkcs.CK_ULONG,
    private_key_template: ?[*]pkcs.CK_ATTRIBUTE,
    private_key_attribute_count: pkcs.CK_ULONG,
    public_key_handle: ?*pkcs.CK_OBJECT_HANDLE,
    private_key_handle: ?*pkcs.CK_OBJECT_HANDLE,
) pkcs.CK_RV {
    _ = session_handle;
    _ = mechanism;
    _ = public_key_template;
    _ = public_key_attribute_count;
    _ = private_key_template;
    _ = private_key_attribute_count;
    _ = public_key_handle;
    _ = private_key_handle;
    return pkcs.CKR_FUNCTION_NOT_SUPPORTED;
}

pub export fn C_DeriveKey(
    session_handle: pkcs.CK_SESSION_HANDLE,
    mechanism: ?*pkcs.CK_MECHANISM,
    base_key: pkcs.CK_OBJECT_HANDLE,
    template: ?[*]pkcs.CK_ATTRIBUTE,
    attribute_count: pkcs.CK_ULONG,
    key_handle: ?*pkcs.CK_OBJECT_HANDLE,
) pkcs.CK_RV {
    _ = session_handle;
    _ = mechanism;
    _ = base_key;
    _ = template;
    _ = attribute_count;
    _ = key_handle;
    return pkcs.CKR_FUNCTION_NOT_SUPPORTED;
}

// not supported in the original module
pub export fn C_WrapKey(
    _: pkcs.CK_SESSION_HANDLE,
    _: ?*pkcs.CK_MECHANISM,
    _: pkcs.CK_OBJECT_HANDLE,
    _: pkcs.CK_OBJECT_HANDLE,
    _: ?[*]pkcs.CK_BYTE,
    _: ?*pkcs.CK_ULONG,
) pkcs.CK_RV {
    return pkcs.CKR_FUNCTION_NOT_SUPPORTED;
}

// not supported in the original module
pub export fn C_UnwrapKey(
    _: pkcs.CK_SESSION_HANDLE,
    _: ?*pkcs.CK_MECHANISM,
    _: pkcs.CK_OBJECT_HANDLE,
    _: ?[*]const pkcs.CK_BYTE,
    _: pkcs.CK_ULONG,
    _: ?[*]pkcs.CK_ATTRIBUTE,
    _: pkcs.CK_ULONG,
    _: ?*pkcs.CK_OBJECT_HANDLE,
) pkcs.CK_RV {
    return pkcs.CKR_FUNCTION_NOT_SUPPORTED;
}
