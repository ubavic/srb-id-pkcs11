const pkcs = @import("pkcs.zig");

pub fn digestEncryptUpdate(
    _: pkcs.CK_SESSION_HANDLE,
    _: ?[*]const pkcs.CK_BYTE,
    _: pkcs.CK_ULONG,
    _: ?[*]pkcs.CK_BYTE,
    _: ?*pkcs.CK_ULONG,
) error{
    FunctionNotSupported,
}!void {
    return error.FunctionNotSupported;
}

pub fn decryptDigestUpdate(
    _: pkcs.CK_SESSION_HANDLE,
    _: ?[*]const pkcs.CK_BYTE,
    _: pkcs.CK_ULONG,
    _: ?[*]pkcs.CK_BYTE,
    _: ?*pkcs.CK_ULONG,
) error{
    FunctionNotSupported,
}!void {
    return error.FunctionNotSupported;
}

pub fn signEncryptUpdate(
    _: pkcs.CK_SESSION_HANDLE,
    _: ?[*]const pkcs.CK_BYTE,
    _: pkcs.CK_ULONG,
    _: ?[*]pkcs.CK_BYTE,
    _: ?*pkcs.CK_ULONG,
) error{
    FunctionNotSupported,
}!void {
    return error.FunctionNotSupported;
}

pub fn decryptVerifyUpdate(
    _: pkcs.CK_SESSION_HANDLE,
    _: ?[*]const pkcs.CK_BYTE,
    _: pkcs.CK_ULONG,
    _: ?[*]pkcs.CK_BYTE,
    _: ?*pkcs.CK_ULONG,
) error{
    FunctionNotSupported,
}!void {
    return error.FunctionNotSupported;
}
