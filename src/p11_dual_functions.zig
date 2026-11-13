const pkcs = @import("pkcs.zig");
const State = @import("ModuleState.zig");

pub fn digestEncryptUpdate(
    _: *State,
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
    _: *State,
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
    _: *State,
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
    _: *State,
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
