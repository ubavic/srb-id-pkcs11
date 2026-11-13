const pkcs = @import("pkcs.zig");

const State = @import("ModuleState.zig");

pub fn generateKey(
    _: *State,
    _: pkcs.CK_SESSION_HANDLE,
    _: ?*pkcs.CK_MECHANISM,
    _: ?[*]pkcs.CK_ATTRIBUTE,
    _: pkcs.CK_ULONG,
    _: ?*pkcs.CK_OBJECT_HANDLE,
) error{
    FunctionNotSupported,
}!void {
    return error.FunctionNotSupported;
}

pub fn generateKeyPair(
    _: *State,
    _: pkcs.CK_SESSION_HANDLE,
    _: ?*pkcs.CK_MECHANISM,
    _: ?[*]pkcs.CK_ATTRIBUTE,
    _: pkcs.CK_ULONG,
    _: ?[*]pkcs.CK_ATTRIBUTE,
    _: pkcs.CK_ULONG,
    _: ?*pkcs.CK_OBJECT_HANDLE,
    _: ?*pkcs.CK_OBJECT_HANDLE,
) error{
    FunctionNotSupported,
}!void {
    return error.FunctionNotSupported;
}

pub fn deriveKey(
    _: *State,
    _: pkcs.CK_SESSION_HANDLE,
    _: ?*pkcs.CK_MECHANISM,
    _: pkcs.CK_OBJECT_HANDLE,
    _: ?[*]pkcs.CK_ATTRIBUTE,
    _: pkcs.CK_ULONG,
    _: ?*pkcs.CK_OBJECT_HANDLE,
) error{
    FunctionNotSupported,
}!void {
    return error.FunctionNotSupported;
}

// not supported in the original module
pub fn wrapKey(
    _: *State,
    _: pkcs.CK_SESSION_HANDLE,
    _: ?*pkcs.CK_MECHANISM,
    _: pkcs.CK_OBJECT_HANDLE,
    _: pkcs.CK_OBJECT_HANDLE,
    _: ?[*]pkcs.CK_BYTE,
    _: ?*pkcs.CK_ULONG,
) error{
    FunctionNotSupported,
}!void {
    return error.FunctionNotSupported;
}

// not supported in the original module
pub fn unwrapKey(
    _: *State,
    _: pkcs.CK_SESSION_HANDLE,
    _: ?*pkcs.CK_MECHANISM,
    _: pkcs.CK_OBJECT_HANDLE,
    _: ?[*]const pkcs.CK_BYTE,
    _: pkcs.CK_ULONG,
    _: ?[*]pkcs.CK_ATTRIBUTE,
    _: pkcs.CK_ULONG,
    _: ?*pkcs.CK_OBJECT_HANDLE,
) error{
    FunctionNotSupported,
}!void {
    return error.FunctionNotSupported;
}
