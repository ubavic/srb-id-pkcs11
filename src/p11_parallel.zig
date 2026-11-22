const pkcs = @import("pkcs.zig");

pub fn getFunctionStatus(
    _: anytype,
    _: pkcs.CK_SESSION_HANDLE,
) error{
    FunctionNotParallel,
}!void {
    return error.FunctionNotParallel;
}

pub fn cancelFunction(
    _: anytype,
    _: pkcs.CK_SESSION_HANDLE,
) error{
    FunctionNotParallel,
}!void {
    return error.FunctionNotParallel;
}
