const pkcs = @import("pkcs.zig");

pub fn getFunctionStatus(
    _: pkcs.CK_SESSION_HANDLE,
) error{
    FunctionNotParallel,
}!void {
    return error.FunctionNotParallel;
}

pub fn cancelFunction(
    _: pkcs.CK_SESSION_HANDLE,
) error{
    FunctionNotParallel,
}!void {
    return error.FunctionNotParallel;
}
