const pkcs = @import("pkcs.zig");

const State = @import("ModuleState.zig");

pub fn getFunctionStatus(
    _: *State,
    _: pkcs.CK_SESSION_HANDLE,
) error{
    FunctionNotParallel,
}!void {
    return error.FunctionNotParallel;
}

pub fn cancelFunction(
    _: *State,
    _: pkcs.CK_SESSION_HANDLE,
) error{
    FunctionNotParallel,
}!void {
    return error.FunctionNotParallel;
}
