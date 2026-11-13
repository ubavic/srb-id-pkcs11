const std = @import("std");
const pcsc = @import("pcsc");

const pkcs = @import("pkcs.zig");
const reader = @import("smart-card/reader.zig");
const session = @import("session/session.zig");
const State = @import("ModuleState.zig");
const version = @import("options").version;

pub fn initialize(
    state: *State,
    init_args: pkcs.CK_VOID_PTR,
) error{
    ArgumentsBad,
    CantLock,
    CryptokiAlreadyInitialized,
    FunctionFailed,
}!void {
    if (!state.lock.tryLock(state.io))
        return error.FunctionFailed;
    defer state.lock.unlock(state.io);

    if (!reader.lock.tryLock(state.io))
        return error.FunctionFailed;
    defer reader.lock.unlock(state.io);

    if (state.initialized)
        return error.CryptokiAlreadyInitialized;

    if (init_args != null) {
        const args: *pkcs.CK_C_INITIALIZE_ARGS = @ptrCast(@alignCast(init_args));

        if (args.*.pReserved != null)
            return error.ArgumentsBad;

        const someNotNull = (args.*.CreateMutex != null) or (args.*.DestroyMutex != null) or (args.*.LockMutex != null) or (args.*.UnlockMutex != null);
        const someNull = (args.*.CreateMutex == null) or (args.*.DestroyMutex == null) or (args.*.LockMutex == null) or (args.*.UnlockMutex == null);

        if (someNotNull and someNull)
            return error.ArgumentsBad;

        if (someNotNull) {
            if (args.*.flags & pkcs.CKF_OS_LOCKING_OK == 0)
                return error.CantLock;
        }
    }

    state.smart_card_client = pcsc.Client.init(.USER) catch
        return error.FunctionFailed;

    reader.reader_states = std.AutoHashMap(pkcs.CK_SLOT_ID, reader.ReaderState).init(state.allocator);
    try session.initSessions(state.allocator, state.io);

    state.initialized = true;
}

pub fn finalize(
    state: *State,
    reserved: pkcs.CK_VOID_PTR,
) error{
    ArgumentsBad,
    CryptokiNotInitialized,
    FunctionFailed,
}!void {
    if (!state.lock.tryLock(state.io))
        return error.FunctionFailed;
    defer state.lock.unlock(state.io);

    if (reserved != null)
        return error.ArgumentsBad;

    if (!state.initialized)
        return error.CryptokiNotInitialized;

    state.smart_card_client.deinit() catch
        return error.FunctionFailed;

    reader.deinit(state.allocator);

    state.initialized = false;
}

pub fn getInfo(
    state: *State,
    info: ?*pkcs.CK_INFO,
) error{
    ArgumentsBad,
    CryptokiNotInitialized,
}!void {
    state.lock.lockSharedUncancelable(state.io);
    defer state.lock.unlockShared(state.io);

    if (!state.initialized)
        return error.CryptokiNotInitialized;

    if (info == null)
        return error.ArgumentsBad;

    info.?.cryptokiVersion.major = pkcs.CRYPTOKI_VERSION_MAJOR;
    info.?.cryptokiVersion.minor = pkcs.CRYPTOKI_VERSION_MINOR;
    info.?.flags = 0;
    info.?.libraryVersion.major = version.major;
    info.?.libraryVersion.minor = version.minor;

    @memset(&info.?.libraryDescription, 0x20);
    std.mem.copyForwards(u8, &info.?.libraryDescription, "Module for Serbian eID cards");

    @memset(&info.?.manufacturerID, 0x20);
    std.mem.copyForwards(u8, &info.?.manufacturerID, "Nikola Ubavic");
}
