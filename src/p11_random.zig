const std = @import("std");

const pkcs = @import("pkcs.zig");
const state = @import("state.zig");
const session = @import("session.zig");

// not supported in the original module
pub fn seedRandom(
    session_handle: pkcs.CK_SESSION_HANDLE,
    _: ?[*]pkcs.CK_BYTE,
    _: pkcs.CK_ULONG,
) error{
    CryptokiNotInitialized,
    FunctionFailed,
    RandomSeedNotSupported,
    SessionHandleInvalid,
}!void {
    state.lock.lockSharedUncancelable(state.io);
    defer state.lock.unlockShared(state.io);

    _ = try session.getSession(session_handle, false);

    return error.RandomSeedNotSupported;
}

pub fn generateRandom(
    session_handle: pkcs.CK_SESSION_HANDLE,
    random_data: ?[*]pkcs.CK_BYTE,
    random_size: pkcs.CK_ULONG,
) error{
    ArgumentsBad,
    CryptokiNotInitialized,
    DeviceError,
    DeviceRemoved,
    FunctionFailed,
    GeneralError,
    HostMemory,
    SessionHandleInvalid,
}!void {
    state.lock.lockSharedUncancelable(state.io);
    defer state.lock.unlockShared(state.io);

    const max_length: comptime_int = 128;

    var response_buffer: [max_length + 2]u8 = undefined;
    defer std.crypto.secureZero(u8, &response_buffer);

    const current_session = try session.getSession(session_handle, false);

    if (random_data == null)
        return error.ArgumentsBad;

    const tx = try current_session.card.startTransaction();
    defer current_session.card.endTransaction(tx);

    var i: usize = 0;
    var remaining_size = random_size;
    while (i < random_size) {
        const segment_size: u8 = @min(max_length, remaining_size);

        const segment = try current_session.card.readRandom(current_session.allocator, segment_size, &response_buffer);

        if (segment.len < segment_size + 2)
            return error.DeviceError;

        @memcpy(random_data.?[i .. i + segment_size], segment[0..segment_size]);

        i += segment_size;
        remaining_size -= segment_size;
    }
}
