const std = @import("std");

const pkcs = @import("pkcs.zig");
const pkcs_error = @import("pkcs_error.zig");
const state = @import("state.zig");
const session = @import("session.zig");

// not supported in the original module
pub export fn C_SeedRandom(
    session_handle: pkcs.CK_SESSION_HANDLE,
    _: ?[*]pkcs.CK_BYTE,
    _: pkcs.CK_ULONG,
) pkcs.CK_RV {
    state.lock.lockSharedUncancelable(state.io);
    defer state.lock.unlockShared(state.io);

    _ = session.getSession(session_handle, false) catch |err|
        return pkcs_error.toRV(err);

    return pkcs.CKR_RANDOM_SEED_NOT_SUPPORTED;
}

pub export fn C_GenerateRandom(
    session_handle: pkcs.CK_SESSION_HANDLE,
    random_data: ?[*]pkcs.CK_BYTE,
    random_size: pkcs.CK_ULONG,
) pkcs.CK_RV {
    state.lock.lockSharedUncancelable(state.io);
    defer state.lock.unlockShared(state.io);

    const max_length: comptime_int = 128;

    var response_buffer: [max_length + 2]u8 = undefined;
    defer std.crypto.secureZero(u8, &response_buffer);

    const current_session = session.getSession(session_handle, false) catch |err|
        return pkcs_error.toRV(err);

    if (random_data == null)
        return pkcs.CKR_ARGUMENTS_BAD;

    var i: c_ulong = 0;
    var remaining_size = random_size;
    while (i < random_size) {
        const segment_size: u8 = @min(max_length, remaining_size);

        const segment = current_session.card.readRandom(current_session.allocator, segment_size, &response_buffer) catch |err|
            return pkcs_error.toRV(err);

        if (segment.len < segment_size + 2)
            return pkcs.CKR_DEVICE_ERROR;

        @memcpy(random_data.?[i .. i + segment_size], segment[0..segment_size]);

        i += segment_size;
        remaining_size -= segment_size;
    }

    return pkcs.CKR_OK;
}
