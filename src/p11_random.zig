const std = @import("std");

const pkcs = @import("pkcs.zig");
const pkcs_error = @import("pkcs_error.zig");
const state = @import("state.zig");
const session = @import("session.zig");

// not supported in the original module
pub export fn C_SeedRandom(
    session_handle: pkcs.CK_SESSION_HANDLE,
    _: [*c]pkcs.CK_BYTE,
    _: pkcs.CK_ULONG,
) pkcs.CK_RV {
    state.lock.lockShared(state.io) catch
        return pkcs.CKR_FUNCTION_FAILED;
    defer state.lock.unlockShared(state.io);

    _ = session.getSession(session_handle, false) catch |err|
        return pkcs_error.toRV(err);

    return pkcs.CKR_RANDOM_SEED_NOT_SUPPORTED;
}

pub export fn C_GenerateRandom(
    session_handle: pkcs.CK_SESSION_HANDLE,
    random_data: [*c]pkcs.CK_BYTE,
    random_size: pkcs.CK_ULONG,
) pkcs.CK_RV {
    state.lock.lockShared(state.io) catch
        return pkcs.CKR_FUNCTION_FAILED;
    defer state.lock.unlockShared(state.io);

    const current_session = session.getSession(session_handle, false) catch |err|
        return pkcs_error.toRV(err);

    if (random_data == null)
        return pkcs.CKR_ARGUMENTS_BAD;

    var i: c_ulong = 0;
    var remaining_size = random_size;
    while (i < random_size) {
        const segment_size: u8 = @min(128, remaining_size);

        const segment = current_session.card.readRandom(current_session.allocator, segment_size) catch |err|
            return pkcs_error.toRV(err);
        defer current_session.allocator.free(segment);

        if (segment.len < segment_size + 2)
            return pkcs.CKR_DEVICE_ERROR;

        @memcpy(random_data[i .. i + segment_size], segment[0..segment_size]);

        i += segment_size;
        remaining_size -= segment_size;
    }

    return pkcs.CKR_OK;
}
