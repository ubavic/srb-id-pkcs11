const std = @import("std");

const pkcs = @import("pkcs.zig").pkcs;
const pkcs_error = @import("pkcs_error.zig");
const state = @import("state.zig");
const session = @import("session.zig");

// not supported in the original module
pub export fn C_SeedRandom(
    session_handle: pkcs.CK_SESSION_HANDLE,
    _: pkcs.CK_BYTE_PTR,
    _: pkcs.CK_ULONG,
) pkcs.CK_RV {
    state.lock.lockShared();
    defer state.lock.unlockShared();

    _ = session.getSession(session_handle, false) catch |err|
        return pkcs_error.toRV(err);

    return pkcs.CKR_RANDOM_SEED_NOT_SUPPORTED;
}

pub export fn C_GenerateRandom(
    session_handle: pkcs.CK_SESSION_HANDLE,
    random_data: [*c]pkcs.CK_BYTE,
    random_size: pkcs.CK_ULONG,
) pkcs.CK_RV {
    state.lock.lockShared();
    defer state.lock.unlockShared();

    const current_session = session.getSession(session_handle, false) catch |err|
        return pkcs_error.toRV(err);

    var i: c_ulong = 0;
    var remaining_size = random_size;
    while (i < random_size) {
        const segment_size: u8 = @min(128, remaining_size);

        const segment = current_session.card.readRandom(current_session.allocator, segment_size) catch |err|
            return pkcs_error.toRV(err);

        std.mem.copyForwards(u8, random_data[i .. i + segment_size], segment[0..segment_size]);

        i += segment_size;
        remaining_size -= segment_size;

        current_session.allocator.free(segment);
    }

    return pkcs.CKR_OK;
}
