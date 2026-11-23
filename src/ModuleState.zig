const std = @import("std");
const pcsc = @import("pcsc");

const SessionState = @import("session/SessionState.zig").SessionState;

pub fn ModuleState(comptime Card: type) type {
    return struct {
        initialized: bool,
        allocator: std.mem.Allocator,
        lock: std.Io.RwLock = std.Io.RwLock.init,
        io: std.Io = std.Io.Threaded.global_single_threaded.io(),
        smart_card_client: pcsc.Client = undefined,
        sessions: SessionState(Card) = undefined,
    };
}
