const std = @import("std");
const pcsc = @import("pcsc");

const SessionState = @import("session/SessionState.zig");

const ModuleState = @This();

lock: std.Io.RwLock = std.Io.RwLock.init,
initialized: bool,
allocator: std.mem.Allocator,
io: std.Io,
smart_card_client: pcsc.Client,
sessions: SessionState,

pub fn newTewstingState() ModuleState {
    const allocator = std.testing.allocator;

    return ModuleState{
        .initialized = false,
        .allocator = allocator,
        .io = std.testing.io,
        .smart_card_client = undefined, // TODO
        .sessions = .init(allocator),
    };
}
