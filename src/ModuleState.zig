const std = @import("std");
const pcsc = @import("pcsc");

const ModuleState = @This();

lock: std.Io.RwLock = std.Io.RwLock.init,
initialized: bool,
allocator: std.mem.Allocator,
io: std.Io,
smart_card_client: pcsc.Client,

pub fn newTewstingState() ModuleState {
    return ModuleState{
        .initialized = false,
        .allocator = std.testing.allocator,
        .io = std.testing.io,
        .smart_card_client = undefined, // TODO
    };
}
