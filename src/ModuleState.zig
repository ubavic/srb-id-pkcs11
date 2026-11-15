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
