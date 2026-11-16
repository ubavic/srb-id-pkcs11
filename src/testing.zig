const builtin = @import("builtin");
const std = @import("std");

const ModuleState = @import("ModuleState.zig");

pub fn newTestingState() ModuleState {
    if (!builtin.is_test)
        @compileError("not testing");

    const allocator = std.testing.allocator;

    return ModuleState{
        .initialized = false,
        .allocator = allocator,
        .io = std.testing.io,
        .smart_card_client = undefined, // TODO
        .sessions = try .init(allocator),
    };
}

pub fn addNewSession(state: *ModuleState) !c_ulong {
    if (!builtin.is_test)
        @compileError("not testing");

    state.sessions.next_session_id += 1;
    try state.sessions.sessions.put(state.sessions.next_session_id, .{
        .allocator = undefined,
        .card = undefined,
        .id = state.sessions.next_session_id,
        .objects = &.{},
        .operation = .none,
        .reader_id = 1,
        .closed = false,
        .write_enabled = false,
    });

    return state.sessions.next_session_id;
}
