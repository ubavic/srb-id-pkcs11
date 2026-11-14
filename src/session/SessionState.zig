const std = @import("std");
const pcsc = @import("pcsc");

const Card = @import("../smart-card/Card.zig");
const pkcs = @import("../pkcs.zig");
const reader = @import("../smart-card/reader.zig");
const Session = @import("session.zig");

const SessionState = @This();

next_session_id: pkcs.CK_SESSION_HANDLE,
sessions: std.AutoHashMap(pkcs.CK_SESSION_HANDLE, Session),
lock: std.Io.RwLock,

pub fn init(
    allocator: std.mem.Allocator,
) !SessionState {
    return .{
        .lock = std.Io.RwLock.init,
        .sessions = std.AutoHashMap(pkcs.CK_SLOT_ID, Session).init(allocator),
        .next_session_id = 1,
    };
}

pub fn newSession(
    state: *SessionState,
    allocator: std.mem.Allocator,
    io: std.Io,
    smart_card_client: *pcsc.Client,
    slot_id: pkcs.CK_SESSION_HANDLE,
    write_enabled: bool,
) !pkcs.CK_SESSION_HANDLE {
    if (!state.lock.tryLock(io))
        return error.FunctionFailed;
    defer state.lock.unlock(io);

    const session_id: pkcs.CK_SESSION_HANDLE = state.next_session_id;
    state.next_session_id += 1;

    const reader_state = reader.reader_states.get(slot_id) orelse
        return error.SlotIdInvalid;

    if (!reader_state.card_present)
        return error.TokenNoPresent;

    if (!reader_state.recognized)
        return error.TokenNotRecognized;

    const card = try Card.connect(
        allocator,
        smart_card_client,
        reader_state.name,
    );

    var new_session = Session{
        .id = session_id,
        .card = card,
        .reader_id = slot_id,
        .write_enabled = write_enabled,
        .allocator = allocator,
        .objects = &.{},
        .operation = .none,
    };

    try new_session.loadObjects(allocator);

    state.sessions.put(session_id, new_session) catch
        return error.HostMemory;

    return session_id;
}

pub fn getSession(
    state: *SessionState,
    io: std.Io,
    session_handle: pkcs.CK_SESSION_HANDLE,
    comptime login_required: bool,
) !*Session {
    if (!state.lock.tryLockShared(io))
        return error.FunctionFailed;
    defer state.lock.unlockShared(io);

    const current_session = state.sessions.getPtr(session_handle) orelse
        return error.SessionHandleInvalid;

    if (login_required and !current_session.loggedIn(io))
        return error.UserNotLoggedIn;

    return current_session;
}

pub fn closeSession(
    state: *SessionState,
    allocator: std.mem.Allocator,
    io: std.Io,
    session_handle: pkcs.CK_SESSION_HANDLE,
) !void {
    if (!state.lock.tryLock(io))
        return error.FunctionFailed;
    defer state.lock.unlock(io);

    const current_session = state.sessions.getPtr(session_handle) orelse
        return error.SessionHandleInvalid;

    try current_session.closeSession(allocator);

    if (!state.sessions.remove(session_handle))
        return error.GeneralError;
}

pub fn closeAllSessions(
    state: *SessionState,
    allocator: std.mem.Allocator,
    io: std.Io,
    slot_id: pkcs.CK_SLOT_ID,
) !void {
    if (!state.lock.tryLock(io))
        return error.FunctionFailed;
    defer state.lock.unlock(io);

    var errored = false;

    var sessions_to_close = std.ArrayList(pkcs.CK_SESSION_HANDLE).initCapacity(allocator, state.sessions.count()) catch
        return error.HostMemory;
    defer sessions_to_close.deinit(allocator);

    var it = state.sessions.iterator();
    while (it.next()) |entry| {
        if (entry.value_ptr.reader_id != slot_id)
            continue;

        entry.value_ptr.closeSession(allocator) catch {
            errored = true;
        };

        sessions_to_close.append(allocator, entry.key_ptr.*) catch
            return error.HostMemory;
    }

    for (sessions_to_close.items) |key|
        _ = state.sessions.remove(key);

    if (errored)
        return error.GeneralError;
}

pub fn countSessions(
    state: *SessionState,
    io: std.Io,
    slot_id: pkcs.CK_SLOT_ID,
    total_sessions: *usize,
    rw_sessions: *usize,
) !void {
    state.lock.lockSharedUncancelable(io);
    defer state.lock.unlockShared(io);

    total_sessions.* = 0;
    rw_sessions.* = 0;

    var it = state.sessions.valueIterator();
    while (it.next()) |value| {
        if (value.*.reader_id == slot_id) {
            total_sessions.* += 1;
            if (value.write_enabled)
                rw_sessions.* += 1;
        }
    }
}
