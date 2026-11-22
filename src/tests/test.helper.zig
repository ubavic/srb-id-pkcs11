const builtin = @import("builtin");
const std = @import("std");

const KeyPair = @import("KeyPair.helper.zig");
const ModuleState = @import("../ModuleState.zig").ModuleState;
const object = @import("../session/object.zig");
const operation = @import("../session/operation.zig");
const pkcs = @import("../pkcs.zig");
const PublicKeyFile = @import("../smart-card/PublicKeyFile.zig");
const reader = @import("../smart-card/reader.zig");

pub const slot_id: pkcs.CK_SLOT_ID = 1;
pub const public_key_handle: pkcs.CK_OBJECT_HANDLE = 0x80000000;
pub const private_key_handle: pkcs.CK_OBJECT_HANDLE = 0x80000008;

pub const key_files = [_][]const u8{
    "testdata/1024.key",
    "testdata/2048.key",
};

pub fn loadKeyPair(path: []const u8) !KeyPair {
    if (!builtin.is_test)
        @compileError("not testing");

    return KeyPair.load(std.testing.allocator, std.testing.io, path);
}

pub fn newTestingState(comptime Card: type) ModuleState(Card) {
    if (!builtin.is_test)
        @compileError("not testing");

    const allocator = std.testing.allocator;

    reader.reader_states = .init(allocator);

    return .{
        .initialized = false,
        .allocator = allocator,
        .io = std.testing.io,
        .smart_card_client = undefined,
        .sessions = try .init(allocator),
    };
}

/// Adds a session without objects. Its card must not be used.
pub fn addNewSession(state: anytype) !c_ulong {
    if (!builtin.is_test)
        @compileError("not testing");

    return addSession(state, undefined, &.{});
}

/// Adds a session with `card` but without objects.
pub fn addNewSessionWithoutKeys(state: anytype, card: anytype) !c_ulong {
    if (!builtin.is_test)
        @compileError("not testing");

    return addSession(state, card, &.{});
}

/// Adds a session holding public and private key objects of `key_pair`.
/// `card` should hold the same key pair.
pub fn addNewSessionWithCard(state: anytype, card: anytype, key_pair: *const KeyPair) !c_ulong {
    if (!builtin.is_test)
        @compileError("not testing");

    const allocator = std.testing.allocator;

    var key_file = PublicKeyFile{
        .id = @splat(0x01),
        .pub_key_file_name = KeyPair.public_key_file_name,
        .priv_key_file_name = KeyPair.private_key_file_name,
        .modulus_len = key_pair.modulus.len,
        .exponent_len = key_pair.public_exponent.len,
        .allow_encrypt = true,
    };
    @memcpy(key_file.modulus[0..key_pair.modulus.len], key_pair.modulus);
    @memcpy(key_file.exponent[0..key_pair.public_exponent.len], key_pair.public_exponent);

    const objects = try allocator.alloc(object.Object, 2);
    errdefer allocator.free(objects);

    objects[0] = .{ .public_key = try .createPublicKeyObject(allocator, key_file, public_key_handle) };
    errdefer objects[0].deinit(allocator);

    objects[1] = .{ .private_key = try .createPrivateKeyObject(allocator, key_file, private_key_handle) };
    errdefer objects[1].deinit(allocator);

    return addSession(state, card, objects);
}

fn addSession(state: anytype, card: anytype, objects: []object.Object) !c_ulong {
    state.sessions.next_session_id += 1;
    try state.sessions.sessions.put(state.sessions.next_session_id, .{
        .allocator = std.testing.allocator,
        .card = card,
        .id = state.sessions.next_session_id,
        .objects = objects,
        .operation = .none,
        .reader_id = slot_id,
        .closed = false,
        .write_enabled = false,
    });

    return state.sessions.next_session_id;
}

pub fn getSession(state: anytype, session_handle: c_ulong) @TypeOf(state.sessions.sessions.getPtr(session_handle).?) {
    return state.sessions.sessions.getPtr(session_handle) orelse
        @panic("session does not exist");
}

pub const ReaderOptions = struct {
    slot_id: pkcs.CK_SLOT_ID = slot_id,
    card_present: bool = true,
    recognized: bool = true,
    user_type: reader.UserType = .None,
};

pub fn addReader(options: ReaderOptions) !void {
    try reader.reader_states.put(options.slot_id, .{
        .name = "Testing reader",
        .active = true,
        .card_present = options.card_present,
        .recognized = options.recognized,
        .user_type = options.user_type,
    });
}

pub fn login() !void {
    try addReader(.{ .user_type = .User });
}

pub fn expectOperation(
    state: anytype,
    session_handle: c_ulong,
    expected: std.meta.Tag(operation.Operation),
) !void {
    const session = getSession(state, session_handle);
    try std.testing.expectEqual(expected, std.meta.activeTag(session.operation));
}

pub fn deinitTestingState(state: anytype) void {
    if (!builtin.is_test)
        @compileError("not testing");

    var it = state.sessions.sessions.valueIterator();
    while (it.next()) |session| {
        session.resetOperation();

        for (session.objects) |*o|
            o.deinit(session.allocator);
        session.allocator.free(session.objects);
    }

    state.sessions.sessions.deinit();
    reader.reader_states.deinit();
}
