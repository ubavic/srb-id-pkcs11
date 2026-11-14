const std = @import("std");
const pcsc = @import("pcsc");

const Card = @import("../smart-card/Card.zig");
const hasher = @import("hasher.zig");
const Index = @import("../smart-card/Index.zig");
const MetaFile = @import("../smart-card/MetaFile.zig");
const object = @import("object.zig");
const operation = @import("operation.zig");
const PaddedPin = @import("../smart-card/PaddedPin.zig");
const pkcs = @import("../pkcs.zig");
const PublicKeyFile = @import("../smart-card/PublicKeyFile.zig");
const reader = @import("../smart-card/reader.zig");
const state = @import("../ModuleState.zig");

var next_session_id: pkcs.CK_SESSION_HANDLE = 1;

var sessions: std.AutoHashMap(pkcs.CK_SESSION_HANDLE, Session) = undefined;

var lock = std.Io.RwLock.init;

pub const Session = struct {
    allocator: std.mem.Allocator,
    id: pkcs.CK_SESSION_HANDLE,
    card: Card,
    reader_id: pkcs.CK_SLOT_ID,
    closed: bool = false,
    write_enabled: bool,
    operation: operation.Operation,
    objects: []object.Object,

    pub fn setPin(self: *Session, allocator: std.mem.Allocator, io: std.Io, old_pin: *const PaddedPin, new_pin: *const PaddedPin) !void {
        try self.login(io, old_pin);
        try self.card.setPin(allocator, old_pin, new_pin);
    }

    pub fn login(self: *Session, io: std.Io, pin: *const PaddedPin) !void {
        errdefer reader.setUserType(io, self.reader_id, reader.UserType.None);
        try self.card.verifyPin(self.allocator, pin);
        reader.setUserType(io, self.reader_id, reader.UserType.User);
    }

    pub fn logout(self: *Session, io: std.Io) void {
        reader.setUserType(io, self.reader_id, reader.UserType.None);
    }

    pub fn loggedIn(self: *Session, io: std.Io) bool {
        return reader.getUserType(io, self.reader_id) != reader.UserType.None;
    }

    pub fn assertNoOperation(self: *Session) !void {
        if (self.operation != .none)
            return error.OperationActive;
    }

    pub fn assertOperation(
        self: *Session,
        comptime kind: std.meta.Tag(operation.Operation),
    ) !*@FieldType(operation.Operation, @tagName(kind)) {
        if (std.meta.activeTag(self.operation) != kind)
            return error.OperationNotInitialized;

        return &@field(self.operation, @tagName(kind));
    }

    pub fn slot(self: *Session) void {
        return self.card.reader_id;
    }

    pub fn resetOperation(self: *Session) void {
        self.operation.deinit(self.allocator);
        self.operation = .none;
    }

    pub fn getObject(self: *Session, io: std.Io, object_handle: pkcs.CK_OBJECT_HANDLE) !*object.Object {
        for (self.objects) |*current_object| {
            if (current_object.private() and !self.loggedIn(io))
                continue;

            if (current_object.handle() == object_handle)
                return current_object;
        }

        return error.ObjectHandleInvalid;
    }

    fn loadObjects(
        self: *Session,
        allocator: std.mem.Allocator,
    ) !void {
        const tx = try self.card.startTransaction();
        defer self.card.endTransaction(tx);

        const index_content = try self.card.readFile(allocator, &.{ 0x8F, 0xFF });
        defer allocator.free(index_content);

        var index = try Index.init(index_content);

        var object_list = std.ArrayList(object.Object).initCapacity(allocator, index.length) catch
            return error.HostMemory;
        errdefer object_list.deinit(allocator);

        var handle: pkcs.CK_OBJECT_HANDLE = 0x80000000;
        while (index.next()) |meta_file_name| {
            const meta_file_content = try self.card.readFile(allocator, &meta_file_name);
            defer allocator.free(meta_file_content);

            const meta_file = try MetaFile.parse(meta_file_content);

            switch (meta_file.class) {
                0x01 => {
                    const compressed_certificate_content = try self.card.readFile(allocator, &meta_file.file_name);
                    defer allocator.free(compressed_certificate_content);

                    const certificate_data = try object.CertificateObject.decompressCertificate(allocator, compressed_certificate_content);
                    defer allocator.free(certificate_data);

                    const cert_object = object.CertificateObject.parse(
                        allocator,
                        handle,
                        certificate_data,
                        meta_file.id,
                        meta_file.file_name,
                    ) catch
                        continue;

                    object_list.append(allocator, .{ .certificate = cert_object }) catch
                        return error.HostMemory;

                    handle += 8;
                },
                0x02 => {
                    const pub_key_file_content: []const u8 = try self.card.readFile(allocator, &meta_file.file_name);
                    defer allocator.free(pub_key_file_content);

                    var pub_key_file = PublicKeyFile{
                        .id = meta_file.id,
                        .pub_key_file_name = meta_file.file_name,
                    };
                    pub_key_file.parse(pub_key_file_content) catch
                        continue;

                    const public_key_object = try object.PublicKeyObject.createPublicKeyObject(allocator, pub_key_file, handle);
                    object_list.append(allocator, .{ .public_key = public_key_object }) catch
                        return error.HostMemory;

                    handle += 8;

                    const private_key_object = try object.PrivateKeyObject.createPrivateKeyObject(allocator, pub_key_file, handle);
                    object_list.append(allocator, .{ .private_key = private_key_object }) catch
                        return error.HostMemory;

                    handle += 8;
                },
                0x03 => {
                    // private key - we know all things needed from the pub key
                },
                else => unreachable,
            }
        }

        self.objects = object_list.toOwnedSlice(allocator) catch
            return error.HostMemory;
    }

    fn closeSession(self: *Session, allocator: std.mem.Allocator) !void {
        if (self.closed)
            return error.SessionClosed;

        self.closed = true;
        self.resetOperation();

        for (self.objects) |*o|
            o.deinit(allocator);

        self.card.disconnect() catch {};
    }
};

pub fn initSessions(
    allocator: std.mem.Allocator,
    io: std.Io,
) !void {
    if (!lock.tryLock(io))
        return error.FunctionFailed;
    defer lock.unlock(io);

    sessions = std.AutoHashMap(pkcs.CK_SLOT_ID, Session).init(allocator);
}

pub fn newSession(
    allocator: std.mem.Allocator,
    io: std.Io,
    smart_card_client: *pcsc.Client,
    slot_id: pkcs.CK_SESSION_HANDLE,
    write_enabled: bool,
) !pkcs.CK_SESSION_HANDLE {
    if (!lock.tryLock(io))
        return error.FunctionFailed;
    defer lock.unlock(io);

    const session_id: pkcs.CK_SESSION_HANDLE = next_session_id;
    next_session_id += 1;

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

    const objects: []object.Object = allocator.alloc(object.Object, 0) catch
        return error.HostMemory;

    var new_session = Session{
        .id = session_id,
        .card = card,
        .reader_id = slot_id,
        .write_enabled = write_enabled,
        .allocator = allocator,
        .objects = objects,
        .operation = .none,
    };

    try new_session.loadObjects(allocator);

    sessions.put(session_id, new_session) catch
        return error.HostMemory;

    return session_id;
}

pub fn getSession(
    io: std.Io,
    session_handle: pkcs.CK_SESSION_HANDLE,
    comptime login_required: bool,
) !*Session {
    if (!lock.tryLockShared(io))
        return error.FunctionFailed;
    defer lock.unlockShared(io);

    const current_session = sessions.getPtr(session_handle) orelse
        return error.SessionHandleInvalid;

    if (login_required and !current_session.loggedIn(io))
        return error.UserNotLoggedIn;

    return current_session;
}

pub fn closeSession(allocator: std.mem.Allocator, io: std.Io, session_handle: pkcs.CK_SESSION_HANDLE) !void {
    if (!lock.tryLock(io))
        return error.FunctionFailed;
    defer lock.unlock(io);

    const current_session = sessions.getPtr(session_handle) orelse
        return error.SessionHandleInvalid;

    try current_session.closeSession(allocator);

    if (!sessions.remove(session_handle))
        return error.GeneralError;
}

pub fn closeAllSessions(
    allocator: std.mem.Allocator,
    io: std.Io,
    slot_id: pkcs.CK_SLOT_ID,
) !void {
    if (!lock.tryLock(io))
        return error.FunctionFailed;
    defer lock.unlock(io);

    var errored = false;

    var sessions_to_close = std.ArrayList(pkcs.CK_SESSION_HANDLE).initCapacity(allocator, sessions.count()) catch
        return error.HostMemory;
    defer sessions_to_close.deinit(allocator);

    var it = sessions.iterator();
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
        _ = sessions.remove(key);

    if (errored)
        return error.GeneralError;
}

pub fn countSessions(
    io: std.Io,
    slot_id: pkcs.CK_SLOT_ID,
    total_sessions: *usize,
    rw_sessions: *usize,
) !void {
    lock.lockSharedUncancelable(io);
    defer lock.unlockShared(io);

    total_sessions.* = 0;
    rw_sessions.* = 0;

    var it = sessions.valueIterator();
    while (it.next()) |value| {
        if (value.*.reader_id == slot_id) {
            total_sessions.* += 1;
            if (value.write_enabled)
                rw_sessions.* += 1;
        }
    }
}
