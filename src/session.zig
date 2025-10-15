const std = @import("std");

const consts = @import("consts.zig");
const object = @import("object.zig");
const operation = @import("operation.zig");
const certificate = @import("certificate.zig");
const hasher = @import("hasher.zig");
const pkcs = @import("pkcs.zig").pkcs;
const pkcs_error = @import("pkcs_error.zig");
const reader = @import("reader.zig");
const smart_card = @import("smart-card.zig");
const state = @import("state.zig");

const PkcsError = pkcs_error.PkcsError;

var next_session_id: pkcs.CK_SESSION_HANDLE = 1;

var sessions: std.AutoHashMap(pkcs.CK_SESSION_HANDLE, Session) = undefined;

var lock = std.Thread.RwLock{};

pub const Session = struct {
    allocator: std.mem.Allocator,
    id: pkcs.CK_SESSION_HANDLE,
    card: smart_card.Card,
    reader_id: pkcs.CK_SLOT_ID,
    closed: bool = false,
    write_enabled: bool,
    operation: operation.Operation,
    objects: []object.Object,

    pub fn login(self: *Session, new_pin: []const u8) PkcsError!void {
        errdefer reader.setUserType(self.reader_id, reader.UserType.None);
        try self.card.verifyPin(self.allocator, new_pin);
        reader.setUserType(self.reader_id, reader.UserType.User);
    }

    pub fn logout(self: *Session) void {
        reader.setUserType(self.reader_id, reader.UserType.None);
    }

    pub fn loggedIn(self: *Session) bool {
        return reader.getUserType(self.reader_id) != reader.UserType.None;
    }

    pub fn assertNoOperation(self: *Session) PkcsError!void {
        return switch (self.operation) {
            .none => {},
            else => PkcsError.OperationActive,
        };
    }

    pub fn assertOperation(self: *Session, kind: operation.Type) PkcsError!void {
        return switch (self.operation) {
            .none => if (kind == operation.Type.None) {} else PkcsError.OperationNotInitialized,
            .digest => if (kind == operation.Type.Digest) {} else PkcsError.OperationActive,
            .sign => if (kind == operation.Type.Sign) {} else PkcsError.OperationActive,
            .verify => if (kind == operation.Type.Verify) {} else PkcsError.OperationActive,
            .search => if (kind == operation.Type.Search) {} else PkcsError.OperationActive,
        };
    }

    pub fn slot(self: *Session) void {
        return self.card.reader_id;
    }

    pub fn resetOperation(self: *Session) void {
        self.operation.deinit(self.allocator);
        self.operation = operation.Operation{
            .none = operation.None{},
        };
    }

    pub fn findObjects(
        self: *Session,
        attributes: []object.Attribute,
    ) PkcsError![]pkcs.CK_OBJECT_HANDLE {
        var object_list = std.array_list.AlignedManaged(pkcs.CK_OBJECT_HANDLE, null).init(self.allocator);
        defer object_list.deinit();

        for (self.objects) |current_object| {
            var matches = true;

            if (current_object.private() and !self.loggedIn())
                continue;

            for (attributes) |attribute| {
                const has_attribute_value = try current_object.hasAttributeValue(self.allocator, attribute);

                if (!has_attribute_value) {
                    matches = false;
                    break;
                }
            }

            if (matches)
                object_list.append(current_object.handle()) catch
                    return PkcsError.HostMemory;
        }

        return object_list.toOwnedSlice() catch
            return PkcsError.HostMemory;
    }

    pub fn getObject(self: *Session, object_handle: pkcs.CK_OBJECT_HANDLE) PkcsError!*object.Object {
        for (self.objects) |*current_object| {
            if (current_object.private() and !self.loggedIn())
                break;

            if (current_object.handle() == object_handle)
                return current_object;
        }

        return PkcsError.ObjectHandleInvalid;
    }

    fn loadCertificates(
        self: *Session,
        allocator: std.mem.Allocator,
    ) PkcsError!void {
        var object_list = std.ArrayList(object.Object).initCapacity(allocator, 6) catch
            return PkcsError.HostMemory;
        errdefer object_list.deinit(allocator);

        const files: [2][2]u8 = [2][2]u8{
            [_]u8{ 0x71, 0x02 },
            [_]u8{ 0x71, 0x03 },
        };

        // TODO determine handles of objects when only the auth cert is present on token

        const ids = [_]consts.ObjectConstants{
            consts.AuthCert,
            consts.SignCert,
        };

        for (files, 0..) |file, i| {
            const certificate_file = self.card.readCertificateFile(allocator, file[0..]) catch
                continue;
            defer allocator.free(certificate_file);

            const certificate_data = try certificate.decompressCertificate(allocator, certificate_file);
            defer allocator.free(certificate_data);

            const cert_objects = certificate.loadObjects(
                allocator,
                certificate_data,
                ids[i].certificate_handle,
                ids[i].private_key_handle,
                ids[i].public_key_handle,
                &ids[i].id,
                i == 0,
            ) catch
                continue;

            for (cert_objects) |o| {
                object_list.append(allocator, o) catch {
                    // TODO deinit o;
                };
            }
        }

        self.objects = object_list.toOwnedSlice(allocator) catch
            return PkcsError.HostMemory;
    }
};

pub fn initSessions(allocator: std.mem.Allocator) PkcsError!void {
    if (!lock.tryLock())
        return PkcsError.FunctionFailed;
    defer lock.unlock();

    sessions = std.AutoHashMap(pkcs.CK_SLOT_ID, Session).init(allocator);
}

pub fn newSession(
    allocator: std.mem.Allocator,
    slot_id: pkcs.CK_SESSION_HANDLE,
    write_enabled: bool,
) PkcsError!pkcs.CK_SESSION_HANDLE {
    if (!lock.tryLock())
        return PkcsError.FunctionFailed;
    defer lock.unlock();

    const session_id: pkcs.CK_SESSION_HANDLE = next_session_id;
    next_session_id += 1;

    const reader_entry = reader.reader_states.get(slot_id);
    if (reader_entry == null)
        return PkcsError.SlotIdInvalid;

    const reader_state = reader_entry.?;

    if (!reader_state.card_present)
        return PkcsError.TokenNoPresent;

    if (!reader_state.recognized)
        return PkcsError.TokenNotRecognized;

    const card = try smart_card.connect(
        allocator,
        &state.smart_card_client,
        reader_state.name,
    );

    const objects: []object.Object = allocator.alloc(object.Object, 0) catch
        return PkcsError.HostMemory;

    var new_session = Session{
        .id = session_id,
        .card = card,
        .reader_id = slot_id,
        .write_enabled = write_enabled,
        .allocator = allocator,
        .objects = objects,
        .operation = operation.Operation{
            .none = operation.None{},
        },
    };

    try new_session.loadCertificates(allocator);

    sessions.put(session_id, new_session) catch
        return PkcsError.HostMemory;

    return session_id;
}

pub fn getSession(
    session_handle: pkcs.CK_SESSION_HANDLE,
    login_required: bool,
) PkcsError!*Session {
    if (!lock.tryLockShared())
        return PkcsError.FunctionFailed;
    defer lock.unlockShared();

    if (!state.initialized)
        return PkcsError.CryptokiNotInitialized;

    const session_entry = sessions.getPtr(session_handle);
    if (session_entry == null)
        return PkcsError.SessionHandleInvalid;

    const current_session = session_entry.?;

    if (login_required and !current_session.loggedIn())
        return PkcsError.UserNotLoggedIn;

    return current_session;
}

pub fn closeSession(session_handle: pkcs.CK_SESSION_HANDLE) PkcsError!void {
    if (!lock.tryLock())
        return PkcsError.FunctionFailed;
    defer lock.unlock();

    const session_entry = sessions.getPtr(session_handle);
    if (session_entry == null)
        return PkcsError.SessionHandleInvalid;

    const current_session = session_entry.?;

    if (current_session.closed)
        return PkcsError.SessionClosed;

    current_session.closed = true;

    current_session.resetOperation();

    current_session.card.disconnect() catch {};

    if (!sessions.remove(session_handle))
        return PkcsError.GeneralError;
}

pub fn closeAllSessions(slot_id: pkcs.CK_SLOT_ID) pkcs.CK_RV {
    var err: pkcs.CK_RV = pkcs.CKR_OK;
    var it = sessions.iterator();

    while (it.next()) |entry| {
        const sessionId = entry.key_ptr.*;
        const session_entry = entry.value_ptr.*;
        if (session_entry.reader_id == slot_id) {
            closeSession(sessionId) catch |e| {
                err = pkcs_error.toRV(e);
            };
        }
    }

    return err;
}

pub fn countSessions(slot_id: pkcs.CK_SLOT_ID, total_sessions: *c_ulong, rw_sessions: *c_ulong) void {
    lock.lockShared();
    defer lock.unlockShared();

    total_sessions.* = 0;
    rw_sessions.* = 0;

    var it = sessions.iterator();
    while (it.next()) |entry| {
        if (entry.value_ptr.*.reader_id == slot_id) {
            total_sessions.* += 1;
            if (entry.value_ptr.write_enabled)
                rw_sessions.* += 1;
        }
    }
}
