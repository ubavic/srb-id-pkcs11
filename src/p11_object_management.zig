const std = @import("std");

const Attribute = @import("session/Attribute.zig");
const operation = @import("session/operation.zig");
const pkcs = @import("pkcs.zig");
const session = @import("session/session.zig");
const state = @import("state.zig");

pub fn createObject(
    _: pkcs.CK_SESSION_HANDLE,
    _: ?[*]pkcs.CK_ATTRIBUTE,
    _: pkcs.CK_ULONG,
    _: ?*pkcs.CK_OBJECT_HANDLE,
) error{
    FunctionNotSupported,
}!void {
    return error.FunctionNotSupported;
}

pub fn copyObject(
    _: pkcs.CK_SESSION_HANDLE,
    _: pkcs.CK_OBJECT_HANDLE,
    _: ?[*]pkcs.CK_ATTRIBUTE,
    _: pkcs.CK_ULONG,
    _: ?*pkcs.CK_OBJECT_HANDLE,
) error{
    FunctionNotSupported,
}!void {
    return error.FunctionNotSupported;
}

pub fn destroyObject(
    _: pkcs.CK_SESSION_HANDLE,
    _: pkcs.CK_OBJECT_HANDLE,
) error{
    FunctionNotSupported,
}!void {
    return error.FunctionNotSupported;
}

pub fn getObjectSize(
    _: pkcs.CK_SESSION_HANDLE,
    _: pkcs.CK_OBJECT_HANDLE,
    _: ?*pkcs.CK_ULONG,
) error{
    FunctionNotSupported,
}!void {
    return error.FunctionNotSupported;
}

pub fn getAttributeValue(
    session_handle: pkcs.CK_SESSION_HANDLE,
    object_handle: pkcs.CK_OBJECT_HANDLE,
    template: ?[*]pkcs.CK_ATTRIBUTE,
    count: pkcs.CK_ULONG,
) error{
    ArgumentsBad,
    AttributeTypeInvalid,
    BufferTooSmall,
    CryptokiNotInitialized,
    FunctionFailed,
    HostMemory,
    ObjectHandleInvalid,
    SessionHandleInvalid,
}!void {
    state.lock.lockSharedUncancelable(state.io);
    defer state.lock.unlockShared(state.io);

    const has_attribute_sensitive = false;
    var has_attribute_type_invalid = false;
    var has_small_buffer = false;

    const current_session = try session.getSession(session_handle, false);

    if (template == null)
        return error.ArgumentsBad;

    if (count == 0)
        return error.ArgumentsBad;

    const selected_object = try current_session.getObject(object_handle);

    for (0..count) |i| {
        const attribute_size = selected_object.getAttributeSize(template.?[i].type) catch {
            template.?[i].ulValueLen = pkcs.CK_UNAVAILABLE_INFORMATION;
            has_attribute_type_invalid = true;
            continue;
        };

        if (template.?[i].pValue == null) {
            template.?[i].ulValueLen = @intCast(attribute_size);
            continue;
        }

        if (template.?[i].ulValueLen < attribute_size) {
            has_small_buffer = true;
            template.?[i].ulValueLen = @intCast(attribute_size);
            continue;
        }

        const target_buffer: [*]u8 = @ptrCast(template.?[i].pValue.?);

        const object_attribute = selected_object.getAttribute(target_buffer[0..attribute_size], template.?[i].type) catch |err| {
            switch (err) {
                // error.AttributeSensitive => {
                //     has_attribute_sensitive = true;
                //     continue; // TODO: check this
                // },
                error.AttributeTypeInvalid => {
                    template.?[i].ulValueLen = pkcs.CK_UNAVAILABLE_INFORMATION;
                    has_attribute_type_invalid = true;
                    continue;
                },
                else => return err,
            }
        };

        template.?[i].ulValueLen = @intCast(object_attribute.value.len);
    }

    if (has_attribute_sensitive)
        return error.AttributeSensitive;

    if (has_attribute_type_invalid)
        return error.AttributeTypeInvalid;

    if (has_small_buffer)
        return error.BufferTooSmall;
}

pub fn setAttributeValue(
    _: pkcs.CK_SESSION_HANDLE,
    _: pkcs.CK_OBJECT_HANDLE,
    _: ?[*]pkcs.CK_ATTRIBUTE,
    _: pkcs.CK_ULONG,
) error{
    FunctionNotSupported,
}!void {
    return error.FunctionNotSupported;
}

pub fn findObjectsInit(
    session_handle: pkcs.CK_SESSION_HANDLE,
    template: ?[*]pkcs.CK_ATTRIBUTE,
    count: pkcs.CK_ULONG,
) error{
    ArgumentsBad,
    CryptokiNotInitialized,
    FunctionFailed,
    HostMemory,
    OperationActive,
    SessionHandleInvalid,
}!void {
    state.lock.lockSharedUncancelable(state.io);
    defer state.lock.unlockShared(state.io);

    const current_session = try session.getSession(session_handle, false);

    try current_session.assertNoOperation();

    if (template == null and count != 0)
        return error.ArgumentsBad;

    var search_template: []Attribute = &.{};
    if (count > 0) {
        search_template = try Attribute.parseAttributes(current_session.allocator, template.?[0..count]);
    }

    current_session.operation = operation.Operation{
        .search = operation.Search{
            .index = 0,
            .search_template = search_template,
            .objects = current_session.objects,
            .logged_in = current_session.loggedIn(),
        },
    };
}

pub fn findObjects(
    session_handle: pkcs.CK_SESSION_HANDLE,
    object_handles: ?[*]pkcs.CK_OBJECT_HANDLE,
    max_object_count: pkcs.CK_ULONG,
    object_count: ?*pkcs.CK_ULONG,
) error{
    ArgumentsBad,
    AttributeTypeInvalid, //TODO: remove
    CryptokiNotInitialized,
    FunctionFailed,
    HostMemory,
    OperationNotInitialized,
    SessionHandleInvalid,
}!void {
    state.lock.lockSharedUncancelable(state.io);
    defer state.lock.unlockShared(state.io);

    const current_session = try session.getSession(session_handle, false);

    try current_session.assertOperation(operation.Type.Search);

    const current_operation = &current_session.operation.search;

    if (object_handles == null)
        return error.ArgumentsBad;

    if (object_count == null)
        return error.ArgumentsBad;

    const found_objects = try current_operation.findNextObjects(current_session.allocator, object_handles.?[0..max_object_count]);

    object_count.?.* = @intCast(found_objects);
}

pub fn findObjectsFinal(
    session_handle: pkcs.CK_SESSION_HANDLE,
) error{
    CryptokiNotInitialized,
    FunctionFailed,
    OperationNotInitialized,
    SessionHandleInvalid,
}!void {
    state.lock.lockSharedUncancelable(state.io);
    defer state.lock.unlockShared(state.io);

    const current_session = try session.getSession(session_handle, false);

    try current_session.assertOperation(operation.Type.Search);

    current_session.resetOperation();
}
