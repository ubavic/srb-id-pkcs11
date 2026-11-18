const std = @import("std");

const pkcs = @import("../pkcs.zig");
const p11_digest = @import("../p11_digest.zig");
const test_helpers = @import("test_helpers.zig");

test "digestInit cryptoki initialization" {
    var testing_state = test_helpers.newTestingState();
    defer test_helpers.deinitTestingState(&testing_state);

    const result = p11_digest.digestInit(&testing_state, 0, null);
    try std.testing.expectError(error.CryptokiNotInitialized, result);
}

test "digestInit invalid session handle" {
    var testing_state = test_helpers.newTestingState();
    defer test_helpers.deinitTestingState(&testing_state);

    testing_state.initialized = true;

    const result = p11_digest.digestInit(&testing_state, 42, null);
    try std.testing.expectError(error.SessionHandleInvalid, result);
}

test "digestInit null mechanism" {
    var testing_state = test_helpers.newTestingState();
    defer test_helpers.deinitTestingState(&testing_state);

    testing_state.initialized = true;
    const id = try test_helpers.addNewSession(&testing_state);

    const result = p11_digest.digestInit(&testing_state, id, null);
    try std.testing.expectError(error.ArgumentsBad, result);
}

test "digest cryptoki initialization" {
    var testing_state = test_helpers.newTestingState();
    defer test_helpers.deinitTestingState(&testing_state);

    const result = p11_digest.digest(&testing_state, 0, null, 0, null, null);
    try std.testing.expectError(error.CryptokiNotInitialized, result);
}

test "digest invalid session handle" {
    var testing_state = test_helpers.newTestingState();
    defer test_helpers.deinitTestingState(&testing_state);

    testing_state.initialized = true;

    const result = p11_digest.digest(&testing_state, 42, null, 0, null, null);
    try std.testing.expectError(error.SessionHandleInvalid, result);
}

test "digest fails on multipart operation" {
    var testing_state = test_helpers.newTestingState();
    defer test_helpers.deinitTestingState(&testing_state);

    testing_state.initialized = true;
    const id = try test_helpers.addNewSession(&testing_state);

    var mechanism = pkcs.CK_MECHANISM{ .mechanism = pkcs.CKM_SHA256 };
    try p11_digest.digestInit(&testing_state, id, &mechanism);

    var data: [2]u8 = .{ 0x01, 0x02 };
    try p11_digest.digestUpdate(&testing_state, id, (&data).ptr, (&data).len);

    var buff: [256]u8 = @splat(0x00);
    var size: c_ulong = buff.len;

    const result = p11_digest.digest(&testing_state, id, (&data).ptr, (&data).len, (&buff).ptr, &size);
    try std.testing.expectError(error.FunctionCanceled, result);
    const new_session = testing_state.sessions.sessions.getPtr(id) orelse unreachable;
    try std.testing.expectEqual(.none, new_session.operation);
}

test "digest bad arguments" {
    var testing_state = test_helpers.newTestingState();
    defer test_helpers.deinitTestingState(&testing_state);

    testing_state.initialized = true;
    const id = try test_helpers.addNewSession(&testing_state);
    const new_session = testing_state.sessions.sessions.getPtr(id) orelse unreachable;

    var mechanism = pkcs.CK_MECHANISM{ .mechanism = pkcs.CKM_SHA256 };
    var data: [2]u8 = .{ 0x01, 0x02 };
    var buff: [32]u8 = @splat(0x00);
    var size: c_ulong = buff.len;

    try p11_digest.digestInit(&testing_state, id, &mechanism);
    const result1 = p11_digest.digest(&testing_state, id, null, (&data).len, (&buff).ptr, &size);
    try std.testing.expectError(error.ArgumentsBad, result1);
    try std.testing.expectEqual(.none, new_session.operation);

    try p11_digest.digestInit(&testing_state, id, &mechanism);
    const result2 = p11_digest.digest(&testing_state, id, (&data).ptr, (&data).len, (&buff).ptr, null);
    try std.testing.expectError(error.ArgumentsBad, result2);
    try std.testing.expectEqual(.none, new_session.operation);
}

test "digest return expected buffer size" {
    var testing_state = test_helpers.newTestingState();
    defer test_helpers.deinitTestingState(&testing_state);

    testing_state.initialized = true;
    const id = try test_helpers.addNewSession(&testing_state);

    var mechanism = pkcs.CK_MECHANISM{ .mechanism = pkcs.CKM_SHA256 };
    try p11_digest.digestInit(&testing_state, id, &mechanism);

    var data: [2]u8 = .{ 0x01, 0x02 };
    var buff: [32]u8 = @splat(0x00);
    var size: c_ulong = 31;

    const result = p11_digest.digest(&testing_state, id, (&data).ptr, (&data).len, (&buff).ptr, &size);
    try std.testing.expectError(error.BufferTooSmall, result);
    try std.testing.expectEqual(32, size);
}

test "digest" {
    var testing_state = test_helpers.newTestingState();
    defer test_helpers.deinitTestingState(&testing_state);

    testing_state.initialized = true;
    const id = try test_helpers.addNewSession(&testing_state);
    const new_session = testing_state.sessions.sessions.getPtr(id) orelse unreachable;

    var mechanism = pkcs.CK_MECHANISM{ .mechanism = pkcs.CKM_SHA256 };
    try p11_digest.digestInit(&testing_state, id, &mechanism);

    var data: [2]u8 = .{ 0x01, 0x02 };
    var buff: [32]u8 = @splat(0x00);
    var size: c_ulong = buff.len;
    const expected_digest: [32]u8 = .{
        0xa1, 0x28, 0x71, 0xfe, 0xe2, 0x10, 0xfb, 0x86, 0x19, 0x29, 0x1e, 0xae, 0xa1, 0x94, 0x58, 0x1c,
        0xbd, 0x25, 0x31, 0xe4, 0xb2, 0x37, 0x59, 0xd2, 0x25, 0xf6, 0x80, 0x69, 0x23, 0xf6, 0x32, 0x22,
    };

    try p11_digest.digest(&testing_state, id, (&data).ptr, (&data).len, (&buff).ptr, &size);
    try std.testing.expectEqualSlices(u8, &expected_digest, &buff);
    try std.testing.expectEqual(.none, new_session.operation);
}

test "digestUpdate cryptoki initialization" {
    var testing_state = test_helpers.newTestingState();
    defer test_helpers.deinitTestingState(&testing_state);

    const result = p11_digest.digestUpdate(&testing_state, 0, null, 0);
    try std.testing.expectError(error.CryptokiNotInitialized, result);
}

test "digestUpdate invalid session handle" {
    var testing_state = test_helpers.newTestingState();
    defer test_helpers.deinitTestingState(&testing_state);

    testing_state.initialized = true;

    const result = p11_digest.digestUpdate(&testing_state, 42, null, 0);
    try std.testing.expectError(error.SessionHandleInvalid, result);
}

test "digestUpdate invalid operation" {
    var testing_state = test_helpers.newTestingState();
    defer test_helpers.deinitTestingState(&testing_state);

    testing_state.initialized = true;
    const id = try test_helpers.addNewSession(&testing_state);

    const result = p11_digest.digestUpdate(&testing_state, id, null, 0);
    try std.testing.expectError(error.OperationNotInitialized, result);
}

test "digestUpdate invalid part" {
    var testing_state = test_helpers.newTestingState();
    defer test_helpers.deinitTestingState(&testing_state);

    testing_state.initialized = true;
    const id = try test_helpers.addNewSession(&testing_state);

    var mechanism = pkcs.CK_MECHANISM{ .mechanism = pkcs.CKM_SHA256 };
    try p11_digest.digestInit(&testing_state, id, &mechanism);

    const result = p11_digest.digestUpdate(&testing_state, id, null, 0);
    try std.testing.expectError(error.ArgumentsBad, result);

    const new_session = testing_state.sessions.sessions.getPtr(id) orelse unreachable;
    try std.testing.expectEqual(.none, new_session.operation);
}

test "digestFinal cryptoki initialization" {
    var testing_state = test_helpers.newTestingState();
    defer test_helpers.deinitTestingState(&testing_state);

    const result = p11_digest.digestFinal(&testing_state, 0, null, null);
    try std.testing.expectError(error.CryptokiNotInitialized, result);
}

test "digestFinal invalid session handle" {
    var testing_state = test_helpers.newTestingState();
    defer test_helpers.deinitTestingState(&testing_state);

    testing_state.initialized = true;

    const result = p11_digest.digestFinal(&testing_state, 42, null, null);
    try std.testing.expectError(error.SessionHandleInvalid, result);
}

test "digestFinal invalid operation" {
    var testing_state = test_helpers.newTestingState();
    defer test_helpers.deinitTestingState(&testing_state);

    testing_state.initialized = true;
    const id = try test_helpers.addNewSession(&testing_state);

    const result = p11_digest.digestFinal(&testing_state, id, null, null);
    try std.testing.expectError(error.OperationNotInitialized, result);
}

test "digestFinal bad arguments" {
    var testing_state = test_helpers.newTestingState();
    defer test_helpers.deinitTestingState(&testing_state);

    testing_state.initialized = true;
    const id = try test_helpers.addNewSession(&testing_state);
    const new_session = testing_state.sessions.sessions.getPtr(id) orelse unreachable;

    var mechanism = pkcs.CK_MECHANISM{ .mechanism = pkcs.CKM_SHA256 };
    try p11_digest.digestInit(&testing_state, id, &mechanism);

    var data: [2]u8 = .{ 0x01, 0x02 };
    var buff: [32]u8 = @splat(0x00);

    try p11_digest.digestUpdate(&testing_state, id, (&data).ptr, (&data).len);

    const result = p11_digest.digestFinal(&testing_state, id, (&buff).ptr, null);
    try std.testing.expectError(error.ArgumentsBad, result);
    try std.testing.expectEqual(.none, new_session.operation);
}

test "digestFinal return expected buffer size" {
    var testing_state = test_helpers.newTestingState();
    defer test_helpers.deinitTestingState(&testing_state);

    testing_state.initialized = true;
    const id = try test_helpers.addNewSession(&testing_state);

    var mechanism = pkcs.CK_MECHANISM{ .mechanism = pkcs.CKM_SHA256 };
    try p11_digest.digestInit(&testing_state, id, &mechanism);

    var data: [2]u8 = .{ 0x01, 0x02 };
    var buff: [32]u8 = @splat(0x00);
    var size: c_ulong = 31;

    try p11_digest.digestUpdate(&testing_state, id, (&data).ptr, (&data).len);

    const result = p11_digest.digestFinal(&testing_state, id, (&buff).ptr, &size);
    try std.testing.expectError(error.BufferTooSmall, result);
    try std.testing.expectEqual(32, size);
}

test "digestFinal" {
    var testing_state = test_helpers.newTestingState();
    defer test_helpers.deinitTestingState(&testing_state);

    testing_state.initialized = true;
    const id = try test_helpers.addNewSession(&testing_state);
    const new_session = testing_state.sessions.sessions.getPtr(id) orelse unreachable;

    var mechanism = pkcs.CK_MECHANISM{ .mechanism = pkcs.CKM_SHA256 };
    try p11_digest.digestInit(&testing_state, id, &mechanism);

    var data: [2]u8 = .{ 0x01, 0x02 };
    var buff: [32]u8 = @splat(0x00);
    var size: c_ulong = buff.len;
    const expected_digest: [32]u8 = .{
        0xa1, 0x28, 0x71, 0xfe, 0xe2, 0x10, 0xfb, 0x86, 0x19, 0x29, 0x1e, 0xae, 0xa1, 0x94, 0x58, 0x1c,
        0xbd, 0x25, 0x31, 0xe4, 0xb2, 0x37, 0x59, 0xd2, 0x25, 0xf6, 0x80, 0x69, 0x23, 0xf6, 0x32, 0x22,
    };

    try p11_digest.digestUpdate(&testing_state, id, (&data).ptr, (&data).len);
    try p11_digest.digestFinal(&testing_state, id, (&buff).ptr, &size);
    try std.testing.expectEqualSlices(u8, &expected_digest, &buff);
    try std.testing.expectEqual(.none, new_session.operation);
}
