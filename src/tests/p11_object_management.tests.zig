const std = @import("std");

const HealthyCard = @import("HealthyCard.helper.zig");
const KeyPair = @import("KeyPair.helper.zig");
const p11_object_management = @import("../p11_object_management.zig");
const pkcs = @import("../pkcs.zig");
const test_helpers = @import("test.helper.zig");

test "createObject not supported" {
    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    try std.testing.expectError(error.FunctionNotSupported, p11_object_management.createObject(&testing_state, 0, null, 0, null));
}

test "copyObject not supported" {
    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    try std.testing.expectError(error.FunctionNotSupported, p11_object_management.copyObject(&testing_state, 0, 0, null, 0, null));
}

test "destroyObject not supported" {
    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    try std.testing.expectError(error.FunctionNotSupported, p11_object_management.destroyObject(&testing_state, 0, 0));
}

test "getObjectSize cryptoki initialization" {
    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    try std.testing.expectError(error.CryptokiNotInitialized, p11_object_management.getObjectSize(&testing_state, 0, 0, null));
}

test "getObjectSize invalid session handle" {
    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    testing_state.initialized = true;

    var size: pkcs.CK_ULONG = 0;
    const result = p11_object_management.getObjectSize(&testing_state, 42, test_helpers.public_key_handle, &size);
    try std.testing.expectError(error.SessionHandleInvalid, result);
    try std.testing.expectEqual(0, size);
}

test "getObjectSize bad arguments" {
    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    testing_state.initialized = true;
    const id = try test_helpers.addNewSession(&testing_state);

    try std.testing.expectError(error.ArgumentsBad, p11_object_management.getObjectSize(&testing_state, id, test_helpers.public_key_handle, null));
}

test "getObjectSize invalid object handle" {
    var key_pair = try test_helpers.loadKeyPair(test_helpers.key_files[0]);
    defer key_pair.deinit();

    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    testing_state.initialized = true;
    const id = try test_helpers.addNewSessionWithCard(&testing_state, HealthyCard{ .key_pair = &key_pair }, &key_pair);

    var size: pkcs.CK_ULONG = 7;
    const result = p11_object_management.getObjectSize(&testing_state, id, 0x1, &size);
    try std.testing.expectError(error.ObjectHandleInvalid, result);
    try std.testing.expectEqual(7, size);
}

test "getObjectSize" {
    var key_pair = try test_helpers.loadKeyPair(test_helpers.key_files[0]);
    defer key_pair.deinit();

    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    testing_state.initialized = true;
    const id = try test_helpers.addNewSessionWithCard(&testing_state, HealthyCard{ .key_pair = &key_pair }, &key_pair);

    var size: pkcs.CK_ULONG = 0;
    try p11_object_management.getObjectSize(&testing_state, id, test_helpers.public_key_handle, &size);
    try std.testing.expectEqual(test_helpers.public_key_size, size);

    try test_helpers.login();

    try p11_object_management.getObjectSize(&testing_state, id, test_helpers.private_key_handle, &size);
    try std.testing.expectEqual(test_helpers.private_key_size, size);
}

test "getObjectSize private object requires login" {
    var key_pair = try test_helpers.loadKeyPair(test_helpers.key_files[0]);
    defer key_pair.deinit();

    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    testing_state.initialized = true;
    const id = try test_helpers.addNewSessionWithCard(&testing_state, HealthyCard{ .key_pair = &key_pair }, &key_pair);

    var size: pkcs.CK_ULONG = 7;
    const result = p11_object_management.getObjectSize(&testing_state, id, test_helpers.private_key_handle, &size);
    try std.testing.expectError(error.ObjectHandleInvalid, result);
    try std.testing.expectEqual(7, size);
}

test "setAttributeValue not supported" {
    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    try std.testing.expectError(error.FunctionNotSupported, p11_object_management.setAttributeValue(&testing_state, 0, 0, null, 0));
}

test "getAttributeValue buffer too small" {
    var key_pair = try test_helpers.loadKeyPair(test_helpers.key_files[0]);
    defer key_pair.deinit();

    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    testing_state.initialized = true;
    const id = try test_helpers.addNewSessionWithCard(&testing_state, HealthyCard{ .key_pair = &key_pair }, &key_pair);

    var buffer: [4]u8 = @splat(0xaa);
    var template = [_]pkcs.CK_ATTRIBUTE{
        .{ .type = pkcs.CKA_MODULUS, .pValue = &buffer, .ulValueLen = buffer.len },
    };

    const result = p11_object_management.getAttributeValue(&testing_state, id, test_helpers.public_key_handle, &template, template.len);
    try std.testing.expectError(error.BufferTooSmall, result);

    // The length must be CK_UNAVAILABLE_INFORMATION, not the required size.
    try std.testing.expectEqual(pkcs.CK_UNAVAILABLE_INFORMATION, template[0].ulValueLen);

    // The buffer must not be written to.
    try std.testing.expectEqualSlices(u8, &@as([4]u8, @splat(0xaa)), &buffer);
}

test "getAttributeValue buffer one byte too small" {
    var key_pair = try test_helpers.loadKeyPair(test_helpers.key_files[0]);
    defer key_pair.deinit();

    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    testing_state.initialized = true;
    const id = try test_helpers.addNewSessionWithCard(&testing_state, HealthyCard{ .key_pair = &key_pair }, &key_pair);

    var buffer: [@sizeOf(pkcs.CK_ULONG)]u8 = undefined;
    var template = [_]pkcs.CK_ATTRIBUTE{
        .{ .type = pkcs.CKA_CLASS, .pValue = &buffer, .ulValueLen = buffer.len - 1 },
    };

    const result = p11_object_management.getAttributeValue(&testing_state, id, test_helpers.public_key_handle, &template, template.len);
    try std.testing.expectError(error.BufferTooSmall, result);
    try std.testing.expectEqual(pkcs.CK_UNAVAILABLE_INFORMATION, template[0].ulValueLen);
}

test "getAttributeValue exact buffer size" {
    var key_pair = try test_helpers.loadKeyPair(test_helpers.key_files[0]);
    defer key_pair.deinit();

    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    testing_state.initialized = true;
    const id = try test_helpers.addNewSessionWithCard(&testing_state, HealthyCard{ .key_pair = &key_pair }, &key_pair);

    var buffer: [@sizeOf(pkcs.CK_ULONG)]u8 = undefined;
    var template = [_]pkcs.CK_ATTRIBUTE{
        .{ .type = pkcs.CKA_CLASS, .pValue = &buffer, .ulValueLen = buffer.len },
    };

    try p11_object_management.getAttributeValue(&testing_state, id, test_helpers.public_key_handle, &template, template.len);

    try std.testing.expectEqual(@sizeOf(pkcs.CK_ULONG), template[0].ulValueLen);
    try std.testing.expectEqual(pkcs.CKO_PUBLIC_KEY, std.mem.bytesToValue(pkcs.CK_ULONG, &buffer));
}

test "getAttributeValue buffer larger than needed" {
    var key_pair = try test_helpers.loadKeyPair(test_helpers.key_files[0]);
    defer key_pair.deinit();

    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    testing_state.initialized = true;
    const id = try test_helpers.addNewSessionWithCard(&testing_state, HealthyCard{ .key_pair = &key_pair }, &key_pair);

    var buffer: [KeyPair.max_size]u8 = undefined;
    var template = [_]pkcs.CK_ATTRIBUTE{
        .{ .type = pkcs.CKA_MODULUS, .pValue = &buffer, .ulValueLen = buffer.len },
    };

    try p11_object_management.getAttributeValue(&testing_state, id, test_helpers.public_key_handle, &template, template.len);

    // Length is set to the exact length of the attribute.
    try std.testing.expectEqual(key_pair.modulus.len, template[0].ulValueLen);
    try std.testing.expectEqualSlices(u8, key_pair.modulus, buffer[0..template[0].ulValueLen]);
}

test "getAttributeValue null value returns length" {
    var key_pair = try test_helpers.loadKeyPair(test_helpers.key_files[0]);
    defer key_pair.deinit();

    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    testing_state.initialized = true;
    const id = try test_helpers.addNewSessionWithCard(&testing_state, HealthyCard{ .key_pair = &key_pair }, &key_pair);

    // ulValueLen is deliberately too small, but it must be ignored when pValue is null.
    var template = [_]pkcs.CK_ATTRIBUTE{
        .{ .type = pkcs.CKA_MODULUS, .pValue = null, .ulValueLen = 0 },
    };

    try p11_object_management.getAttributeValue(&testing_state, id, test_helpers.public_key_handle, &template, template.len);
    try std.testing.expectEqual(key_pair.modulus.len, template[0].ulValueLen);
}

test "getAttributeValue buffer too small does not stop processing" {
    var key_pair = try test_helpers.loadKeyPair(test_helpers.key_files[0]);
    defer key_pair.deinit();

    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    testing_state.initialized = true;
    const id = try test_helpers.addNewSessionWithCard(&testing_state, HealthyCard{ .key_pair = &key_pair }, &key_pair);

    var small_buffer: [1]u8 = undefined;
    var class_buffer: [@sizeOf(pkcs.CK_ULONG)]u8 = undefined;
    var template = [_]pkcs.CK_ATTRIBUTE{
        .{ .type = pkcs.CKA_MODULUS, .pValue = &small_buffer, .ulValueLen = small_buffer.len },
        .{ .type = pkcs.CKA_CLASS, .pValue = &class_buffer, .ulValueLen = class_buffer.len },
        .{ .type = pkcs.CKA_MODULUS, .pValue = null, .ulValueLen = 0 },
    };

    const result = p11_object_management.getAttributeValue(&testing_state, id, test_helpers.public_key_handle, &template, template.len);
    try std.testing.expectError(error.BufferTooSmall, result);

    // Attributes after the failing one must still be processed.
    try std.testing.expectEqual(pkcs.CK_UNAVAILABLE_INFORMATION, template[0].ulValueLen);
    try std.testing.expectEqual(@sizeOf(pkcs.CK_ULONG), template[1].ulValueLen);
    try std.testing.expectEqual(pkcs.CKO_PUBLIC_KEY, std.mem.bytesToValue(pkcs.CK_ULONG, &class_buffer));
    try std.testing.expectEqual(key_pair.modulus.len, template[2].ulValueLen);
}

test "getAttributeValue buffer too small and invalid attribute" {
    var key_pair = try test_helpers.loadKeyPair(test_helpers.key_files[0]);
    defer key_pair.deinit();

    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    testing_state.initialized = true;
    const id = try test_helpers.addNewSessionWithCard(&testing_state, HealthyCard{ .key_pair = &key_pair }, &key_pair);

    var small_buffer: [1]u8 = undefined;
    var template = [_]pkcs.CK_ATTRIBUTE{
        .{ .type = pkcs.CKA_MODULUS, .pValue = &small_buffer, .ulValueLen = small_buffer.len },
        .{ .type = pkcs.CKA_VALUE, .pValue = null, .ulValueLen = 0 },
    };

    // Both error codes are applicable, the module reports the invalid attribute type.
    const result = p11_object_management.getAttributeValue(&testing_state, id, test_helpers.public_key_handle, &template, template.len);
    try std.testing.expectError(error.AttributeTypeInvalid, result);

    // Each attribute is still marked individually.
    try std.testing.expectEqual(pkcs.CK_UNAVAILABLE_INFORMATION, template[0].ulValueLen);
    try std.testing.expectEqual(pkcs.CK_UNAVAILABLE_INFORMATION, template[1].ulValueLen);
}
