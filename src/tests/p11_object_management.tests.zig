const std = @import("std");

const HealthyCard = @import("HealthyCard.helper.zig");
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
