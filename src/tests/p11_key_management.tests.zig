const std = @import("std");

const HealthyCard = @import("HealthyCard.helper.zig");
const p11_key_management = @import("../p11_key_management.zig");
const test_helpers = @import("test.helper.zig");

test "generateKey not supported" {
    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    try std.testing.expectError(error.FunctionNotSupported, p11_key_management.generateKey(&testing_state, 0, null, null, 0, null));
}

test "generateKeyPair not supported" {
    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    try std.testing.expectError(error.FunctionNotSupported, p11_key_management.generateKeyPair(&testing_state, 0, null, null, 0, null, 0, null, null));
}

test "deriveKey not supported" {
    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    try std.testing.expectError(error.FunctionNotSupported, p11_key_management.deriveKey(&testing_state, 0, null, 0, null, 0, null));
}

test "wrapKey not supported" {
    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    try std.testing.expectError(error.FunctionNotSupported, p11_key_management.wrapKey(&testing_state, 0, null, 0, 0, null, null));
}

test "unwrapKey not supported" {
    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    try std.testing.expectError(error.FunctionNotSupported, p11_key_management.unwrapKey(&testing_state, 0, null, 0, null, 0, null, 0, null));
}
