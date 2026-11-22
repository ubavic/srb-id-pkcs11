const std = @import("std");

const HealthyCard = @import("HealthyCard.helper.zig");
const p11_object_management = @import("../p11_object_management.zig");
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

test "getObjectSize not supported" {
    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    try std.testing.expectError(error.FunctionNotSupported, p11_object_management.getObjectSize(&testing_state, 0, 0, null));
}

test "setAttributeValue not supported" {
    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    try std.testing.expectError(error.FunctionNotSupported, p11_object_management.setAttributeValue(&testing_state, 0, 0, null, 0));
}
