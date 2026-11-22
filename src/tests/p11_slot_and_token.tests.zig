const std = @import("std");

const HealthyCard = @import("HealthyCard.helper.zig");
const p11_slot_and_token = @import("../p11_slot_and_token.zig");
const test_helpers = @import("test.helper.zig");

test "initToken not supported" {
    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    try std.testing.expectError(error.FunctionNotSupported, p11_slot_and_token.initToken(&testing_state, test_helpers.slot_id, null, 0, null));
}

test "initPIN not supported" {
    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    try std.testing.expectError(error.FunctionNotSupported, p11_slot_and_token.initPIN(&testing_state, 0, null, 0));
}

test "waitForSlotEvent not supported" {
    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    try std.testing.expectError(error.FunctionNotSupported, p11_slot_and_token.waitForSlotEvent(&testing_state, 0, null, null));
}
