const std = @import("std");

const HealthyCard = @import("HealthyCard.helper.zig");
const p11_dual_functions = @import("../p11_dual_functions.zig");
const test_helpers = @import("test.helper.zig");

test "digestEncryptUpdate not supported" {
    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    try std.testing.expectError(error.FunctionNotSupported, p11_dual_functions.digestEncryptUpdate(&testing_state, 0, null, 0, null, null));
}

test "decryptDigestUpdate not supported" {
    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    try std.testing.expectError(error.FunctionNotSupported, p11_dual_functions.decryptDigestUpdate(&testing_state, 0, null, 0, null, null));
}

test "signEncryptUpdate not supported" {
    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    try std.testing.expectError(error.FunctionNotSupported, p11_dual_functions.signEncryptUpdate(&testing_state, 0, null, 0, null, null));
}

test "decryptVerifyUpdate not supported" {
    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    try std.testing.expectError(error.FunctionNotSupported, p11_dual_functions.decryptVerifyUpdate(&testing_state, 0, null, 0, null, null));
}
