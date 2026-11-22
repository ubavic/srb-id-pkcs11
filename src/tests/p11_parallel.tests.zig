const std = @import("std");

const HealthyCard = @import("HealthyCard.helper.zig");
const p11_parallel = @import("../p11_parallel.zig");
const test_helpers = @import("test.helper.zig");

test "getFunctionStatus not parallel" {
    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    try std.testing.expectError(error.FunctionNotParallel, p11_parallel.getFunctionStatus(&testing_state, 0));
}

test "cancelFunction not parallel" {
    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    try std.testing.expectError(error.FunctionNotParallel, p11_parallel.cancelFunction(&testing_state, 0));
}
