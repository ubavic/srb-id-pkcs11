const std = @import("std");

const FailureCard = @import("FailureCard.helper.zig").FailureCard;
const HealthyCard = @import("HealthyCard.helper.zig");
const p11_random = @import("../p11_random.zig");
const test_helpers = @import("test.helper.zig");

/// The most random bytes requested from the card at once.
const segment_size = 128;

/// Card that answers random requests without the status word.
const ShortResponseCard = struct {
    open_transactions: usize = 0,

    pub const Transaction = struct {};

    pub fn startTransaction(self: *ShortResponseCard) !Transaction {
        self.open_transactions += 1;
        return .{};
    }

    pub fn endTransaction(self: *ShortResponseCard, _: Transaction) void {
        self.open_transactions -= 1;
    }

    pub fn readRandom(_: *ShortResponseCard, _: std.mem.Allocator, length: u8, out_buffer: []u8) ![]const u8 {
        @memset(out_buffer[0..length], 0x01);
        return out_buffer[0..length];
    }
};

test "seedRandom cryptoki initialization" {
    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    const result = p11_random.seedRandom(&testing_state, 0, null, 0);
    try std.testing.expectError(error.CryptokiNotInitialized, result);
}

test "seedRandom invalid session handle" {
    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    testing_state.initialized = true;

    const result = p11_random.seedRandom(&testing_state, 42, null, 0);
    try std.testing.expectError(error.SessionHandleInvalid, result);
}

test "seedRandom not supported" {
    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    testing_state.initialized = true;
    const id = try test_helpers.addNewSessionWithoutKeys(&testing_state, HealthyCard{});

    var seed: [4]u8 = .{ 0x01, 0x02, 0x03, 0x04 };
    const result = p11_random.seedRandom(&testing_state, id, &seed, seed.len);
    try std.testing.expectError(error.RandomSeedNotSupported, result);
}

test "generateRandom cryptoki initialization" {
    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    const result = p11_random.generateRandom(&testing_state, 0, null, 0);
    try std.testing.expectError(error.CryptokiNotInitialized, result);
}

test "generateRandom invalid session handle" {
    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    testing_state.initialized = true;

    var random_data: [16]u8 = undefined;
    const result = p11_random.generateRandom(&testing_state, 42, &random_data, random_data.len);
    try std.testing.expectError(error.SessionHandleInvalid, result);
}

test "generateRandom bad arguments" {
    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    testing_state.initialized = true;
    const id = try test_helpers.addNewSessionWithoutKeys(&testing_state, HealthyCard{});

    const result = p11_random.generateRandom(&testing_state, id, null, 16);
    try std.testing.expectError(error.ArgumentsBad, result);

    const card = &test_helpers.getSession(&testing_state, id).card;
    try std.testing.expectEqual(0, card.random_requests);
    try std.testing.expectEqual(0, card.open_transactions);
}

test "generateRandom does not require login" {
    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    testing_state.initialized = true;
    const id = try test_helpers.addNewSessionWithoutKeys(&testing_state, HealthyCard{});

    var random_data: [16]u8 = @splat(0x00);
    try p11_random.generateRandom(&testing_state, id, &random_data, random_data.len);

    const card = &test_helpers.getSession(&testing_state, id).card;
    try std.testing.expect(std.mem.allEqual(u8, &random_data, 0x01));
    try std.testing.expectEqual(1, card.random_requests);
    try std.testing.expectEqual(0, card.open_transactions);
}

test "generateRandom zero length" {
    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    testing_state.initialized = true;
    const id = try test_helpers.addNewSessionWithoutKeys(&testing_state, HealthyCard{});

    var random_data: [16]u8 = @splat(0x00);
    try p11_random.generateRandom(&testing_state, id, &random_data, 0);

    const card = &test_helpers.getSession(&testing_state, id).card;
    try std.testing.expect(std.mem.allEqual(u8, &random_data, 0x00));
    try std.testing.expectEqual(0, card.random_requests);
    try std.testing.expectEqual(0, card.open_transactions);
}

test "generateRandom splits request into segments" {
    const sizes = [_]usize{ 1, segment_size - 1, segment_size, segment_size + 1, 2 * segment_size, 300 };

    for (sizes) |size| {
        var testing_state = test_helpers.newTestingState(HealthyCard);
        defer test_helpers.deinitTestingState(&testing_state);

        testing_state.initialized = true;
        const id = try test_helpers.addNewSessionWithoutKeys(&testing_state, HealthyCard{});

        var random_data: [512]u8 = @splat(0x00);
        try p11_random.generateRandom(&testing_state, id, &random_data, size);

        const card = &test_helpers.getSession(&testing_state, id).card;
        try std.testing.expectEqual((size + segment_size - 1) / segment_size, card.random_requests);
        try std.testing.expectEqual(0, card.open_transactions);

        // Each segment holds the response of its own request
        for (random_data[0..size], 0..) |byte, i|
            try std.testing.expectEqual(i / segment_size + 1, byte);

        try std.testing.expect(std.mem.allEqual(u8, random_data[size..], 0x00));
    }
}

test "generateRandom card failure" {
    const Card = FailureCard(HealthyCard);

    var testing_state = test_helpers.newTestingState(Card);
    defer test_helpers.deinitTestingState(&testing_state);

    testing_state.initialized = true;
    const id = try test_helpers.addNewSessionWithoutKeys(&testing_state, Card.init(.{}, .{ .fail_index = 0, .err = error.DeviceRemoved }));

    var random_data: [16]u8 = undefined;
    const result = p11_random.generateRandom(&testing_state, id, &random_data, random_data.len);
    try std.testing.expectError(error.DeviceRemoved, result);

    const card = &test_helpers.getSession(&testing_state, id).card;
    try std.testing.expect(card.has_induced_failure);
    try std.testing.expectEqual(0, card.parent.random_requests);
    try std.testing.expectEqual(0, card.parent.open_transactions);
}

test "generateRandom card failure ends transaction" {
    const Card = FailureCard(HealthyCard);

    var testing_state = test_helpers.newTestingState(Card);
    defer test_helpers.deinitTestingState(&testing_state);

    testing_state.initialized = true;
    // Starting the transaction and the first segment succeed, the second segment fails
    const id = try test_helpers.addNewSessionWithoutKeys(&testing_state, Card.init(.{}, .{ .fail_index = 2 }));

    var random_data: [300]u8 = undefined;
    const result = p11_random.generateRandom(&testing_state, id, &random_data, random_data.len);
    try std.testing.expectError(error.DeviceError, result);

    const card = &test_helpers.getSession(&testing_state, id).card;
    try std.testing.expect(card.has_induced_failure);
    try std.testing.expectEqual(1, card.parent.random_requests);
    try std.testing.expectEqual(0, card.parent.open_transactions);
}

test "generateRandom short card response" {
    var testing_state = test_helpers.newTestingState(ShortResponseCard);
    defer test_helpers.deinitTestingState(&testing_state);

    testing_state.initialized = true;
    const id = try test_helpers.addNewSessionWithoutKeys(&testing_state, ShortResponseCard{});

    var random_data: [16]u8 = undefined;
    const result = p11_random.generateRandom(&testing_state, id, &random_data, random_data.len);
    try std.testing.expectError(error.DeviceError, result);
    try std.testing.expectEqual(0, test_helpers.getSession(&testing_state, id).card.open_transactions);
}
