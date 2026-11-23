const std = @import("std");
const version = @import("options").version;

const HealthyCard = @import("HealthyCard.helper.zig");
const ModuleState = @import("../ModuleState.zig").ModuleState;
const pkcs = @import("../pkcs.zig");
const p11_general = @import("../p11_general.zig");
const reader = @import("../smart-card/reader.zig");
const test_helpers = @import("test.helper.zig");

/// State for tests that run the real `initialize` and `finalize`.
/// `finalize` frees the readers and sessions itself, so the state
/// must not be passed to `test_helpers.deinitTestingState`.
fn newLifecycleState() ModuleState(HealthyCard) {
    return .{
        .lock = std.Io.RwLock.init,
        .initialized = false,
        .allocator = std.testing.allocator,
        .io = std.testing.io,
    };
}

/// `initialize` connects to the PC/SC service, which may not be running.
/// Skips the test in that case.
fn initializeOrSkip(state: anytype, init_args: pkcs.CK_VOID_PTR) !void {
    p11_general.initialize(state, init_args) catch |err| switch (err) {
        error.FunctionFailed => return error.SkipZigTest,
        else => return err,
    };
}

fn createMutex(_: [*c]pkcs.CK_VOID_PTR) callconv(.c) pkcs.CK_RV {
    return pkcs.CKR_OK;
}

fn mutexOperation(_: pkcs.CK_VOID_PTR) callconv(.c) pkcs.CK_RV {
    return pkcs.CKR_OK;
}

test "initialize already initialized" {
    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    testing_state.initialized = true;

    const result = p11_general.initialize(&testing_state, null);
    try std.testing.expectError(error.CryptokiAlreadyInitialized, result);
    try std.testing.expect(testing_state.initialized);
}

test "initialize reserved not null" {
    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    var reserved: u8 = 0;
    var args = pkcs.CK_C_INITIALIZE_ARGS{ .pReserved = &reserved };

    const result = p11_general.initialize(&testing_state, &args);
    try std.testing.expectError(error.ArgumentsBad, result);
    try std.testing.expect(!testing_state.initialized);
}

test "initialize some mutex functions missing" {
    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    var args = pkcs.CK_C_INITIALIZE_ARGS{
        .CreateMutex = createMutex,
        .DestroyMutex = mutexOperation,
        .LockMutex = mutexOperation,
        .flags = pkcs.CKF_OS_LOCKING_OK,
    };

    const result = p11_general.initialize(&testing_state, &args);
    try std.testing.expectError(error.ArgumentsBad, result);
    try std.testing.expect(!testing_state.initialized);

    args = pkcs.CK_C_INITIALIZE_ARGS{
        .CreateMutex = createMutex,
        .LockMutex = mutexOperation,
        .UnlockMutex = mutexOperation,
        .flags = pkcs.CKF_OS_LOCKING_OK,
    };

    const result2 = p11_general.initialize(&testing_state, &args);
    try std.testing.expectError(error.ArgumentsBad, result2);
    try std.testing.expect(!testing_state.initialized);

    args = pkcs.CK_C_INITIALIZE_ARGS{
        .DestroyMutex = mutexOperation,
        .LockMutex = mutexOperation,
        .UnlockMutex = mutexOperation,
        .flags = pkcs.CKF_OS_LOCKING_OK,
    };

    const result3 = p11_general.initialize(&testing_state, &args);
    try std.testing.expectError(error.ArgumentsBad, result3);
    try std.testing.expect(!testing_state.initialized);
}

test "initialize mutex functions without os locking" {
    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    var args = pkcs.CK_C_INITIALIZE_ARGS{
        .CreateMutex = createMutex,
        .DestroyMutex = mutexOperation,
        .LockMutex = mutexOperation,
        .UnlockMutex = mutexOperation,
    };

    const result = p11_general.initialize(&testing_state, &args);
    try std.testing.expectError(error.CantLock, result);
    try std.testing.expect(!testing_state.initialized);
}

test "initialize state locked" {
    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    testing_state.lock.lockSharedUncancelable(testing_state.io);
    defer testing_state.lock.unlockShared(testing_state.io);

    const result = p11_general.initialize(&testing_state, null);
    try std.testing.expectError(error.FunctionFailed, result);
    try std.testing.expect(!testing_state.initialized);
}

test "initialize readers locked" {
    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    reader.lock.lockSharedUncancelable(testing_state.io);
    defer reader.lock.unlockShared(testing_state.io);

    const result = p11_general.initialize(&testing_state, null);
    try std.testing.expectError(error.FunctionFailed, result);
    try std.testing.expect(!testing_state.initialized);
}

test "finalize reserved not null" {
    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    testing_state.initialized = true;

    var reserved: u8 = 0;
    const result = p11_general.finalize(&testing_state, &reserved);
    try std.testing.expectError(error.ArgumentsBad, result);
    try std.testing.expect(testing_state.initialized);
}

test "finalize cryptoki initialization" {
    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    const result = p11_general.finalize(&testing_state, null);
    try std.testing.expectError(error.CryptokiNotInitialized, result);
}

test "finalize state locked" {
    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    testing_state.initialized = true;

    testing_state.lock.lockSharedUncancelable(testing_state.io);
    defer testing_state.lock.unlockShared(testing_state.io);

    const result = p11_general.finalize(&testing_state, null);
    try std.testing.expectError(error.FunctionFailed, result);
    try std.testing.expect(testing_state.initialized);
}

test "finalize readers locked" {
    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    testing_state.initialized = true;

    reader.lock.lockSharedUncancelable(testing_state.io);
    defer reader.lock.unlockShared(testing_state.io);

    const result = p11_general.finalize(&testing_state, null);
    try std.testing.expectError(error.FunctionFailed, result);
    try std.testing.expect(testing_state.initialized);
}

test "initialize with all mutex functions and os locking" {
    var args = pkcs.CK_C_INITIALIZE_ARGS{
        .CreateMutex = createMutex,
        .DestroyMutex = mutexOperation,
        .LockMutex = mutexOperation,
        .UnlockMutex = mutexOperation,
        .flags = pkcs.CKF_OS_LOCKING_OK,
    };

    var state = newLifecycleState();
    defer if (state.initialized) p11_general.finalize(&state, null) catch {};

    try initializeOrSkip(&state, &args);
    try std.testing.expect(state.initialized);

    try p11_general.finalize(&state, null);
    try std.testing.expect(!state.initialized);
}

test "initialize after finalize resets readers" {
    var state = newLifecycleState();
    defer if (state.initialized) p11_general.finalize(&state, null) catch {};

    try initializeOrSkip(&state, null);
    try std.testing.expect(state.initialized);

    // Pretend that a previous scan happened.
    reader.scanned = true;
    reader.next_reader_id = 5;

    const name = try std.testing.allocator.allocSentinel(u8, "Testing reader".len, 0);
    @memcpy(name, "Testing reader");
    errdefer std.testing.allocator.free(name);

    try reader.reader_states.put(1, .{
        .name = name,
        .active = true,
        .card_present = true,
        .recognized = true,
        .user_type = .None,
    });

    try p11_general.finalize(&state, null);
    try std.testing.expect(!state.initialized);
    try std.testing.expect(!reader.scanned);
    try std.testing.expectEqual(1, reader.next_reader_id);

    try p11_general.initialize(&state, null);
    try std.testing.expect(state.initialized);
    try std.testing.expect(!reader.scanned);
    try std.testing.expectEqual(1, reader.next_reader_id);
    try std.testing.expectEqual(0, reader.reader_states.count());
    try std.testing.expectEqual(0, state.sessions.sessions.count());

    try p11_general.finalize(&state, null);
    try std.testing.expect(!state.initialized);
}

test "getInfo cryptoki initialization" {
    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    var info: pkcs.CK_INFO = .{};
    const result = p11_general.getInfo(&testing_state, &info);
    try std.testing.expectError(error.CryptokiNotInitialized, result);
}

test "getInfo null info cryptoki initialization" {
    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    const result = p11_general.getInfo(&testing_state, null);
    try std.testing.expectError(error.CryptokiNotInitialized, result);
}

test "getInfo null info" {
    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    testing_state.initialized = true;

    const result = p11_general.getInfo(&testing_state, null);
    try std.testing.expectError(error.ArgumentsBad, result);
}

test "getInfo" {
    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    testing_state.initialized = true;

    var info: pkcs.CK_INFO = .{
        .manufacturerID = @splat(0xAA),
        .flags = 0xAA,
        .libraryDescription = @splat(0xAA),
    };
    try p11_general.getInfo(&testing_state, &info);

    try std.testing.expectEqual(pkcs.CRYPTOKI_VERSION_MAJOR, info.cryptokiVersion.major);
    try std.testing.expectEqual(pkcs.CRYPTOKI_VERSION_MINOR, info.cryptokiVersion.minor);
    try std.testing.expectEqual(0, info.flags);
    try std.testing.expectEqual(version.major, info.libraryVersion.major);
    try std.testing.expectEqual(version.minor, info.libraryVersion.minor);
}
