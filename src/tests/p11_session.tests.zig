const std = @import("std");

const FailureCard = @import("FailureCard.zig").FailureCard;
const HealthyCard = @import("HealthyCard.zig");
const p11_digest = @import("../p11_digest.zig");
const p11_session = @import("../p11_session.zig");
const p11_sign = @import("../p11_sign.zig");
const pkcs = @import("../pkcs.zig");
const reader = @import("../smart-card/reader.zig");
const test_helpers = @import("test_helpers.zig");

const pin = "1234";

fn startDigest(state: anytype, session_handle: pkcs.CK_SESSION_HANDLE) !void {
    var mechanism = pkcs.CK_MECHANISM{ .mechanism = pkcs.CKM_SHA256 };
    try p11_digest.digestInit(state, session_handle, &mechanism);
}

test "openSession cryptoki initialization" {
    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    var session_handle: pkcs.CK_SESSION_HANDLE = 0;
    const result = p11_session.openSession(&testing_state, test_helpers.slot_id, pkcs.CKF_SERIAL_SESSION, null, null, &session_handle);
    try std.testing.expectError(error.CryptokiNotInitialized, result);
}

test "openSession parallel session not supported" {
    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    testing_state.initialized = true;
    try test_helpers.addReader(.{});

    var session_handle: pkcs.CK_SESSION_HANDLE = 0;
    const result = p11_session.openSession(&testing_state, test_helpers.slot_id, pkcs.CKF_RW_SESSION, null, null, &session_handle);
    try std.testing.expectError(error.SessionParallelNotSupported, result);
    try std.testing.expectEqual(0, testing_state.sessions.sessions.count());
}

test "openSession bad arguments" {
    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    testing_state.initialized = true;
    try test_helpers.addReader(.{});

    const result = p11_session.openSession(&testing_state, test_helpers.slot_id, pkcs.CKF_SERIAL_SESSION, null, null, null);
    try std.testing.expectError(error.ArgumentsBad, result);
    try std.testing.expectEqual(0, testing_state.sessions.sessions.count());
}

test "openSession invalid slot" {
    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    testing_state.initialized = true;

    var session_handle: pkcs.CK_SESSION_HANDLE = 0;
    const result = p11_session.openSession(&testing_state, 42, pkcs.CKF_SERIAL_SESSION, null, null, &session_handle);
    try std.testing.expectError(error.SlotIdInvalid, result);
    try std.testing.expectEqual(0, testing_state.sessions.sessions.count());
}

test "openSession token state" {
    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    testing_state.initialized = true;
    var session_handle: pkcs.CK_SESSION_HANDLE = 0;

    try test_helpers.addReader(.{ .card_present = false });
    const result1 = p11_session.openSession(&testing_state, test_helpers.slot_id, pkcs.CKF_SERIAL_SESSION, null, null, &session_handle);
    try std.testing.expectError(error.TokenNoPresent, result1);

    try test_helpers.addReader(.{ .recognized = false });
    const result2 = p11_session.openSession(&testing_state, test_helpers.slot_id, pkcs.CKF_SERIAL_SESSION, null, null, &session_handle);
    try std.testing.expectError(error.TokenNotRecognized, result2);

    try std.testing.expectEqual(0, testing_state.sessions.sessions.count());
}

test "openSession" {
    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    testing_state.initialized = true;
    try test_helpers.addReader(.{});

    var ro_handle: pkcs.CK_SESSION_HANDLE = 0;
    try p11_session.openSession(&testing_state, test_helpers.slot_id, pkcs.CKF_SERIAL_SESSION, null, null, &ro_handle);

    var rw_handle: pkcs.CK_SESSION_HANDLE = 0;
    try p11_session.openSession(&testing_state, test_helpers.slot_id, pkcs.CKF_SERIAL_SESSION | pkcs.CKF_RW_SESSION, null, null, &rw_handle);

    try std.testing.expect(ro_handle != rw_handle);
    try std.testing.expectEqual(2, testing_state.sessions.sessions.count());

    const ro_session = test_helpers.getSession(&testing_state, ro_handle);
    try std.testing.expectEqual(test_helpers.slot_id, ro_session.reader_id);
    try std.testing.expect(!ro_session.write_enabled);
    try test_helpers.expectOperation(&testing_state, ro_handle, .none);

    const rw_session = test_helpers.getSession(&testing_state, rw_handle);
    try std.testing.expectEqual(test_helpers.slot_id, rw_session.reader_id);
    try std.testing.expect(rw_session.write_enabled);
    try test_helpers.expectOperation(&testing_state, rw_handle, .none);
}

test "closeSession cryptoki initialization" {
    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    const result = p11_session.closeSession(&testing_state, 0);
    try std.testing.expectError(error.CryptokiNotInitialized, result);
}

test "closeSession invalid session handle" {
    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    testing_state.initialized = true;

    const result = p11_session.closeSession(&testing_state, 42);
    try std.testing.expectError(error.SessionHandleInvalid, result);
}

test "closeSession" {
    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    testing_state.initialized = true;
    var disconnects: usize = 0;
    const id = try test_helpers.addNewSessionWithoutKeys(&testing_state, HealthyCard{ .disconnects = &disconnects });

    try p11_session.closeSession(&testing_state, id);
    try std.testing.expectEqual(1, disconnects);
    try std.testing.expectEqual(0, testing_state.sessions.sessions.count());

    const result = p11_session.closeSession(&testing_state, id);
    try std.testing.expectError(error.SessionHandleInvalid, result);
    try std.testing.expectEqual(1, disconnects);
}

test "closeSession frees objects" {
    for (test_helpers.key_files) |key_file| {
        var key_pair = try test_helpers.loadKeyPair(key_file);
        defer key_pair.deinit();

        var testing_state = test_helpers.newTestingState(HealthyCard);
        defer test_helpers.deinitTestingState(&testing_state);

        testing_state.initialized = true;
        const id = try test_helpers.addNewSessionWithCard(&testing_state, HealthyCard{ .key_pair = &key_pair }, &key_pair);

        // The testing allocator reports a leak if any object memory stays allocated
        try p11_session.closeSession(&testing_state, id);
        try std.testing.expectEqual(0, testing_state.sessions.sessions.count());
    }
}

test "closeSession frees active operation" {
    for (test_helpers.key_files) |key_file| {
        var key_pair = try test_helpers.loadKeyPair(key_file);
        defer key_pair.deinit();

        var testing_state = test_helpers.newTestingState(HealthyCard);
        defer test_helpers.deinitTestingState(&testing_state);

        testing_state.initialized = true;
        const id = try test_helpers.addNewSessionWithCard(&testing_state, HealthyCard{ .key_pair = &key_pair }, &key_pair);
        try test_helpers.login();

        var mechanism = pkcs.CK_MECHANISM{ .mechanism = pkcs.CKM_RSA_PKCS };
        try p11_sign.signInit(&testing_state, id, &mechanism, test_helpers.private_key_handle);
        var data: [4]u8 = .{ 0x31, 0x32, 0x33, 0x34 };
        try p11_sign.signUpdate(&testing_state, id, &data, data.len);

        try p11_session.closeSession(&testing_state, id);
        try std.testing.expectEqual(0, testing_state.sessions.sessions.count());
    }
}

test "closeAllSessions cryptoki initialization" {
    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    const result = p11_session.closeAllSessions(&testing_state, test_helpers.slot_id);
    try std.testing.expectError(error.CryptokiNotInitialized, result);
}

test "closeAllSessions invalid slot" {
    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    testing_state.initialized = true;

    const result = p11_session.closeAllSessions(&testing_state, 42);
    try std.testing.expectError(error.SlotIdInvalid, result);
}

test "closeAllSessions closes only sessions of the slot" {
    for (test_helpers.key_files) |key_file| {
        var key_pair = try test_helpers.loadKeyPair(key_file);
        defer key_pair.deinit();

        var testing_state = test_helpers.newTestingState(HealthyCard);
        defer test_helpers.deinitTestingState(&testing_state);

        testing_state.initialized = true;
        const other_slot_id = test_helpers.slot_id + 1;
        try test_helpers.addReader(.{});
        try test_helpers.addReader(.{ .slot_id = other_slot_id });

        var disconnects: usize = 0;
        const card = HealthyCard{ .key_pair = &key_pair, .disconnects = &disconnects };
        const id1 = try test_helpers.addNewSessionWithCard(&testing_state, card, &key_pair);
        const id2 = try test_helpers.addNewSessionWithCard(&testing_state, card, &key_pair);
        const other_id = try test_helpers.addNewSessionWithCard(&testing_state, card, &key_pair);
        test_helpers.getSession(&testing_state, other_id).reader_id = other_slot_id;

        try p11_session.closeAllSessions(&testing_state, test_helpers.slot_id);
        try std.testing.expectEqual(2, disconnects);
        try std.testing.expectEqual(1, testing_state.sessions.sessions.count());
        try std.testing.expect(!testing_state.sessions.sessions.contains(id1));
        try std.testing.expect(!testing_state.sessions.sessions.contains(id2));
        try std.testing.expect(testing_state.sessions.sessions.contains(other_id));
    }
}

test "getSessionInfo cryptoki initialization" {
    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    var session_info: pkcs.CK_SESSION_INFO = undefined;
    const result = p11_session.getSessionInfo(&testing_state, 0, &session_info);
    try std.testing.expectError(error.CryptokiNotInitialized, result);
}

test "getSessionInfo invalid session handle" {
    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    testing_state.initialized = true;

    var session_info: pkcs.CK_SESSION_INFO = undefined;
    const result = p11_session.getSessionInfo(&testing_state, 42, &session_info);
    try std.testing.expectError(error.SessionHandleInvalid, result);
}

test "getSessionInfo bad arguments" {
    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    testing_state.initialized = true;
    const id = try test_helpers.addNewSessionWithoutKeys(&testing_state, HealthyCard{});

    const result = p11_session.getSessionInfo(&testing_state, id, null);
    try std.testing.expectError(error.ArgumentsBad, result);
}

test "getSessionInfo session states" {
    const cases = [_]struct {
        write_enabled: bool,
        user_type: reader.UserType,
        expected_state: pkcs.CK_STATE,
    }{
        .{ .write_enabled = false, .user_type = .None, .expected_state = pkcs.CKS_RO_PUBLIC_SESSION },
        .{ .write_enabled = true, .user_type = .None, .expected_state = pkcs.CKS_RW_PUBLIC_SESSION },
        .{ .write_enabled = false, .user_type = .User, .expected_state = pkcs.CKS_RO_USER_FUNCTIONS },
        .{ .write_enabled = true, .user_type = .User, .expected_state = pkcs.CKS_RW_USER_FUNCTIONS },
        .{ .write_enabled = true, .user_type = .SecurityOfficer, .expected_state = pkcs.CKS_RW_SO_FUNCTIONS },
    };

    for (cases) |case| {
        var testing_state = test_helpers.newTestingState(HealthyCard);
        defer test_helpers.deinitTestingState(&testing_state);

        testing_state.initialized = true;
        try test_helpers.addReader(.{ .user_type = case.user_type });
        const id = try test_helpers.addNewSessionWithoutKeys(&testing_state, HealthyCard{});
        test_helpers.getSession(&testing_state, id).write_enabled = case.write_enabled;

        var session_info: pkcs.CK_SESSION_INFO = undefined;
        try p11_session.getSessionInfo(&testing_state, id, &session_info);

        const expected_flags: pkcs.CK_FLAGS = pkcs.CKF_SERIAL_SESSION | if (case.write_enabled) pkcs.CKF_RW_SESSION else 0;
        try std.testing.expectEqual(test_helpers.slot_id, session_info.slotID);
        try std.testing.expectEqual(case.expected_state, session_info.state);
        try std.testing.expectEqual(expected_flags, session_info.flags);
        try std.testing.expectEqual(0, session_info.ulDeviceError);
    }
}

test "operation state not supported" {
    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    try std.testing.expectError(error.FunctionNotSupported, p11_session.getOperationState(&testing_state, 0, null, null));
    try std.testing.expectError(error.FunctionNotSupported, p11_session.setOperationState(&testing_state, 0, null, 0, 0, 0));
}

test "login cryptoki initialization" {
    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    const result = p11_session.login(&testing_state, 0, pkcs.CKU_USER, pin, pin.len);
    try std.testing.expectError(error.CryptokiNotInitialized, result);
}

test "login invalid session handle" {
    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    testing_state.initialized = true;

    const result = p11_session.login(&testing_state, 42, pkcs.CKU_USER, pin, pin.len);
    try std.testing.expectError(error.SessionHandleInvalid, result);
}

test "login user type invalid" {
    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    testing_state.initialized = true;
    try test_helpers.addReader(.{});
    const id = try test_helpers.addNewSessionWithoutKeys(&testing_state, HealthyCard{});

    const result1 = p11_session.login(&testing_state, id, pkcs.CKU_SO, pin, pin.len);
    try std.testing.expectError(error.UserTypeInvalid, result1);

    const result2 = p11_session.login(&testing_state, id, pkcs.CKU_CONTEXT_SPECIFIC, pin, pin.len);
    try std.testing.expectError(error.UserTypeInvalid, result2);

    try std.testing.expectEqual(.None, reader.getUserType(testing_state.io, test_helpers.slot_id));
}

test "login bad arguments" {
    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    testing_state.initialized = true;
    try test_helpers.addReader(.{});
    const id = try test_helpers.addNewSessionWithoutKeys(&testing_state, HealthyCard{});

    const result = p11_session.login(&testing_state, id, pkcs.CKU_USER, null, pin.len);
    try std.testing.expectError(error.ArgumentsBad, result);
    try std.testing.expectEqual(.None, reader.getUserType(testing_state.io, test_helpers.slot_id));
}

test "login invalid pin" {
    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    testing_state.initialized = true;
    try test_helpers.addReader(.{});
    const id = try test_helpers.addNewSessionWithoutKeys(&testing_state, HealthyCard{});

    const invalid_pins = [_][]const u8{ "123", "123456789", "12a4" };
    for (invalid_pins) |invalid_pin| {
        const result = p11_session.login(&testing_state, id, pkcs.CKU_USER, invalid_pin.ptr, invalid_pin.len);
        try std.testing.expectError(error.PinIncorrect, result);
    }

    try std.testing.expectEqual(.None, reader.getUserType(testing_state.io, test_helpers.slot_id));
}

test "login user already logged in" {
    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    testing_state.initialized = true;
    try test_helpers.addReader(.{ .user_type = .User });
    const id = try test_helpers.addNewSessionWithoutKeys(&testing_state, HealthyCard{});

    const result = p11_session.login(&testing_state, id, pkcs.CKU_USER, pin, pin.len);
    try std.testing.expectError(error.UserAlreadyLoggedIn, result);
}

test "login" {
    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    testing_state.initialized = true;
    try test_helpers.addReader(.{});
    const id = try test_helpers.addNewSessionWithoutKeys(&testing_state, HealthyCard{});
    const other_id = try test_helpers.addNewSessionWithoutKeys(&testing_state, HealthyCard{});
    try startDigest(&testing_state, id);

    try p11_session.login(&testing_state, id, pkcs.CKU_USER, pin, pin.len);
    try std.testing.expectEqual(.User, reader.getUserType(testing_state.io, test_helpers.slot_id));
    try test_helpers.expectOperation(&testing_state, id, .none);

    // Login state is shared by all sessions of the token
    var session_info: pkcs.CK_SESSION_INFO = undefined;
    try p11_session.getSessionInfo(&testing_state, other_id, &session_info);
    try std.testing.expectEqual(pkcs.CKS_RO_USER_FUNCTIONS, session_info.state);
}

test "login card failure" {
    const Card = FailureCard(HealthyCard);

    var testing_state = test_helpers.newTestingState(Card);
    defer test_helpers.deinitTestingState(&testing_state);

    testing_state.initialized = true;
    try test_helpers.addReader(.{});
    const id = try test_helpers.addNewSessionWithoutKeys(&testing_state, Card.init(.{}, .{ .fail_index = 0, .err = error.DeviceRemoved }));

    const result = p11_session.login(&testing_state, id, pkcs.CKU_USER, pin, pin.len);
    try std.testing.expectError(error.DeviceRemoved, result);
    try std.testing.expect(test_helpers.getSession(&testing_state, id).card.has_induced_failure);
    try std.testing.expectEqual(.None, reader.getUserType(testing_state.io, test_helpers.slot_id));
}

test "logout cryptoki initialization" {
    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    const result = p11_session.logout(&testing_state, 0);
    try std.testing.expectError(error.CryptokiNotInitialized, result);
}

test "logout invalid session handle" {
    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    testing_state.initialized = true;

    const result = p11_session.logout(&testing_state, 42);
    try std.testing.expectError(error.SessionHandleInvalid, result);
}

test "logout user not logged in" {
    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    testing_state.initialized = true;
    try test_helpers.addReader(.{});
    const id = try test_helpers.addNewSessionWithoutKeys(&testing_state, HealthyCard{});

    const result = p11_session.logout(&testing_state, id);
    try std.testing.expectError(error.UserNotLoggedIn, result);
}

test "logout" {
    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    testing_state.initialized = true;
    try test_helpers.addReader(.{ .user_type = .User });
    const id = try test_helpers.addNewSessionWithoutKeys(&testing_state, HealthyCard{});
    try startDigest(&testing_state, id);

    try p11_session.logout(&testing_state, id);
    try std.testing.expectEqual(.None, reader.getUserType(testing_state.io, test_helpers.slot_id));
    try test_helpers.expectOperation(&testing_state, id, .none);
}
