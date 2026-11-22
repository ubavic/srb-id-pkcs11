const std = @import("std");

const FailureCard = @import("FailureCard.zig").FailureCard;
const HealthyCard = @import("HealthyCard.zig");
const KeyPair = @import("KeyPair.zig");
const p11_decryption = @import("../p11_decryption.zig");
const p11_encryption = @import("../p11_encryption.zig");
const pkcs = @import("../pkcs.zig");
const test_helpers = @import("test_helpers.zig");

fn encryptData(
    state: anytype,
    session_handle: pkcs.CK_SESSION_HANDLE,
    mechanism: *pkcs.CK_MECHANISM,
    data: []const u8,
    encrypted_data: []u8,
) ![]u8 {
    var encrypted_data_len: pkcs.CK_ULONG = encrypted_data.len;

    try p11_encryption.encryptInit(state, session_handle, mechanism, test_helpers.public_key_handle);
    try p11_encryption.encrypt(state, session_handle, data.ptr, data.len, encrypted_data.ptr, &encrypted_data_len);

    return encrypted_data[0..encrypted_data_len];
}

test "decryptInit cryptoki initialization" {
    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    const result = p11_decryption.decryptInit(&testing_state, 0, null, 0);
    try std.testing.expectError(error.CryptokiNotInitialized, result);
}

test "decryptInit invalid session handle" {
    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    testing_state.initialized = true;

    const result = p11_decryption.decryptInit(&testing_state, 42, null, 0);
    try std.testing.expectError(error.SessionHandleInvalid, result);
}

test "decryptInit user not logged in" {
    var key_pair = try test_helpers.loadKeyPair(test_helpers.key_files[1]);
    defer key_pair.deinit();

    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    testing_state.initialized = true;
    const id = try test_helpers.addNewSessionWithCard(&testing_state, HealthyCard{ .key_pair = &key_pair }, &key_pair);

    var mechanism = pkcs.CK_MECHANISM{ .mechanism = pkcs.CKM_RSA_PKCS };
    const result = p11_decryption.decryptInit(&testing_state, id, &mechanism, test_helpers.private_key_handle);
    try std.testing.expectError(error.UserNotLoggedIn, result);
    try test_helpers.expectOperation(&testing_state, id, .none);
}

test "decryptInit bad mechanism" {
    var key_pair = try test_helpers.loadKeyPair(test_helpers.key_files[0]);
    defer key_pair.deinit();

    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    testing_state.initialized = true;
    const id = try test_helpers.addNewSessionWithCard(&testing_state, HealthyCard{ .key_pair = &key_pair }, &key_pair);
    try test_helpers.login();

    const result1 = p11_decryption.decryptInit(&testing_state, id, null, test_helpers.private_key_handle);
    try std.testing.expectError(error.ArgumentsBad, result1);

    var sign_mechanism = pkcs.CK_MECHANISM{ .mechanism = pkcs.CKM_SHA256_RSA_PKCS };
    const result2 = p11_decryption.decryptInit(&testing_state, id, &sign_mechanism, test_helpers.private_key_handle);
    try std.testing.expectError(error.MechanismInvalid, result2);

    try test_helpers.expectOperation(&testing_state, id, .none);
}

test "decryptInit invalid key handle" {
    var key_pair = try test_helpers.loadKeyPair(test_helpers.key_files[1]);
    defer key_pair.deinit();

    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    testing_state.initialized = true;
    const id = try test_helpers.addNewSessionWithCard(&testing_state, HealthyCard{ .key_pair = &key_pair }, &key_pair);
    try test_helpers.login();

    var mechanism = pkcs.CK_MECHANISM{ .mechanism = pkcs.CKM_RSA_PKCS };

    const result1 = p11_decryption.decryptInit(&testing_state, id, &mechanism, 42);
    try std.testing.expectError(error.KeyHandleInvalid, result1);

    const result2 = p11_decryption.decryptInit(&testing_state, id, &mechanism, test_helpers.public_key_handle);
    try std.testing.expectError(error.KeyHandleInvalid, result2);

    try test_helpers.expectOperation(&testing_state, id, .none);
}

test "decryptInit key function not permitted" {
    for (test_helpers.key_files) |key_file| {
        var key_pair = try test_helpers.loadKeyPair(key_file);
        defer key_pair.deinit();

        var testing_state = test_helpers.newTestingState(HealthyCard);
        defer test_helpers.deinitTestingState(&testing_state);

        testing_state.initialized = true;
        const id = try test_helpers.addNewSessionWithCard(&testing_state, HealthyCard{ .key_pair = &key_pair }, &key_pair);
        try test_helpers.login();

        const session = test_helpers.getSession(&testing_state, id);
        const private_key = try session.getObject(testing_state.io, test_helpers.private_key_handle);
        private_key.private_key.decrypt = pkcs.CK_FALSE;

        var mechanism = pkcs.CK_MECHANISM{ .mechanism = pkcs.CKM_RSA_PKCS };
        const result = p11_decryption.decryptInit(&testing_state, id, &mechanism, test_helpers.private_key_handle);
        try std.testing.expectError(error.KeyFunctionNotPermitted, result);
        try test_helpers.expectOperation(&testing_state, id, .none);
    }
}

test "decryptInit operation active" {
    for (test_helpers.key_files) |key_file| {
        var key_pair = try test_helpers.loadKeyPair(key_file);
        defer key_pair.deinit();

        var testing_state = test_helpers.newTestingState(HealthyCard);
        defer test_helpers.deinitTestingState(&testing_state);

        testing_state.initialized = true;
        const id = try test_helpers.addNewSessionWithCard(&testing_state, HealthyCard{ .key_pair = &key_pair }, &key_pair);
        try test_helpers.login();

        var mechanism = pkcs.CK_MECHANISM{ .mechanism = pkcs.CKM_RSA_PKCS };
        try p11_decryption.decryptInit(&testing_state, id, &mechanism, test_helpers.private_key_handle);

        const result = p11_decryption.decryptInit(&testing_state, id, &mechanism, test_helpers.private_key_handle);
        try std.testing.expectError(error.OperationActive, result);
        try test_helpers.expectOperation(&testing_state, id, .decrypt);
    }
}

test "decrypt cryptoki initialization" {
    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    const result = p11_decryption.decrypt(&testing_state, 0, null, 0, null, null);
    try std.testing.expectError(error.CryptokiNotInitialized, result);
}

test "decrypt operation not initialized" {
    var key_pair = try test_helpers.loadKeyPair(test_helpers.key_files[0]);
    defer key_pair.deinit();

    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    testing_state.initialized = true;
    const id = try test_helpers.addNewSessionWithCard(&testing_state, HealthyCard{ .key_pair = &key_pair }, &key_pair);
    try test_helpers.login();

    const result = p11_decryption.decrypt(&testing_state, id, null, 0, null, null);
    try std.testing.expectError(error.OperationNotInitialized, result);
}

test "decrypt data size query keeps operation" {
    for (test_helpers.key_files) |key_file| {
        var key_pair = try test_helpers.loadKeyPair(key_file);
        defer key_pair.deinit();

        var testing_state = test_helpers.newTestingState(HealthyCard);
        defer test_helpers.deinitTestingState(&testing_state);

        testing_state.initialized = true;
        const id = try test_helpers.addNewSessionWithCard(&testing_state, HealthyCard{ .key_pair = &key_pair }, &key_pair);
        try test_helpers.login();

        var mechanism = pkcs.CK_MECHANISM{ .mechanism = pkcs.CKM_RSA_PKCS };
        try p11_decryption.decryptInit(&testing_state, id, &mechanism, test_helpers.private_key_handle);

        const encrypted_buffer: [KeyPair.max_size]u8 = @splat(0x01);
        const encrypted_data = encrypted_buffer[0..key_pair.size()];
        var data: [KeyPair.max_size]u8 = undefined;
        var data_len: pkcs.CK_ULONG = 0;

        try p11_decryption.decrypt(&testing_state, id, encrypted_data.ptr, encrypted_data.len, null, &data_len);
        try std.testing.expectEqual(key_pair.size(), data_len);
        try test_helpers.expectOperation(&testing_state, id, .decrypt);

        data_len = key_pair.size() - 1;
        const result = p11_decryption.decrypt(&testing_state, id, encrypted_data.ptr, encrypted_data.len, &data, &data_len);
        try std.testing.expectError(error.BufferTooSmall, result);
        try test_helpers.expectOperation(&testing_state, id, .decrypt);
        try std.testing.expectEqual(0, test_helpers.getSession(&testing_state, id).card.decrypt_requests);
    }
}

test "decrypt bad arguments" {
    for (test_helpers.key_files) |key_file| {
        var key_pair = try test_helpers.loadKeyPair(key_file);
        defer key_pair.deinit();

        var testing_state = test_helpers.newTestingState(HealthyCard);
        defer test_helpers.deinitTestingState(&testing_state);

        testing_state.initialized = true;
        const id = try test_helpers.addNewSessionWithCard(&testing_state, HealthyCard{ .key_pair = &key_pair }, &key_pair);
        try test_helpers.login();

        var mechanism = pkcs.CK_MECHANISM{ .mechanism = pkcs.CKM_RSA_PKCS };
        const encrypted_buffer: [KeyPair.max_size]u8 = @splat(0x01);
        const encrypted_data = encrypted_buffer[0..key_pair.size()];
        var data: [KeyPair.max_size]u8 = undefined;
        var data_len: pkcs.CK_ULONG = data.len;

        try p11_decryption.decryptInit(&testing_state, id, &mechanism, test_helpers.private_key_handle);
        const result1 = p11_decryption.decrypt(&testing_state, id, encrypted_data.ptr, encrypted_data.len, &data, null);
        try std.testing.expectError(error.ArgumentsBad, result1);
        try test_helpers.expectOperation(&testing_state, id, .none);

        try p11_decryption.decryptInit(&testing_state, id, &mechanism, test_helpers.private_key_handle);
        const result2 = p11_decryption.decrypt(&testing_state, id, null, encrypted_data.len, &data, &data_len);
        try std.testing.expectError(error.ArgumentsBad, result2);
        try test_helpers.expectOperation(&testing_state, id, .none);

        try std.testing.expectEqual(0, test_helpers.getSession(&testing_state, id).card.decrypt_requests);
    }
}

test "decrypt fails on multipart operation" {
    for (test_helpers.key_files) |key_file| {
        var key_pair = try test_helpers.loadKeyPair(key_file);
        defer key_pair.deinit();

        var testing_state = test_helpers.newTestingState(HealthyCard);
        defer test_helpers.deinitTestingState(&testing_state);

        testing_state.initialized = true;
        const id = try test_helpers.addNewSessionWithCard(&testing_state, HealthyCard{ .key_pair = &key_pair }, &key_pair);
        try test_helpers.login();

        var mechanism = pkcs.CK_MECHANISM{ .mechanism = pkcs.CKM_RSA_PKCS };
        try p11_decryption.decryptInit(&testing_state, id, &mechanism, test_helpers.private_key_handle);

        const encrypted_buffer: [KeyPair.max_size]u8 = @splat(0x01);
        const encrypted_data = encrypted_buffer[0..key_pair.size()];
        var data: [KeyPair.max_size]u8 = undefined;
        var data_len: pkcs.CK_ULONG = data.len;

        try p11_decryption.decryptUpdate(&testing_state, id, encrypted_data.ptr, 64, &data, &data_len);

        data_len = data.len;
        const result = p11_decryption.decrypt(&testing_state, id, encrypted_data.ptr, encrypted_data.len, &data, &data_len);
        try std.testing.expectError(error.FunctionCanceled, result);
        try test_helpers.expectOperation(&testing_state, id, .none);
    }
}

test "decrypt encrypted data length range" {
    for (test_helpers.key_files) |key_file| {
        var key_pair = try test_helpers.loadKeyPair(key_file);
        defer key_pair.deinit();

        var testing_state = test_helpers.newTestingState(HealthyCard);
        defer test_helpers.deinitTestingState(&testing_state);

        testing_state.initialized = true;
        const id = try test_helpers.addNewSessionWithCard(&testing_state, HealthyCard{ .key_pair = &key_pair }, &key_pair);
        try test_helpers.login();

        var mechanism = pkcs.CK_MECHANISM{ .mechanism = pkcs.CKM_RSA_PKCS };
        try p11_decryption.decryptInit(&testing_state, id, &mechanism, test_helpers.private_key_handle);

        const encrypted_buffer: [KeyPair.max_size]u8 = @splat(0x01);
        const encrypted_data = encrypted_buffer[0 .. key_pair.size() - 1];
        var data: [KeyPair.max_size]u8 = undefined;
        var data_len: pkcs.CK_ULONG = data.len;

        const result = p11_decryption.decrypt(&testing_state, id, encrypted_data.ptr, encrypted_data.len, &data, &data_len);
        try std.testing.expectError(error.EncryptedDataLenRange, result);
        try test_helpers.expectOperation(&testing_state, id, .none);
        try std.testing.expectEqual(0, test_helpers.getSession(&testing_state, id).card.decrypt_requests);
    }
}

test "decrypt invalid padding" {
    for (test_helpers.key_files) |key_file| {
        var key_pair = try test_helpers.loadKeyPair(key_file);
        defer key_pair.deinit();

        var testing_state = test_helpers.newTestingState(HealthyCard);
        defer test_helpers.deinitTestingState(&testing_state);

        testing_state.initialized = true;
        const id = try test_helpers.addNewSessionWithCard(&testing_state, HealthyCard{ .key_pair = &key_pair }, &key_pair);
        try test_helpers.login();

        // PKCS#1 v1.5 block without the zero byte separating padding from the message
        var raw_mechanism = pkcs.CK_MECHANISM{ .mechanism = pkcs.CKM_RSA_X_509 };
        var block: [KeyPair.max_size]u8 = @splat(0x01);
        block[0] = 0x00;
        block[1] = 0x02;
        var encrypted_buffer: [KeyPair.max_size]u8 = undefined;
        const encrypted_data = try encryptData(&testing_state, id, &raw_mechanism, block[0..key_pair.size()], &encrypted_buffer);

        var mechanism = pkcs.CK_MECHANISM{ .mechanism = pkcs.CKM_RSA_PKCS };
        try p11_decryption.decryptInit(&testing_state, id, &mechanism, test_helpers.private_key_handle);

        var data: [KeyPair.max_size]u8 = undefined;
        var data_len: pkcs.CK_ULONG = data.len;
        const result = p11_decryption.decrypt(&testing_state, id, encrypted_data.ptr, encrypted_data.len, &data, &data_len);
        try std.testing.expectError(error.EncryptedDataInvalid, result);
        try test_helpers.expectOperation(&testing_state, id, .none);
    }
}

test "decrypt" {
    for (test_helpers.key_files) |key_file| {
        var key_pair = try test_helpers.loadKeyPair(key_file);
        defer key_pair.deinit();

        var testing_state = test_helpers.newTestingState(HealthyCard);
        defer test_helpers.deinitTestingState(&testing_state);

        testing_state.initialized = true;
        const id = try test_helpers.addNewSessionWithCard(&testing_state, HealthyCard{ .key_pair = &key_pair }, &key_pair);
        try test_helpers.login();

        var mechanism = pkcs.CK_MECHANISM{ .mechanism = pkcs.CKM_RSA_PKCS };
        const message: [4]u8 = .{ 0x31, 0x32, 0x33, 0x34 };
        var encrypted_buffer: [KeyPair.max_size]u8 = undefined;
        const encrypted_data = try encryptData(&testing_state, id, &mechanism, &message, &encrypted_buffer);

        try p11_decryption.decryptInit(&testing_state, id, &mechanism, test_helpers.private_key_handle);

        var data: [KeyPair.max_size]u8 = undefined;
        var data_len: pkcs.CK_ULONG = data.len;
        try p11_decryption.decrypt(&testing_state, id, encrypted_data.ptr, encrypted_data.len, &data, &data_len);
        try std.testing.expectEqualSlices(u8, &message, data[0..data_len]);
        try std.testing.expectEqual(1, test_helpers.getSession(&testing_state, id).card.decrypt_requests);
        try test_helpers.expectOperation(&testing_state, id, .none);
    }
}

test "decrypt card failure" {
    const Card = FailureCard(HealthyCard);

    for (test_helpers.key_files) |key_file| {
        var key_pair = try test_helpers.loadKeyPair(key_file);
        defer key_pair.deinit();

        var testing_state = test_helpers.newTestingState(Card);
        defer test_helpers.deinitTestingState(&testing_state);

        testing_state.initialized = true;
        const card = Card.init(.{ .key_pair = &key_pair }, .{ .fail_index = 0, .err = error.DeviceRemoved });
        const id = try test_helpers.addNewSessionWithCard(&testing_state, card, &key_pair);
        try test_helpers.login();

        var mechanism = pkcs.CK_MECHANISM{ .mechanism = pkcs.CKM_RSA_PKCS };
        const message: [4]u8 = .{ 0x31, 0x32, 0x33, 0x34 };
        var encrypted_buffer: [KeyPair.max_size]u8 = undefined;
        const encrypted_data = try encryptData(&testing_state, id, &mechanism, &message, &encrypted_buffer);

        try p11_decryption.decryptInit(&testing_state, id, &mechanism, test_helpers.private_key_handle);

        var data: [KeyPair.max_size]u8 = undefined;
        var data_len: pkcs.CK_ULONG = data.len;
        const result = p11_decryption.decrypt(&testing_state, id, encrypted_data.ptr, encrypted_data.len, &data, &data_len);
        try std.testing.expectError(error.DeviceRemoved, result);
        try std.testing.expect(test_helpers.getSession(&testing_state, id).card.has_induced_failure);
        try test_helpers.expectOperation(&testing_state, id, .none);
    }
}

test "decrypt card failure after successful decryption" {
    const Card = FailureCard(HealthyCard);

    for (test_helpers.key_files) |key_file| {
        var key_pair = try test_helpers.loadKeyPair(key_file);
        defer key_pair.deinit();

        var testing_state = test_helpers.newTestingState(Card);
        defer test_helpers.deinitTestingState(&testing_state);

        testing_state.initialized = true;
        const card = Card.init(.{ .key_pair = &key_pair }, .{ .fail_index = 1 });
        const id = try test_helpers.addNewSessionWithCard(&testing_state, card, &key_pair);
        try test_helpers.login();

        var mechanism = pkcs.CK_MECHANISM{ .mechanism = pkcs.CKM_RSA_PKCS };
        const message: [4]u8 = .{ 0x31, 0x32, 0x33, 0x34 };
        var encrypted_buffer: [KeyPair.max_size]u8 = undefined;
        const encrypted_data = try encryptData(&testing_state, id, &mechanism, &message, &encrypted_buffer);

        var data: [KeyPair.max_size]u8 = undefined;
        var data_len: pkcs.CK_ULONG = data.len;

        try p11_decryption.decryptInit(&testing_state, id, &mechanism, test_helpers.private_key_handle);
        try p11_decryption.decrypt(&testing_state, id, encrypted_data.ptr, encrypted_data.len, &data, &data_len);
        try std.testing.expect(!test_helpers.getSession(&testing_state, id).card.has_induced_failure);

        data_len = data.len;
        try p11_decryption.decryptInit(&testing_state, id, &mechanism, test_helpers.private_key_handle);
        const result = p11_decryption.decrypt(&testing_state, id, encrypted_data.ptr, encrypted_data.len, &data, &data_len);
        try std.testing.expectError(error.DeviceError, result);
        try std.testing.expect(test_helpers.getSession(&testing_state, id).card.has_induced_failure);
        try test_helpers.expectOperation(&testing_state, id, .none);
    }
}

test "decryptUpdate cryptoki initialization" {
    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    const result = p11_decryption.decryptUpdate(&testing_state, 0, null, 0, null, null);
    try std.testing.expectError(error.CryptokiNotInitialized, result);
}

test "decryptUpdate operation not initialized" {
    for (test_helpers.key_files) |key_file| {
        var key_pair = try test_helpers.loadKeyPair(key_file);
        defer key_pair.deinit();

        var testing_state = test_helpers.newTestingState(HealthyCard);
        defer test_helpers.deinitTestingState(&testing_state);

        testing_state.initialized = true;
        const id = try test_helpers.addNewSessionWithCard(&testing_state, HealthyCard{ .key_pair = &key_pair }, &key_pair);
        try test_helpers.login();

        const result = p11_decryption.decryptUpdate(&testing_state, id, null, 0, null, null);
        try std.testing.expectError(error.OperationNotInitialized, result);
    }
}

test "decryptUpdate bad arguments" {
    for (test_helpers.key_files) |key_file| {
        var key_pair = try test_helpers.loadKeyPair(key_file);
        defer key_pair.deinit();

        var testing_state = test_helpers.newTestingState(HealthyCard);
        defer test_helpers.deinitTestingState(&testing_state);

        testing_state.initialized = true;
        const id = try test_helpers.addNewSessionWithCard(&testing_state, HealthyCard{ .key_pair = &key_pair }, &key_pair);
        try test_helpers.login();

        var mechanism = pkcs.CK_MECHANISM{ .mechanism = pkcs.CKM_RSA_PKCS };
        const encrypted_part: [64]u8 = @splat(0x01);
        var part: [KeyPair.max_size]u8 = undefined;
        var part_len: pkcs.CK_ULONG = part.len;

        try p11_decryption.decryptInit(&testing_state, id, &mechanism, test_helpers.private_key_handle);
        const result1 = p11_decryption.decryptUpdate(&testing_state, id, &encrypted_part, encrypted_part.len, &part, null);
        try std.testing.expectError(error.ArgumentsBad, result1);
        try test_helpers.expectOperation(&testing_state, id, .none);

        try p11_decryption.decryptInit(&testing_state, id, &mechanism, test_helpers.private_key_handle);
        const result2 = p11_decryption.decryptUpdate(&testing_state, id, null, encrypted_part.len, &part, &part_len);
        try std.testing.expectError(error.ArgumentsBad, result2);
        try test_helpers.expectOperation(&testing_state, id, .none);
    }
}

test "decryptUpdate produces no output" {
    for (test_helpers.key_files) |key_file| {
        var key_pair = try test_helpers.loadKeyPair(key_file);
        defer key_pair.deinit();

        var testing_state = test_helpers.newTestingState(HealthyCard);
        defer test_helpers.deinitTestingState(&testing_state);

        testing_state.initialized = true;
        const id = try test_helpers.addNewSessionWithCard(&testing_state, HealthyCard{ .key_pair = &key_pair }, &key_pair);
        try test_helpers.login();

        var mechanism = pkcs.CK_MECHANISM{ .mechanism = pkcs.CKM_RSA_PKCS };
        try p11_decryption.decryptInit(&testing_state, id, &mechanism, test_helpers.private_key_handle);

        const encrypted_part: [64]u8 = @splat(0x01);
        var part: [KeyPair.max_size]u8 = undefined;
        var part_len: pkcs.CK_ULONG = part.len;

        try p11_decryption.decryptUpdate(&testing_state, id, &encrypted_part, encrypted_part.len, null, &part_len);
        try std.testing.expectEqual(0, part_len);

        part_len = part.len;
        try p11_decryption.decryptUpdate(&testing_state, id, &encrypted_part, encrypted_part.len, &part, &part_len);
        try std.testing.expectEqual(0, part_len);
        try test_helpers.expectOperation(&testing_state, id, .decrypt);
        try std.testing.expectEqual(0, test_helpers.getSession(&testing_state, id).card.decrypt_requests);
    }
}

test "decryptFinal cryptoki initialization" {
    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    const result = p11_decryption.decryptFinal(&testing_state, 0, null, null);
    try std.testing.expectError(error.CryptokiNotInitialized, result);
}

test "decryptFinal bad arguments" {
    for (test_helpers.key_files) |key_file| {
        var key_pair = try test_helpers.loadKeyPair(key_file);
        defer key_pair.deinit();

        var testing_state = test_helpers.newTestingState(HealthyCard);
        defer test_helpers.deinitTestingState(&testing_state);

        testing_state.initialized = true;
        const id = try test_helpers.addNewSessionWithCard(&testing_state, HealthyCard{ .key_pair = &key_pair }, &key_pair);
        try test_helpers.login();

        var mechanism = pkcs.CK_MECHANISM{ .mechanism = pkcs.CKM_RSA_PKCS };
        try p11_decryption.decryptInit(&testing_state, id, &mechanism, test_helpers.private_key_handle);

        var last_part: [KeyPair.max_size]u8 = undefined;
        const result = p11_decryption.decryptFinal(&testing_state, id, &last_part, null);
        try std.testing.expectError(error.ArgumentsBad, result);
        try test_helpers.expectOperation(&testing_state, id, .none);
    }
}

test "decryptFinal data size query keeps operation" {
    for (test_helpers.key_files) |key_file| {
        var key_pair = try test_helpers.loadKeyPair(key_file);
        defer key_pair.deinit();

        var testing_state = test_helpers.newTestingState(HealthyCard);
        defer test_helpers.deinitTestingState(&testing_state);

        testing_state.initialized = true;
        const id = try test_helpers.addNewSessionWithCard(&testing_state, HealthyCard{ .key_pair = &key_pair }, &key_pair);
        try test_helpers.login();

        var mechanism = pkcs.CK_MECHANISM{ .mechanism = pkcs.CKM_RSA_PKCS };
        try p11_decryption.decryptInit(&testing_state, id, &mechanism, test_helpers.private_key_handle);

        var last_part: [KeyPair.max_size]u8 = undefined;
        var last_part_len: pkcs.CK_ULONG = 0;

        try p11_decryption.decryptFinal(&testing_state, id, null, &last_part_len);
        try std.testing.expectEqual(key_pair.size(), last_part_len);
        try test_helpers.expectOperation(&testing_state, id, .decrypt);

        last_part_len = key_pair.size() - 1;
        const result = p11_decryption.decryptFinal(&testing_state, id, &last_part, &last_part_len);
        try std.testing.expectError(error.BufferTooSmall, result);
        try test_helpers.expectOperation(&testing_state, id, .decrypt);
    }
}

test "decryptFinal" {
    for (test_helpers.key_files) |key_file| {
        var key_pair = try test_helpers.loadKeyPair(key_file);
        defer key_pair.deinit();

        var testing_state = test_helpers.newTestingState(HealthyCard);
        defer test_helpers.deinitTestingState(&testing_state);

        testing_state.initialized = true;
        const id = try test_helpers.addNewSessionWithCard(&testing_state, HealthyCard{ .key_pair = &key_pair }, &key_pair);
        try test_helpers.login();

        var mechanism = pkcs.CK_MECHANISM{ .mechanism = pkcs.CKM_RSA_PKCS };
        const message: [4]u8 = .{ 0x31, 0x32, 0x33, 0x34 };
        var encrypted_buffer: [KeyPair.max_size]u8 = undefined;
        const encrypted_data = try encryptData(&testing_state, id, &mechanism, &message, &encrypted_buffer);

        try p11_decryption.decryptInit(&testing_state, id, &mechanism, test_helpers.private_key_handle);

        var part: [KeyPair.max_size]u8 = undefined;
        var part_len: pkcs.CK_ULONG = part.len;
        try p11_decryption.decryptUpdate(&testing_state, id, encrypted_data.ptr, 64, &part, &part_len);
        part_len = part.len;
        try p11_decryption.decryptUpdate(&testing_state, id, encrypted_data[64..].ptr, encrypted_data.len - 64, &part, &part_len);

        var last_part: [KeyPair.max_size]u8 = undefined;
        var last_part_len: pkcs.CK_ULONG = last_part.len;
        try p11_decryption.decryptFinal(&testing_state, id, &last_part, &last_part_len);
        try std.testing.expectEqualSlices(u8, &message, last_part[0..last_part_len]);
        try test_helpers.expectOperation(&testing_state, id, .none);
    }
}

test "decryptFinal card failure" {
    const Card = FailureCard(HealthyCard);

    for (test_helpers.key_files) |key_file| {
        var key_pair = try test_helpers.loadKeyPair(key_file);
        defer key_pair.deinit();

        var testing_state = test_helpers.newTestingState(Card);
        defer test_helpers.deinitTestingState(&testing_state);

        testing_state.initialized = true;
        const card = Card.init(.{ .key_pair = &key_pair }, .{ .fail_index = 0, .err = error.GeneralError });
        const id = try test_helpers.addNewSessionWithCard(&testing_state, card, &key_pair);
        try test_helpers.login();

        var mechanism = pkcs.CK_MECHANISM{ .mechanism = pkcs.CKM_RSA_PKCS };
        const message: [4]u8 = .{ 0x31, 0x32, 0x33, 0x34 };
        var encrypted_buffer: [KeyPair.max_size]u8 = undefined;
        const encrypted_data = try encryptData(&testing_state, id, &mechanism, &message, &encrypted_buffer);

        try p11_decryption.decryptInit(&testing_state, id, &mechanism, test_helpers.private_key_handle);

        var part: [KeyPair.max_size]u8 = undefined;
        var part_len: pkcs.CK_ULONG = part.len;
        try p11_decryption.decryptUpdate(&testing_state, id, encrypted_data.ptr, encrypted_data.len, &part, &part_len);

        var last_part: [KeyPair.max_size]u8 = undefined;
        var last_part_len: pkcs.CK_ULONG = last_part.len;
        const result = p11_decryption.decryptFinal(&testing_state, id, &last_part, &last_part_len);
        try std.testing.expectError(error.GeneralError, result);
        try test_helpers.expectOperation(&testing_state, id, .none);
    }
}
