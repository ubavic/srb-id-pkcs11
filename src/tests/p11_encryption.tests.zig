const std = @import("std");

const HealthyCard = @import("HealthyCard.zig");
const KeyPair = @import("KeyPair.zig");
const p11_decryption = @import("../p11_decryption.zig");
const p11_encryption = @import("../p11_encryption.zig");
const pkcs = @import("../pkcs.zig");
const test_helpers = @import("test_helpers.zig");

fn expectDecryptsTo(
    state: anytype,
    session_handle: pkcs.CK_SESSION_HANDLE,
    mechanism: *pkcs.CK_MECHANISM,
    encrypted_data: []const u8,
    expected: []const u8,
) !void {
    var data: [KeyPair.max_size]u8 = undefined;
    var data_len: pkcs.CK_ULONG = data.len;

    try p11_decryption.decryptInit(state, session_handle, mechanism, test_helpers.private_key_handle);
    try p11_decryption.decrypt(state, session_handle, encrypted_data.ptr, encrypted_data.len, &data, &data_len);
    try std.testing.expectEqualSlices(u8, expected, data[0..data_len]);
}

test "encryptInit cryptoki initialization" {
    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    const result = p11_encryption.encryptInit(&testing_state, 0, null, 0);
    try std.testing.expectError(error.CryptokiNotInitialized, result);
}

test "encryptInit invalid session handle" {
    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    testing_state.initialized = true;

    const result = p11_encryption.encryptInit(&testing_state, 42, null, 0);
    try std.testing.expectError(error.SessionHandleInvalid, result);
}

test "encryptInit bad mechanism" {
    var key_pair = try test_helpers.loadKeyPair(test_helpers.key_files[1]);
    defer key_pair.deinit();

    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    testing_state.initialized = true;
    const id = try test_helpers.addNewSessionWithCard(&testing_state, HealthyCard{ .key_pair = &key_pair }, &key_pair);

    const result1 = p11_encryption.encryptInit(&testing_state, id, null, test_helpers.public_key_handle);
    try std.testing.expectError(error.ArgumentsBad, result1);

    var sign_mechanism = pkcs.CK_MECHANISM{ .mechanism = pkcs.CKM_SHA256_RSA_PKCS };
    const result2 = p11_encryption.encryptInit(&testing_state, id, &sign_mechanism, test_helpers.public_key_handle);
    try std.testing.expectError(error.MechanismInvalid, result2);

    var parameter: u8 = 0;
    var mechanism_with_parameter = pkcs.CK_MECHANISM{ .mechanism = pkcs.CKM_RSA_PKCS, .pParameter = &parameter, .ulParameterLen = 1 };
    const result3 = p11_encryption.encryptInit(&testing_state, id, &mechanism_with_parameter, test_helpers.public_key_handle);
    try std.testing.expectError(error.MechanismParamInvalid, result3);

    try test_helpers.expectOperation(&testing_state, id, .none);
}

test "encryptInit invalid key handle" {
    var key_pair = try test_helpers.loadKeyPair(test_helpers.key_files[1]);
    defer key_pair.deinit();

    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    testing_state.initialized = true;
    const id = try test_helpers.addNewSessionWithCard(&testing_state, HealthyCard{ .key_pair = &key_pair }, &key_pair);
    try test_helpers.login();

    var mechanism = pkcs.CK_MECHANISM{ .mechanism = pkcs.CKM_RSA_PKCS };

    const result1 = p11_encryption.encryptInit(&testing_state, id, &mechanism, 42);
    try std.testing.expectError(error.KeyHandleInvalid, result1);

    const result2 = p11_encryption.encryptInit(&testing_state, id, &mechanism, test_helpers.private_key_handle);
    try std.testing.expectError(error.KeyHandleInvalid, result2);

    try test_helpers.expectOperation(&testing_state, id, .none);
}

test "encryptInit key function not permitted" {
    for (test_helpers.key_files) |key_file| {
        var key_pair = try test_helpers.loadKeyPair(key_file);
        defer key_pair.deinit();

        var testing_state = test_helpers.newTestingState(HealthyCard);
        defer test_helpers.deinitTestingState(&testing_state);

        testing_state.initialized = true;
        const id = try test_helpers.addNewSessionWithCard(&testing_state, HealthyCard{ .key_pair = &key_pair }, &key_pair);

        const session = test_helpers.getSession(&testing_state, id);
        const public_key = try session.getObject(testing_state.io, test_helpers.public_key_handle);
        public_key.public_key.encrypt = pkcs.CK_FALSE;

        var mechanism = pkcs.CK_MECHANISM{ .mechanism = pkcs.CKM_RSA_PKCS };
        const result = p11_encryption.encryptInit(&testing_state, id, &mechanism, test_helpers.public_key_handle);
        try std.testing.expectError(error.KeyFunctionNotPermitted, result);
        try test_helpers.expectOperation(&testing_state, id, .none);
    }
}

test "encryptInit operation active" {
    var key_pair = try test_helpers.loadKeyPair(test_helpers.key_files[1]);
    defer key_pair.deinit();

    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    testing_state.initialized = true;
    const id = try test_helpers.addNewSessionWithCard(&testing_state, HealthyCard{ .key_pair = &key_pair }, &key_pair);

    var mechanism = pkcs.CK_MECHANISM{ .mechanism = pkcs.CKM_RSA_PKCS };
    try p11_encryption.encryptInit(&testing_state, id, &mechanism, test_helpers.public_key_handle);

    const result = p11_encryption.encryptInit(&testing_state, id, &mechanism, test_helpers.public_key_handle);
    try std.testing.expectError(error.OperationActive, result);
    try test_helpers.expectOperation(&testing_state, id, .encrypt);
}

test "encrypt cryptoki initialization" {
    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    const result = p11_encryption.encrypt(&testing_state, 0, null, 0, null, null);
    try std.testing.expectError(error.CryptokiNotInitialized, result);
}

test "encrypt operation not initialized" {
    for (test_helpers.key_files) |key_file| {
        var key_pair = try test_helpers.loadKeyPair(key_file);
        defer key_pair.deinit();

        var testing_state = test_helpers.newTestingState(HealthyCard);
        defer test_helpers.deinitTestingState(&testing_state);

        testing_state.initialized = true;
        const id = try test_helpers.addNewSessionWithCard(&testing_state, HealthyCard{ .key_pair = &key_pair }, &key_pair);

        const result = p11_encryption.encrypt(&testing_state, id, null, 0, null, null);
        try std.testing.expectError(error.OperationNotInitialized, result);
    }
}

test "encrypt encrypted data size query keeps operation" {
    for (test_helpers.key_files) |key_file| {
        var key_pair = try test_helpers.loadKeyPair(key_file);
        defer key_pair.deinit();

        var testing_state = test_helpers.newTestingState(HealthyCard);
        defer test_helpers.deinitTestingState(&testing_state);

        testing_state.initialized = true;
        const id = try test_helpers.addNewSessionWithCard(&testing_state, HealthyCard{ .key_pair = &key_pair }, &key_pair);

        var mechanism = pkcs.CK_MECHANISM{ .mechanism = pkcs.CKM_RSA_PKCS };
        try p11_encryption.encryptInit(&testing_state, id, &mechanism, test_helpers.public_key_handle);

        const data: [2]u8 = .{ 0x01, 0x02 };
        var encrypted_data: [KeyPair.max_size]u8 = undefined;
        var encrypted_data_len: pkcs.CK_ULONG = 0;

        try p11_encryption.encrypt(&testing_state, id, &data, data.len, null, &encrypted_data_len);
        try std.testing.expectEqual(key_pair.size(), encrypted_data_len);
        try test_helpers.expectOperation(&testing_state, id, .encrypt);

        encrypted_data_len = key_pair.size() - 1;
        const result = p11_encryption.encrypt(&testing_state, id, &data, data.len, &encrypted_data, &encrypted_data_len);
        try std.testing.expectError(error.BufferTooSmall, result);
        try test_helpers.expectOperation(&testing_state, id, .encrypt);
    }
}

test "encrypt buffer too small returns required length" {
    for (test_helpers.key_files) |key_file| {
        var key_pair = try test_helpers.loadKeyPair(key_file);
        defer key_pair.deinit();

        var testing_state = test_helpers.newTestingState(HealthyCard);
        defer test_helpers.deinitTestingState(&testing_state);

        testing_state.initialized = true;
        const id = try test_helpers.addNewSessionWithCard(&testing_state, HealthyCard{ .key_pair = &key_pair }, &key_pair);

        var mechanism = pkcs.CK_MECHANISM{ .mechanism = pkcs.CKM_RSA_PKCS };
        try p11_encryption.encryptInit(&testing_state, id, &mechanism, test_helpers.public_key_handle);

        const data: [4]u8 = .{ 0x31, 0x32, 0x33, 0x34 };
        var encrypted_data: [KeyPair.max_size]u8 = undefined;
        var encrypted_data_len: pkcs.CK_ULONG = key_pair.size() - 1;

        const result = p11_encryption.encrypt(&testing_state, id, &data, data.len, &encrypted_data, &encrypted_data_len);
        try std.testing.expectError(error.BufferTooSmall, result);
        try std.testing.expectEqual(key_pair.size(), encrypted_data_len);
        try test_helpers.expectOperation(&testing_state, id, .encrypt);

        try p11_encryption.encrypt(&testing_state, id, &data, data.len, &encrypted_data, &encrypted_data_len);
        try std.testing.expectEqual(key_pair.size(), encrypted_data_len);
        try test_helpers.expectOperation(&testing_state, id, .none);

        try test_helpers.login();
        try expectDecryptsTo(&testing_state, id, &mechanism, encrypted_data[0..encrypted_data_len], &data);
    }
}

test "encrypt bad arguments" {
    for (test_helpers.key_files) |key_file| {
        var key_pair = try test_helpers.loadKeyPair(key_file);
        defer key_pair.deinit();

        var testing_state = test_helpers.newTestingState(HealthyCard);
        defer test_helpers.deinitTestingState(&testing_state);

        testing_state.initialized = true;
        const id = try test_helpers.addNewSessionWithCard(&testing_state, HealthyCard{ .key_pair = &key_pair }, &key_pair);

        var mechanism = pkcs.CK_MECHANISM{ .mechanism = pkcs.CKM_RSA_PKCS };
        const data: [2]u8 = .{ 0x01, 0x02 };
        var encrypted_data: [KeyPair.max_size]u8 = undefined;
        var encrypted_data_len: pkcs.CK_ULONG = encrypted_data.len;

        try p11_encryption.encryptInit(&testing_state, id, &mechanism, test_helpers.public_key_handle);
        const result1 = p11_encryption.encrypt(&testing_state, id, &data, data.len, &encrypted_data, null);
        try std.testing.expectError(error.ArgumentsBad, result1);
        try test_helpers.expectOperation(&testing_state, id, .none);

        try p11_encryption.encryptInit(&testing_state, id, &mechanism, test_helpers.public_key_handle);
        const result2 = p11_encryption.encrypt(&testing_state, id, null, data.len, &encrypted_data, &encrypted_data_len);
        try std.testing.expectError(error.ArgumentsBad, result2);
        try test_helpers.expectOperation(&testing_state, id, .none);
    }
}

test "encrypt data length range" {
    for (test_helpers.key_files) |key_file| {
        var key_pair = try test_helpers.loadKeyPair(key_file);
        defer key_pair.deinit();

        var testing_state = test_helpers.newTestingState(HealthyCard);
        defer test_helpers.deinitTestingState(&testing_state);

        testing_state.initialized = true;
        const id = try test_helpers.addNewSessionWithCard(&testing_state, HealthyCard{ .key_pair = &key_pair }, &key_pair);

        var encrypted_data: [KeyPair.max_size]u8 = undefined;
        var encrypted_data_len: pkcs.CK_ULONG = encrypted_data.len;

        var padded_mechanism = pkcs.CK_MECHANISM{ .mechanism = pkcs.CKM_RSA_PKCS };
        const data_buffer: [KeyPair.max_size]u8 = @splat(0x01);
        const too_long_data = data_buffer[0 .. key_pair.size() - 10];
        try p11_encryption.encryptInit(&testing_state, id, &padded_mechanism, test_helpers.public_key_handle);
        const result1 = p11_encryption.encrypt(&testing_state, id, too_long_data.ptr, too_long_data.len, &encrypted_data, &encrypted_data_len);
        try std.testing.expectError(error.DataLenRange, result1);
        try test_helpers.expectOperation(&testing_state, id, .none);

        var raw_mechanism = pkcs.CK_MECHANISM{ .mechanism = pkcs.CKM_RSA_X_509 };
        const short_data: [2]u8 = .{ 0x01, 0x02 };
        try p11_encryption.encryptInit(&testing_state, id, &raw_mechanism, test_helpers.public_key_handle);
        const result2 = p11_encryption.encrypt(&testing_state, id, &short_data, short_data.len, &encrypted_data, &encrypted_data_len);
        try std.testing.expectError(error.DataLenRange, result2);
        try test_helpers.expectOperation(&testing_state, id, .none);
    }
}

test "encrypt fails on multipart operation" {
    for (test_helpers.key_files) |key_file| {
        var key_pair = try test_helpers.loadKeyPair(key_file);
        defer key_pair.deinit();

        var testing_state = test_helpers.newTestingState(HealthyCard);
        defer test_helpers.deinitTestingState(&testing_state);

        testing_state.initialized = true;
        const id = try test_helpers.addNewSessionWithCard(&testing_state, HealthyCard{ .key_pair = &key_pair }, &key_pair);

        var mechanism = pkcs.CK_MECHANISM{ .mechanism = pkcs.CKM_RSA_PKCS };
        try p11_encryption.encryptInit(&testing_state, id, &mechanism, test_helpers.public_key_handle);

        const data: [2]u8 = .{ 0x01, 0x02 };
        var encrypted_data: [KeyPair.max_size]u8 = undefined;
        var encrypted_data_len: pkcs.CK_ULONG = encrypted_data.len;

        try p11_encryption.encryptUpdate(&testing_state, id, &data, data.len, &encrypted_data, &encrypted_data_len);

        encrypted_data_len = encrypted_data.len;
        const result = p11_encryption.encrypt(&testing_state, id, &data, data.len, &encrypted_data, &encrypted_data_len);
        try std.testing.expectError(error.FunctionCanceled, result);
        try test_helpers.expectOperation(&testing_state, id, .none);
    }
}

test "encrypt" {
    for (test_helpers.key_files) |key_file| {
        var key_pair = try test_helpers.loadKeyPair(key_file);
        defer key_pair.deinit();

        var testing_state = test_helpers.newTestingState(HealthyCard);
        defer test_helpers.deinitTestingState(&testing_state);

        testing_state.initialized = true;
        const id = try test_helpers.addNewSessionWithCard(&testing_state, HealthyCard{ .key_pair = &key_pair }, &key_pair);

        var mechanism = pkcs.CK_MECHANISM{ .mechanism = pkcs.CKM_RSA_PKCS };
        try p11_encryption.encryptInit(&testing_state, id, &mechanism, test_helpers.public_key_handle);

        const data: [4]u8 = .{ 0x31, 0x32, 0x33, 0x34 };
        var encrypted_data: [KeyPair.max_size]u8 = undefined;
        var encrypted_data_len: pkcs.CK_ULONG = encrypted_data.len;

        try p11_encryption.encrypt(&testing_state, id, &data, data.len, &encrypted_data, &encrypted_data_len);
        try std.testing.expectEqual(key_pair.size(), encrypted_data_len);
        try test_helpers.expectOperation(&testing_state, id, .none);

        try test_helpers.login();
        try expectDecryptsTo(&testing_state, id, &mechanism, encrypted_data[0..encrypted_data_len], &data);
    }
}

test "encryptUpdate cryptoki initialization" {
    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    const result = p11_encryption.encryptUpdate(&testing_state, 0, null, 0, null, null);
    try std.testing.expectError(error.CryptokiNotInitialized, result);
}

test "encryptUpdate operation not initialized" {
    for (test_helpers.key_files) |key_file| {
        var key_pair = try test_helpers.loadKeyPair(key_file);
        defer key_pair.deinit();

        var testing_state = test_helpers.newTestingState(HealthyCard);
        defer test_helpers.deinitTestingState(&testing_state);

        testing_state.initialized = true;
        const id = try test_helpers.addNewSessionWithCard(&testing_state, HealthyCard{ .key_pair = &key_pair }, &key_pair);

        const result = p11_encryption.encryptUpdate(&testing_state, id, null, 0, null, null);
        try std.testing.expectError(error.OperationNotInitialized, result);
    }
}

test "encryptUpdate bad arguments" {
    for (test_helpers.key_files) |key_file| {
        var key_pair = try test_helpers.loadKeyPair(key_file);
        defer key_pair.deinit();

        var testing_state = test_helpers.newTestingState(HealthyCard);
        defer test_helpers.deinitTestingState(&testing_state);

        testing_state.initialized = true;
        const id = try test_helpers.addNewSessionWithCard(&testing_state, HealthyCard{ .key_pair = &key_pair }, &key_pair);

        var mechanism = pkcs.CK_MECHANISM{ .mechanism = pkcs.CKM_RSA_PKCS };
        const data: [2]u8 = .{ 0x01, 0x02 };
        var encrypted_part: [KeyPair.max_size]u8 = undefined;
        var encrypted_part_len: pkcs.CK_ULONG = encrypted_part.len;

        try p11_encryption.encryptInit(&testing_state, id, &mechanism, test_helpers.public_key_handle);
        const result1 = p11_encryption.encryptUpdate(&testing_state, id, &data, data.len, &encrypted_part, null);
        try std.testing.expectError(error.ArgumentsBad, result1);
        try test_helpers.expectOperation(&testing_state, id, .none);

        try p11_encryption.encryptInit(&testing_state, id, &mechanism, test_helpers.public_key_handle);
        const result2 = p11_encryption.encryptUpdate(&testing_state, id, null, data.len, &encrypted_part, &encrypted_part_len);
        try std.testing.expectError(error.ArgumentsBad, result2);
        try test_helpers.expectOperation(&testing_state, id, .none);
    }
}

test "encryptUpdate produces no output" {
    for (test_helpers.key_files) |key_file| {
        var key_pair = try test_helpers.loadKeyPair(key_file);
        defer key_pair.deinit();

        var testing_state = test_helpers.newTestingState(HealthyCard);
        defer test_helpers.deinitTestingState(&testing_state);

        testing_state.initialized = true;
        const id = try test_helpers.addNewSessionWithCard(&testing_state, HealthyCard{ .key_pair = &key_pair }, &key_pair);

        var mechanism = pkcs.CK_MECHANISM{ .mechanism = pkcs.CKM_RSA_PKCS };
        try p11_encryption.encryptInit(&testing_state, id, &mechanism, test_helpers.public_key_handle);

        const data: [2]u8 = .{ 0x01, 0x02 };
        var encrypted_part: [KeyPair.max_size]u8 = undefined;
        var encrypted_part_len: pkcs.CK_ULONG = encrypted_part.len;

        try p11_encryption.encryptUpdate(&testing_state, id, &data, data.len, null, &encrypted_part_len);
        try std.testing.expectEqual(0, encrypted_part_len);

        encrypted_part_len = encrypted_part.len;
        try p11_encryption.encryptUpdate(&testing_state, id, &data, data.len, &encrypted_part, &encrypted_part_len);
        try std.testing.expectEqual(0, encrypted_part_len);
        try test_helpers.expectOperation(&testing_state, id, .encrypt);
    }
}

test "encryptFinal cryptoki initialization" {
    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    const result = p11_encryption.encryptFinal(&testing_state, 0, null, null);
    try std.testing.expectError(error.CryptokiNotInitialized, result);
}

test "encryptFinal bad arguments" {
    for (test_helpers.key_files) |key_file| {
        var key_pair = try test_helpers.loadKeyPair(key_file);
        defer key_pair.deinit();

        var testing_state = test_helpers.newTestingState(HealthyCard);
        defer test_helpers.deinitTestingState(&testing_state);

        testing_state.initialized = true;
        const id = try test_helpers.addNewSessionWithCard(&testing_state, HealthyCard{ .key_pair = &key_pair }, &key_pair);

        var mechanism = pkcs.CK_MECHANISM{ .mechanism = pkcs.CKM_RSA_PKCS };
        try p11_encryption.encryptInit(&testing_state, id, &mechanism, test_helpers.public_key_handle);

        var encrypted_data: [KeyPair.max_size]u8 = undefined;
        const result = p11_encryption.encryptFinal(&testing_state, id, &encrypted_data, null);
        try std.testing.expectError(error.ArgumentsBad, result);
        try test_helpers.expectOperation(&testing_state, id, .none);
    }
}

test "encryptFinal encrypted data size query keeps operation" {
    for (test_helpers.key_files) |key_file| {
        var key_pair = try test_helpers.loadKeyPair(key_file);
        defer key_pair.deinit();

        var testing_state = test_helpers.newTestingState(HealthyCard);
        defer test_helpers.deinitTestingState(&testing_state);

        testing_state.initialized = true;
        const id = try test_helpers.addNewSessionWithCard(&testing_state, HealthyCard{ .key_pair = &key_pair }, &key_pair);

        var mechanism = pkcs.CK_MECHANISM{ .mechanism = pkcs.CKM_RSA_PKCS };
        try p11_encryption.encryptInit(&testing_state, id, &mechanism, test_helpers.public_key_handle);

        var encrypted_data: [KeyPair.max_size]u8 = undefined;
        var encrypted_data_len: pkcs.CK_ULONG = 0;

        try p11_encryption.encryptFinal(&testing_state, id, null, &encrypted_data_len);
        try std.testing.expectEqual(key_pair.size(), encrypted_data_len);
        try test_helpers.expectOperation(&testing_state, id, .encrypt);

        encrypted_data_len = key_pair.size() - 1;
        const result = p11_encryption.encryptFinal(&testing_state, id, &encrypted_data, &encrypted_data_len);
        try std.testing.expectError(error.BufferTooSmall, result);
        try test_helpers.expectOperation(&testing_state, id, .encrypt);
    }
}

test "encryptFinal buffer too small returns required length" {
    for (test_helpers.key_files) |key_file| {
        var key_pair = try test_helpers.loadKeyPair(key_file);
        defer key_pair.deinit();

        var testing_state = test_helpers.newTestingState(HealthyCard);
        defer test_helpers.deinitTestingState(&testing_state);

        testing_state.initialized = true;
        const id = try test_helpers.addNewSessionWithCard(&testing_state, HealthyCard{ .key_pair = &key_pair }, &key_pair);

        var mechanism = pkcs.CK_MECHANISM{ .mechanism = pkcs.CKM_RSA_PKCS };
        try p11_encryption.encryptInit(&testing_state, id, &mechanism, test_helpers.public_key_handle);

        const data: [4]u8 = .{ 0x31, 0x32, 0x33, 0x34 };
        var encrypted_part: [KeyPair.max_size]u8 = undefined;
        var encrypted_part_len: pkcs.CK_ULONG = encrypted_part.len;
        try p11_encryption.encryptUpdate(&testing_state, id, &data, data.len, &encrypted_part, &encrypted_part_len);

        var encrypted_data: [KeyPair.max_size]u8 = undefined;
        var encrypted_data_len: pkcs.CK_ULONG = key_pair.size() - 1;

        const result = p11_encryption.encryptFinal(&testing_state, id, &encrypted_data, &encrypted_data_len);
        try std.testing.expectError(error.BufferTooSmall, result);
        try std.testing.expectEqual(key_pair.size(), encrypted_data_len);
        try test_helpers.expectOperation(&testing_state, id, .encrypt);

        try p11_encryption.encryptFinal(&testing_state, id, &encrypted_data, &encrypted_data_len);
        try std.testing.expectEqual(key_pair.size(), encrypted_data_len);
        try test_helpers.expectOperation(&testing_state, id, .none);

        try test_helpers.login();
        try expectDecryptsTo(&testing_state, id, &mechanism, encrypted_data[0..encrypted_data_len], &data);
    }
}

test "encryptFinal" {
    for (test_helpers.key_files) |key_file| {
        var key_pair = try test_helpers.loadKeyPair(key_file);
        defer key_pair.deinit();

        var testing_state = test_helpers.newTestingState(HealthyCard);
        defer test_helpers.deinitTestingState(&testing_state);

        testing_state.initialized = true;
        const id = try test_helpers.addNewSessionWithCard(&testing_state, HealthyCard{ .key_pair = &key_pair }, &key_pair);

        var mechanism = pkcs.CK_MECHANISM{ .mechanism = pkcs.CKM_RSA_X_509 };
        try p11_encryption.encryptInit(&testing_state, id, &mechanism, test_helpers.public_key_handle);

        var data_buffer: [KeyPair.max_size]u8 = @splat(0x42);
        data_buffer[0] = 0x00;
        const data = data_buffer[0..key_pair.size()];
        var encrypted_part: [KeyPair.max_size]u8 = undefined;
        var encrypted_part_len: pkcs.CK_ULONG = encrypted_part.len;

        try p11_encryption.encryptUpdate(&testing_state, id, data.ptr, 64, &encrypted_part, &encrypted_part_len);
        encrypted_part_len = encrypted_part.len;
        try p11_encryption.encryptUpdate(&testing_state, id, data[64..].ptr, data.len - 64, &encrypted_part, &encrypted_part_len);

        var encrypted_data: [KeyPair.max_size]u8 = undefined;
        var encrypted_data_len: pkcs.CK_ULONG = encrypted_data.len;
        try p11_encryption.encryptFinal(&testing_state, id, &encrypted_data, &encrypted_data_len);
        try std.testing.expectEqual(key_pair.size(), encrypted_data_len);
        try test_helpers.expectOperation(&testing_state, id, .none);

        try test_helpers.login();
        try expectDecryptsTo(&testing_state, id, &mechanism, encrypted_data[0..encrypted_data_len], data);
    }
}
