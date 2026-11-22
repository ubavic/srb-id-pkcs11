const std = @import("std");

const HealthyCard = @import("HealthyCard.helper.zig");
const KeyPair = @import("KeyPair.helper.zig");
const p11_sign = @import("../p11_sign.zig");
const p11_verify = @import("../p11_verify.zig");
const pkcs = @import("../pkcs.zig");
const test_helpers = @import("test.helper.zig");

fn signData(
    state: anytype,
    session_handle: pkcs.CK_SESSION_HANDLE,
    mechanism: *pkcs.CK_MECHANISM,
    data: []u8,
    signature: []u8,
) ![]u8 {
    var signature_len: pkcs.CK_ULONG = signature.len;

    try p11_sign.signInit(state, session_handle, mechanism, test_helpers.private_key_handle);
    try p11_sign.sign(state, session_handle, data.ptr, data.len, signature.ptr, &signature_len);

    return signature[0..signature_len];
}

test "verifyInit cryptoki initialization" {
    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    const result = p11_verify.verifyInit(&testing_state, 0, null, 0);
    try std.testing.expectError(error.CryptokiNotInitialized, result);
}

test "verifyInit invalid session handle" {
    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    testing_state.initialized = true;

    const result = p11_verify.verifyInit(&testing_state, 42, null, 0);
    try std.testing.expectError(error.SessionHandleInvalid, result);
}

test "verifyInit does not require login" {
    var key_pair = try test_helpers.loadKeyPair(test_helpers.key_files[0]);
    defer key_pair.deinit();

    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    testing_state.initialized = true;
    const id = try test_helpers.addNewSessionWithCard(&testing_state, HealthyCard{ .key_pair = &key_pair }, &key_pair);

    var mechanism = pkcs.CK_MECHANISM{ .mechanism = pkcs.CKM_SHA256_RSA_PKCS };
    try p11_verify.verifyInit(&testing_state, id, &mechanism, test_helpers.public_key_handle);
    try test_helpers.expectOperation(&testing_state, id, .verify);
}

test "verifyInit bad mechanism" {
    var key_pair = try test_helpers.loadKeyPair(test_helpers.key_files[1]);
    defer key_pair.deinit();

    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    testing_state.initialized = true;
    const id = try test_helpers.addNewSessionWithCard(&testing_state, HealthyCard{ .key_pair = &key_pair }, &key_pair);

    const result1 = p11_verify.verifyInit(&testing_state, id, null, test_helpers.public_key_handle);
    try std.testing.expectError(error.ArgumentsBad, result1);
    try test_helpers.expectOperation(&testing_state, id, .none);

    var digest_mechanism = pkcs.CK_MECHANISM{ .mechanism = pkcs.CKM_SHA256 };
    const result2 = p11_verify.verifyInit(&testing_state, id, &digest_mechanism, test_helpers.public_key_handle);
    try std.testing.expectError(error.MechanismInvalid, result2);
    try test_helpers.expectOperation(&testing_state, id, .none);
}

test "verifyInit invalid key handle" {
    var key_pair = try test_helpers.loadKeyPair(test_helpers.key_files[1]);
    defer key_pair.deinit();

    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    testing_state.initialized = true;
    const id = try test_helpers.addNewSessionWithCard(&testing_state, HealthyCard{ .key_pair = &key_pair }, &key_pair);
    try test_helpers.login();

    var mechanism = pkcs.CK_MECHANISM{ .mechanism = pkcs.CKM_SHA256_RSA_PKCS };

    const result1 = p11_verify.verifyInit(&testing_state, id, &mechanism, 42);
    try std.testing.expectError(error.KeyHandleInvalid, result1);

    const result2 = p11_verify.verifyInit(&testing_state, id, &mechanism, test_helpers.private_key_handle);
    try std.testing.expectError(error.KeyHandleInvalid, result2);

    try test_helpers.expectOperation(&testing_state, id, .none);
}

test "verifyInit key function not permitted" {
    for (test_helpers.key_files) |key_file| {
        var key_pair = try test_helpers.loadKeyPair(key_file);
        defer key_pair.deinit();

        var testing_state = test_helpers.newTestingState(HealthyCard);
        defer test_helpers.deinitTestingState(&testing_state);

        testing_state.initialized = true;
        const id = try test_helpers.addNewSessionWithCard(&testing_state, HealthyCard{ .key_pair = &key_pair }, &key_pair);

        const session = test_helpers.getSession(&testing_state, id);
        const public_key = try session.getObject(testing_state.io, test_helpers.public_key_handle);
        public_key.public_key.verify = pkcs.CK_FALSE;

        var mechanism = pkcs.CK_MECHANISM{ .mechanism = pkcs.CKM_SHA256_RSA_PKCS };
        const result = p11_verify.verifyInit(&testing_state, id, &mechanism, test_helpers.public_key_handle);
        try std.testing.expectError(error.KeyFunctionNotPermitted, result);
        try test_helpers.expectOperation(&testing_state, id, .none);
    }
}

test "verifyInit operation active" {
    var key_pair = try test_helpers.loadKeyPair(test_helpers.key_files[1]);
    defer key_pair.deinit();

    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    testing_state.initialized = true;
    const id = try test_helpers.addNewSessionWithCard(&testing_state, HealthyCard{ .key_pair = &key_pair }, &key_pair);

    var mechanism = pkcs.CK_MECHANISM{ .mechanism = pkcs.CKM_SHA256_RSA_PKCS };
    try p11_verify.verifyInit(&testing_state, id, &mechanism, test_helpers.public_key_handle);

    const result = p11_verify.verifyInit(&testing_state, id, &mechanism, test_helpers.public_key_handle);
    try std.testing.expectError(error.OperationActive, result);
    try test_helpers.expectOperation(&testing_state, id, .verify);
}

test "verify cryptoki initialization" {
    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    const result = p11_verify.verify(&testing_state, 0, null, 0, null, 0);
    try std.testing.expectError(error.CryptokiNotInitialized, result);
}

test "verify operation not initialized" {
    var key_pair = try test_helpers.loadKeyPair(test_helpers.key_files[1]);
    defer key_pair.deinit();

    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    testing_state.initialized = true;
    const id = try test_helpers.addNewSessionWithCard(&testing_state, HealthyCard{ .key_pair = &key_pair }, &key_pair);

    const result = p11_verify.verify(&testing_state, id, null, 0, null, 0);
    try std.testing.expectError(error.OperationNotInitialized, result);
}

test "verify bad arguments" {
    var key_pair = try test_helpers.loadKeyPair(test_helpers.key_files[1]);
    defer key_pair.deinit();

    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    testing_state.initialized = true;
    const id = try test_helpers.addNewSessionWithCard(&testing_state, HealthyCard{ .key_pair = &key_pair }, &key_pair);

    var mechanism = pkcs.CK_MECHANISM{ .mechanism = pkcs.CKM_SHA256_RSA_PKCS };
    const data: [2]u8 = .{ 0x01, 0x02 };
    const signature_buffer: [KeyPair.max_size]u8 = @splat(0x01);
    const signature = signature_buffer[0..key_pair.size()];

    try p11_verify.verifyInit(&testing_state, id, &mechanism, test_helpers.public_key_handle);
    const result1 = p11_verify.verify(&testing_state, id, null, data.len, signature.ptr, signature.len);
    try std.testing.expectError(error.ArgumentsBad, result1);
    try test_helpers.expectOperation(&testing_state, id, .none);

    try p11_verify.verifyInit(&testing_state, id, &mechanism, test_helpers.public_key_handle);
    const result2 = p11_verify.verify(&testing_state, id, &data, data.len, null, signature.len);
    try std.testing.expectError(error.ArgumentsBad, result2);
    try test_helpers.expectOperation(&testing_state, id, .none);
}

test "verify signature length range" {
    for (test_helpers.key_files) |key_file| {
        var key_pair = try test_helpers.loadKeyPair(key_file);
        defer key_pair.deinit();

        var testing_state = test_helpers.newTestingState(HealthyCard);
        defer test_helpers.deinitTestingState(&testing_state);

        testing_state.initialized = true;
        const id = try test_helpers.addNewSessionWithCard(&testing_state, HealthyCard{ .key_pair = &key_pair }, &key_pair);

        var mechanism = pkcs.CK_MECHANISM{ .mechanism = pkcs.CKM_SHA256_RSA_PKCS };
        try p11_verify.verifyInit(&testing_state, id, &mechanism, test_helpers.public_key_handle);

        const data: [2]u8 = .{ 0x01, 0x02 };
        const signature_buffer: [KeyPair.max_size]u8 = @splat(0x01);
        const signature = signature_buffer[0 .. key_pair.size() - 1];

        const result = p11_verify.verify(&testing_state, id, &data, data.len, signature.ptr, signature.len);
        try std.testing.expectError(error.SignatureLenRange, result);
        try test_helpers.expectOperation(&testing_state, id, .none);
    }
}

test "verify fails on multipart operation" {
    for (test_helpers.key_files) |key_file| {
        var key_pair = try test_helpers.loadKeyPair(key_file);
        defer key_pair.deinit();

        var testing_state = test_helpers.newTestingState(HealthyCard);
        defer test_helpers.deinitTestingState(&testing_state);

        testing_state.initialized = true;
        const id = try test_helpers.addNewSessionWithCard(&testing_state, HealthyCard{ .key_pair = &key_pair }, &key_pair);

        var mechanism = pkcs.CK_MECHANISM{ .mechanism = pkcs.CKM_SHA256_RSA_PKCS };
        try p11_verify.verifyInit(&testing_state, id, &mechanism, test_helpers.public_key_handle);

        const data: [2]u8 = .{ 0x01, 0x02 };
        const signature_buffer: [KeyPair.max_size]u8 = @splat(0x01);
        const signature = signature_buffer[0..key_pair.size()];
        try p11_verify.verifyUpdate(&testing_state, id, &data, data.len);

        const result = p11_verify.verify(&testing_state, id, &data, data.len, signature.ptr, signature.len);
        try std.testing.expectError(error.FunctionCanceled, result);
        try test_helpers.expectOperation(&testing_state, id, .none);
    }
}

test "verify" {
    for (test_helpers.key_files) |key_file| {
        var key_pair = try test_helpers.loadKeyPair(key_file);
        defer key_pair.deinit();

        var testing_state = test_helpers.newTestingState(HealthyCard);
        defer test_helpers.deinitTestingState(&testing_state);

        testing_state.initialized = true;
        const id = try test_helpers.addNewSessionWithCard(&testing_state, HealthyCard{ .key_pair = &key_pair }, &key_pair);
        try test_helpers.login();

        var mechanism = pkcs.CK_MECHANISM{ .mechanism = pkcs.CKM_SHA1_RSA_PKCS };
        var data: [4]u8 = .{ 0x31, 0x32, 0x33, 0x34 };
        var signature_buffer: [KeyPair.max_size]u8 = undefined;
        const signature = try signData(&testing_state, id, &mechanism, &data, &signature_buffer);

        try p11_verify.verifyInit(&testing_state, id, &mechanism, test_helpers.public_key_handle);
        try p11_verify.verify(&testing_state, id, &data, data.len, signature.ptr, signature.len);
        try test_helpers.expectOperation(&testing_state, id, .none);
    }
}

test "verify invalid signature" {
    for (test_helpers.key_files) |key_file| {
        var key_pair = try test_helpers.loadKeyPair(key_file);
        defer key_pair.deinit();

        var testing_state = test_helpers.newTestingState(HealthyCard);
        defer test_helpers.deinitTestingState(&testing_state);

        testing_state.initialized = true;
        const id = try test_helpers.addNewSessionWithCard(&testing_state, HealthyCard{ .key_pair = &key_pair }, &key_pair);
        try test_helpers.login();

        var mechanism = pkcs.CK_MECHANISM{ .mechanism = pkcs.CKM_SHA1_RSA_PKCS };
        var data: [4]u8 = .{ 0x31, 0x32, 0x33, 0x34 };
        var signature_buffer: [KeyPair.max_size]u8 = undefined;
        const signature = try signData(&testing_state, id, &mechanism, &data, &signature_buffer);

        const other_data: [4]u8 = .{ 0x31, 0x32, 0x33, 0x35 };
        try p11_verify.verifyInit(&testing_state, id, &mechanism, test_helpers.public_key_handle);
        const result1 = p11_verify.verify(&testing_state, id, &other_data, other_data.len, signature.ptr, signature.len);
        try std.testing.expectError(error.SignatureInvalid, result1);
        try test_helpers.expectOperation(&testing_state, id, .none);

        signature[signature.len - 1] ^= 0xFF;
        try p11_verify.verifyInit(&testing_state, id, &mechanism, test_helpers.public_key_handle);
        const result2 = p11_verify.verify(&testing_state, id, &data, data.len, signature.ptr, signature.len);
        try std.testing.expectError(error.SignatureInvalid, result2);
        try test_helpers.expectOperation(&testing_state, id, .none);
    }
}

test "verifyUpdate cryptoki initialization" {
    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    const result = p11_verify.verifyUpdate(&testing_state, 0, null, 0);
    try std.testing.expectError(error.CryptokiNotInitialized, result);
}

test "verifyUpdate operation not initialized" {
    var key_pair = try test_helpers.loadKeyPair(test_helpers.key_files[1]);
    defer key_pair.deinit();

    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    testing_state.initialized = true;
    const id = try test_helpers.addNewSessionWithCard(&testing_state, HealthyCard{ .key_pair = &key_pair }, &key_pair);

    const result = p11_verify.verifyUpdate(&testing_state, id, null, 0);
    try std.testing.expectError(error.OperationNotInitialized, result);
}

test "verifyUpdate invalid part" {
    for (test_helpers.key_files) |key_file| {
        var key_pair = try test_helpers.loadKeyPair(key_file);
        defer key_pair.deinit();

        var testing_state = test_helpers.newTestingState(HealthyCard);
        defer test_helpers.deinitTestingState(&testing_state);

        testing_state.initialized = true;
        const id = try test_helpers.addNewSessionWithCard(&testing_state, HealthyCard{ .key_pair = &key_pair }, &key_pair);

        var mechanism = pkcs.CK_MECHANISM{ .mechanism = pkcs.CKM_RSA_PKCS };
        try p11_verify.verifyInit(&testing_state, id, &mechanism, test_helpers.public_key_handle);

        const result = p11_verify.verifyUpdate(&testing_state, id, null, 0);
        try std.testing.expectError(error.ArgumentsBad, result);
        try test_helpers.expectOperation(&testing_state, id, .none);
    }
}

test "verifyFinal cryptoki initialization" {
    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    const result = p11_verify.verifyFinal(&testing_state, 0, null, 0);
    try std.testing.expectError(error.CryptokiNotInitialized, result);
}

test "verifyFinal operation not initialized" {
    for (test_helpers.key_files) |key_file| {
        var key_pair = try test_helpers.loadKeyPair(key_file);
        defer key_pair.deinit();

        var testing_state = test_helpers.newTestingState(HealthyCard);
        defer test_helpers.deinitTestingState(&testing_state);

        testing_state.initialized = true;
        const id = try test_helpers.addNewSessionWithCard(&testing_state, HealthyCard{ .key_pair = &key_pair }, &key_pair);

        const result = p11_verify.verifyFinal(&testing_state, id, null, 0);
        try std.testing.expectError(error.OperationNotInitialized, result);
    }
}

test "verifyFinal bad arguments" {
    var key_pair = try test_helpers.loadKeyPair(test_helpers.key_files[1]);
    defer key_pair.deinit();

    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    testing_state.initialized = true;
    const id = try test_helpers.addNewSessionWithCard(&testing_state, HealthyCard{ .key_pair = &key_pair }, &key_pair);

    var mechanism = pkcs.CK_MECHANISM{ .mechanism = pkcs.CKM_SHA256_RSA_PKCS };
    const signature_buffer: [KeyPair.max_size]u8 = @splat(0x01);
    const signature = signature_buffer[0 .. key_pair.size() - 1];

    try p11_verify.verifyInit(&testing_state, id, &mechanism, test_helpers.public_key_handle);
    const result1 = p11_verify.verifyFinal(&testing_state, id, null, key_pair.size());
    try std.testing.expectError(error.ArgumentsBad, result1);
    try test_helpers.expectOperation(&testing_state, id, .none);

    try p11_verify.verifyInit(&testing_state, id, &mechanism, test_helpers.public_key_handle);
    const result2 = p11_verify.verifyFinal(&testing_state, id, signature.ptr, signature.len);
    try std.testing.expectError(error.SignatureLenRange, result2);
    try test_helpers.expectOperation(&testing_state, id, .none);
}

test "verifyFinal" {
    for (test_helpers.key_files) |key_file| {
        var key_pair = try test_helpers.loadKeyPair(key_file);
        defer key_pair.deinit();

        var testing_state = test_helpers.newTestingState(HealthyCard);
        defer test_helpers.deinitTestingState(&testing_state);

        testing_state.initialized = true;
        const id = try test_helpers.addNewSessionWithCard(&testing_state, HealthyCard{ .key_pair = &key_pair }, &key_pair);
        try test_helpers.login();

        var mechanism = pkcs.CK_MECHANISM{ .mechanism = pkcs.CKM_RSA_PKCS };
        var data: [4]u8 = .{ 0x31, 0x32, 0x33, 0x34 };
        var signature_buffer: [KeyPair.max_size]u8 = undefined;
        const signature = try signData(&testing_state, id, &mechanism, &data, &signature_buffer);

        try p11_verify.verifyInit(&testing_state, id, &mechanism, test_helpers.public_key_handle);
        try p11_verify.verifyUpdate(&testing_state, id, data[0..2], 2);
        try p11_verify.verifyUpdate(&testing_state, id, data[2..4], 2);
        try p11_verify.verifyFinal(&testing_state, id, signature.ptr, signature.len);
        try test_helpers.expectOperation(&testing_state, id, .none);
    }
}

test "verifyRecover not supported" {
    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    try std.testing.expectError(error.FunctionNotSupported, p11_verify.verifyRecoverInit(&testing_state, 0, null, 0));
    try std.testing.expectError(error.FunctionNotSupported, p11_verify.verifyRecover(&testing_state, 0, null, 0, null, null));
}
