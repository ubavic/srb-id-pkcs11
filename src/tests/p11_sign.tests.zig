const std = @import("std");

const FailureCard = @import("FailureCard.zig").FailureCard;
const HealthyCard = @import("HealthyCard.zig");
const KeyPair = @import("KeyPair.zig");
const p11_sign = @import("../p11_sign.zig");
const p11_verify = @import("../p11_verify.zig");
const pkcs = @import("../pkcs.zig");
const test_helpers = @import("test_helpers.zig");

test "signInit cryptoki initialization" {
    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    const result = p11_sign.signInit(&testing_state, 0, null, 0);
    try std.testing.expectError(error.CryptokiNotInitialized, result);
}

test "signInit invalid session handle" {
    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    testing_state.initialized = true;

    const result = p11_sign.signInit(&testing_state, 42, null, 0);
    try std.testing.expectError(error.SessionHandleInvalid, result);
}

test "signInit user not logged in" {
    for (test_helpers.key_files) |key_file| {
        var key_pair = try test_helpers.loadKeyPair(key_file);
        defer key_pair.deinit();

        var testing_state = test_helpers.newTestingState(HealthyCard);
        defer test_helpers.deinitTestingState(&testing_state);

        testing_state.initialized = true;
        const id = try test_helpers.addNewSessionWithCard(&testing_state, HealthyCard{ .key_pair = &key_pair }, &key_pair);

        var mechanism = pkcs.CK_MECHANISM{ .mechanism = pkcs.CKM_SHA256_RSA_PKCS };
        const result = p11_sign.signInit(&testing_state, id, &mechanism, test_helpers.private_key_handle);
        try std.testing.expectError(error.UserNotLoggedIn, result);
        try test_helpers.expectOperation(&testing_state, id, .none);
    }
}

test "signInit bad mechanism" {
    for (test_helpers.key_files) |key_file| {
        var key_pair = try test_helpers.loadKeyPair(key_file);
        defer key_pair.deinit();

        var testing_state = test_helpers.newTestingState(HealthyCard);
        defer test_helpers.deinitTestingState(&testing_state);

        testing_state.initialized = true;
        const id = try test_helpers.addNewSessionWithCard(&testing_state, HealthyCard{ .key_pair = &key_pair }, &key_pair);
        try test_helpers.login();

        const result1 = p11_sign.signInit(&testing_state, id, null, test_helpers.private_key_handle);
        try std.testing.expectError(error.ArgumentsBad, result1);
        try test_helpers.expectOperation(&testing_state, id, .none);

        var digest_mechanism = pkcs.CK_MECHANISM{ .mechanism = pkcs.CKM_SHA256 };
        const result2 = p11_sign.signInit(&testing_state, id, &digest_mechanism, test_helpers.private_key_handle);
        try std.testing.expectError(error.MechanismInvalid, result2);
        try test_helpers.expectOperation(&testing_state, id, .none);
    }
}

test "signInit invalid key handle" {
    for (test_helpers.key_files) |key_file| {
        var key_pair = try test_helpers.loadKeyPair(key_file);
        defer key_pair.deinit();

        var testing_state = test_helpers.newTestingState(HealthyCard);
        defer test_helpers.deinitTestingState(&testing_state);

        testing_state.initialized = true;
        const id = try test_helpers.addNewSessionWithCard(&testing_state, HealthyCard{ .key_pair = &key_pair }, &key_pair);
        try test_helpers.login();

        var mechanism = pkcs.CK_MECHANISM{ .mechanism = pkcs.CKM_SHA256_RSA_PKCS };

        const result1 = p11_sign.signInit(&testing_state, id, &mechanism, 42);
        try std.testing.expectError(error.KeyHandleInvalid, result1);

        const result2 = p11_sign.signInit(&testing_state, id, &mechanism, test_helpers.public_key_handle);
        try std.testing.expectError(error.KeyHandleInvalid, result2);

        try test_helpers.expectOperation(&testing_state, id, .none);
    }
}

test "signInit key function not permitted" {
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
        private_key.private_key.sign = pkcs.CK_FALSE;

        var mechanism = pkcs.CK_MECHANISM{ .mechanism = pkcs.CKM_SHA256_RSA_PKCS };
        const result = p11_sign.signInit(&testing_state, id, &mechanism, test_helpers.private_key_handle);
        try std.testing.expectError(error.KeyFunctionNotPermitted, result);
        try test_helpers.expectOperation(&testing_state, id, .none);
    }
}

test "signInit operation active" {
    for (test_helpers.key_files) |key_file| {
        var key_pair = try test_helpers.loadKeyPair(key_file);
        defer key_pair.deinit();

        var testing_state = test_helpers.newTestingState(HealthyCard);
        defer test_helpers.deinitTestingState(&testing_state);

        testing_state.initialized = true;
        const id = try test_helpers.addNewSessionWithCard(&testing_state, HealthyCard{ .key_pair = &key_pair }, &key_pair);
        try test_helpers.login();

        var mechanism = pkcs.CK_MECHANISM{ .mechanism = pkcs.CKM_SHA256_RSA_PKCS };
        try p11_sign.signInit(&testing_state, id, &mechanism, test_helpers.private_key_handle);

        const result = p11_sign.signInit(&testing_state, id, &mechanism, test_helpers.private_key_handle);
        try std.testing.expectError(error.OperationActive, result);
        try test_helpers.expectOperation(&testing_state, id, .sign);
    }
}

test "sign cryptoki initialization" {
    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    const result = p11_sign.sign(&testing_state, 0, null, 0, null, null);
    try std.testing.expectError(error.CryptokiNotInitialized, result);
}

test "sign operation not initialized" {
    for (test_helpers.key_files) |key_file| {
        var key_pair = try test_helpers.loadKeyPair(key_file);
        defer key_pair.deinit();

        var testing_state = test_helpers.newTestingState(HealthyCard);
        defer test_helpers.deinitTestingState(&testing_state);

        testing_state.initialized = true;
        const id = try test_helpers.addNewSessionWithCard(&testing_state, HealthyCard{ .key_pair = &key_pair }, &key_pair);
        try test_helpers.login();

        const result = p11_sign.sign(&testing_state, id, null, 0, null, null);
        try std.testing.expectError(error.OperationNotInitialized, result);
    }
}

test "sign signature size query keeps operation" {
    for (test_helpers.key_files) |key_file| {
        var key_pair = try test_helpers.loadKeyPair(key_file);
        defer key_pair.deinit();

        var testing_state = test_helpers.newTestingState(HealthyCard);
        defer test_helpers.deinitTestingState(&testing_state);

        testing_state.initialized = true;
        const id = try test_helpers.addNewSessionWithCard(&testing_state, HealthyCard{ .key_pair = &key_pair }, &key_pair);
        try test_helpers.login();

        var mechanism = pkcs.CK_MECHANISM{ .mechanism = pkcs.CKM_SHA256_RSA_PKCS };
        try p11_sign.signInit(&testing_state, id, &mechanism, test_helpers.private_key_handle);

        var data: [2]u8 = .{ 0x01, 0x02 };
        var signature: [KeyPair.max_size]u8 = undefined;
        var signature_len: pkcs.CK_ULONG = 0;

        try p11_sign.sign(&testing_state, id, &data, data.len, null, &signature_len);
        try std.testing.expectEqual(key_pair.size(), signature_len);
        try test_helpers.expectOperation(&testing_state, id, .sign);

        signature_len = key_pair.size() - 1;
        const result = p11_sign.sign(&testing_state, id, &data, data.len, &signature, &signature_len);
        try std.testing.expectError(error.BufferTooSmall, result);
        try test_helpers.expectOperation(&testing_state, id, .sign);
        try std.testing.expectEqual(0, test_helpers.getSession(&testing_state, id).card.sign_requests);
    }
}

test "sign buffer too small returns required length" {
    for (test_helpers.key_files) |key_file| {
        var key_pair = try test_helpers.loadKeyPair(key_file);
        defer key_pair.deinit();

        var testing_state = test_helpers.newTestingState(HealthyCard);
        defer test_helpers.deinitTestingState(&testing_state);

        testing_state.initialized = true;
        const id = try test_helpers.addNewSessionWithCard(&testing_state, HealthyCard{ .key_pair = &key_pair }, &key_pair);
        try test_helpers.login();

        var mechanism = pkcs.CK_MECHANISM{ .mechanism = pkcs.CKM_SHA256_RSA_PKCS };
        try p11_sign.signInit(&testing_state, id, &mechanism, test_helpers.private_key_handle);

        var data: [4]u8 = .{ 0x31, 0x32, 0x33, 0x34 };
        var signature: [KeyPair.max_size]u8 = undefined;
        var signature_len: pkcs.CK_ULONG = key_pair.size() - 1;

        const result = p11_sign.sign(&testing_state, id, &data, data.len, &signature, &signature_len);
        try std.testing.expectError(error.BufferTooSmall, result);
        try std.testing.expectEqual(key_pair.size(), signature_len);
        try test_helpers.expectOperation(&testing_state, id, .sign);

        try p11_sign.sign(&testing_state, id, &data, data.len, &signature, &signature_len);
        try std.testing.expectEqual(key_pair.size(), signature_len);
        try test_helpers.expectOperation(&testing_state, id, .none);

        try p11_verify.verifyInit(&testing_state, id, &mechanism, test_helpers.public_key_handle);
        try p11_verify.verify(&testing_state, id, &data, data.len, &signature, signature_len);
    }
}

test "sign bad arguments" {
    for (test_helpers.key_files) |key_file| {
        var key_pair = try test_helpers.loadKeyPair(key_file);
        defer key_pair.deinit();

        var testing_state = test_helpers.newTestingState(HealthyCard);
        defer test_helpers.deinitTestingState(&testing_state);

        testing_state.initialized = true;
        const id = try test_helpers.addNewSessionWithCard(&testing_state, HealthyCard{ .key_pair = &key_pair }, &key_pair);
        try test_helpers.login();

        var mechanism = pkcs.CK_MECHANISM{ .mechanism = pkcs.CKM_SHA256_RSA_PKCS };
        var data: [2]u8 = .{ 0x01, 0x02 };
        var signature: [KeyPair.max_size]u8 = undefined;
        var signature_len: pkcs.CK_ULONG = signature.len;

        try p11_sign.signInit(&testing_state, id, &mechanism, test_helpers.private_key_handle);
        const result1 = p11_sign.sign(&testing_state, id, &data, data.len, &signature, null);
        try std.testing.expectError(error.ArgumentsBad, result1);
        try test_helpers.expectOperation(&testing_state, id, .none);

        try p11_sign.signInit(&testing_state, id, &mechanism, test_helpers.private_key_handle);
        const result2 = p11_sign.sign(&testing_state, id, null, data.len, &signature, &signature_len);
        try std.testing.expectError(error.ArgumentsBad, result2);
        try test_helpers.expectOperation(&testing_state, id, .none);

        try std.testing.expectEqual(0, test_helpers.getSession(&testing_state, id).card.sign_requests);
    }
}

test "sign fails on multipart operation" {
    for (test_helpers.key_files) |key_file| {
        var key_pair = try test_helpers.loadKeyPair(key_file);
        defer key_pair.deinit();

        var testing_state = test_helpers.newTestingState(HealthyCard);
        defer test_helpers.deinitTestingState(&testing_state);

        testing_state.initialized = true;
        const id = try test_helpers.addNewSessionWithCard(&testing_state, HealthyCard{ .key_pair = &key_pair }, &key_pair);
        try test_helpers.login();

        var mechanism = pkcs.CK_MECHANISM{ .mechanism = pkcs.CKM_SHA256_RSA_PKCS };
        try p11_sign.signInit(&testing_state, id, &mechanism, test_helpers.private_key_handle);

        var data: [2]u8 = .{ 0x01, 0x02 };
        try p11_sign.signUpdate(&testing_state, id, &data, data.len);

        var signature: [KeyPair.max_size]u8 = undefined;
        var signature_len: pkcs.CK_ULONG = signature.len;
        const result = p11_sign.sign(&testing_state, id, &data, data.len, &signature, &signature_len);
        try std.testing.expectError(error.FunctionCanceled, result);
        try test_helpers.expectOperation(&testing_state, id, .none);
    }
}

test "sign" {
    for (test_helpers.key_files) |key_file| {
        var key_pair = try test_helpers.loadKeyPair(key_file);
        defer key_pair.deinit();

        var testing_state = test_helpers.newTestingState(HealthyCard);
        defer test_helpers.deinitTestingState(&testing_state);

        testing_state.initialized = true;
        const id = try test_helpers.addNewSessionWithCard(&testing_state, HealthyCard{ .key_pair = &key_pair }, &key_pair);
        try test_helpers.login();

        var mechanism = pkcs.CK_MECHANISM{ .mechanism = pkcs.CKM_SHA256_RSA_PKCS };
        try p11_sign.signInit(&testing_state, id, &mechanism, test_helpers.private_key_handle);

        var data: [4]u8 = .{ 0x31, 0x32, 0x33, 0x34 };
        var signature: [KeyPair.max_size]u8 = undefined;
        var signature_len: pkcs.CK_ULONG = signature.len;

        try p11_sign.sign(&testing_state, id, &data, data.len, &signature, &signature_len);
        try std.testing.expectEqual(key_pair.size(), signature_len);
        try std.testing.expectEqual(1, test_helpers.getSession(&testing_state, id).card.sign_requests);
        try test_helpers.expectOperation(&testing_state, id, .none);

        try p11_verify.verifyInit(&testing_state, id, &mechanism, test_helpers.public_key_handle);
        try p11_verify.verify(&testing_state, id, &data, data.len, &signature, signature_len);
    }
}

test "sign card failure" {
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

        var mechanism = pkcs.CK_MECHANISM{ .mechanism = pkcs.CKM_SHA256_RSA_PKCS };
        try p11_sign.signInit(&testing_state, id, &mechanism, test_helpers.private_key_handle);

        var data: [2]u8 = .{ 0x01, 0x02 };
        var signature: [KeyPair.max_size]u8 = undefined;
        var signature_len: pkcs.CK_ULONG = signature.len;

        const result = p11_sign.sign(&testing_state, id, &data, data.len, &signature, &signature_len);
        try std.testing.expectError(error.DeviceRemoved, result);
        try std.testing.expect(test_helpers.getSession(&testing_state, id).card.has_induced_failure);
        try test_helpers.expectOperation(&testing_state, id, .none);
    }
}

test "signUpdate cryptoki initialization" {
    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    const result = p11_sign.signUpdate(&testing_state, 0, null, 0);
    try std.testing.expectError(error.CryptokiNotInitialized, result);
}

test "signUpdate operation not initialized" {
    for (test_helpers.key_files) |key_file| {
        var key_pair = try test_helpers.loadKeyPair(key_file);
        defer key_pair.deinit();

        var testing_state = test_helpers.newTestingState(HealthyCard);
        defer test_helpers.deinitTestingState(&testing_state);

        testing_state.initialized = true;
        const id = try test_helpers.addNewSessionWithCard(&testing_state, HealthyCard{ .key_pair = &key_pair }, &key_pair);
        try test_helpers.login();

        const result = p11_sign.signUpdate(&testing_state, id, null, 0);
        try std.testing.expectError(error.OperationNotInitialized, result);
    }
}

test "signUpdate invalid part" {
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

        const result = p11_sign.signUpdate(&testing_state, id, null, 0);
        try std.testing.expectError(error.ArgumentsBad, result);
        try test_helpers.expectOperation(&testing_state, id, .none);
    }
}

test "signFinal cryptoki initialization" {
    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    const result = p11_sign.signFinal(&testing_state, 0, null, null);
    try std.testing.expectError(error.CryptokiNotInitialized, result);
}

test "signFinal bad arguments" {
    for (test_helpers.key_files) |key_file| {
        var key_pair = try test_helpers.loadKeyPair(key_file);
        defer key_pair.deinit();

        var testing_state = test_helpers.newTestingState(HealthyCard);
        defer test_helpers.deinitTestingState(&testing_state);

        testing_state.initialized = true;
        const id = try test_helpers.addNewSessionWithCard(&testing_state, HealthyCard{ .key_pair = &key_pair }, &key_pair);
        try test_helpers.login();

        var mechanism = pkcs.CK_MECHANISM{ .mechanism = pkcs.CKM_SHA256_RSA_PKCS };
        try p11_sign.signInit(&testing_state, id, &mechanism, test_helpers.private_key_handle);

        var signature: [KeyPair.max_size]u8 = undefined;
        const result = p11_sign.signFinal(&testing_state, id, &signature, null);
        try std.testing.expectError(error.ArgumentsBad, result);
        try test_helpers.expectOperation(&testing_state, id, .none);
    }
}

test "signFinal signature size query keeps operation" {
    for (test_helpers.key_files) |key_file| {
        var key_pair = try test_helpers.loadKeyPair(key_file);
        defer key_pair.deinit();

        var testing_state = test_helpers.newTestingState(HealthyCard);
        defer test_helpers.deinitTestingState(&testing_state);

        testing_state.initialized = true;
        const id = try test_helpers.addNewSessionWithCard(&testing_state, HealthyCard{ .key_pair = &key_pair }, &key_pair);
        try test_helpers.login();

        var mechanism = pkcs.CK_MECHANISM{ .mechanism = pkcs.CKM_SHA256_RSA_PKCS };
        try p11_sign.signInit(&testing_state, id, &mechanism, test_helpers.private_key_handle);

        var signature: [KeyPair.max_size]u8 = undefined;
        var signature_len: pkcs.CK_ULONG = 0;

        try p11_sign.signFinal(&testing_state, id, null, &signature_len);
        try std.testing.expectEqual(key_pair.size(), signature_len);
        try test_helpers.expectOperation(&testing_state, id, .sign);

        signature_len = key_pair.size() - 1;
        const result = p11_sign.signFinal(&testing_state, id, &signature, &signature_len);
        try std.testing.expectError(error.BufferTooSmall, result);
        try test_helpers.expectOperation(&testing_state, id, .sign);
    }
}

test "signFinal buffer too small returns required length" {
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

        var signature: [KeyPair.max_size]u8 = undefined;
        var signature_len: pkcs.CK_ULONG = key_pair.size() - 1;

        const result = p11_sign.signFinal(&testing_state, id, &signature, &signature_len);
        try std.testing.expectError(error.BufferTooSmall, result);
        try std.testing.expectEqual(key_pair.size(), signature_len);
        try test_helpers.expectOperation(&testing_state, id, .sign);

        try p11_sign.signFinal(&testing_state, id, &signature, &signature_len);
        try std.testing.expectEqual(key_pair.size(), signature_len);
        try test_helpers.expectOperation(&testing_state, id, .none);

        try p11_verify.verifyInit(&testing_state, id, &mechanism, test_helpers.public_key_handle);
        try p11_verify.verify(&testing_state, id, &data, data.len, &signature, signature_len);
    }
}

test "signFinal" {
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
        try p11_sign.signUpdate(&testing_state, id, data[0..2], 2);
        try p11_sign.signUpdate(&testing_state, id, data[2..4], 2);

        var signature: [KeyPair.max_size]u8 = undefined;
        var signature_len: pkcs.CK_ULONG = signature.len;
        try p11_sign.signFinal(&testing_state, id, &signature, &signature_len);
        try std.testing.expectEqual(key_pair.size(), signature_len);
        try test_helpers.expectOperation(&testing_state, id, .none);

        try p11_verify.verifyInit(&testing_state, id, &mechanism, test_helpers.public_key_handle);
        try p11_verify.verify(&testing_state, id, &data, data.len, &signature, signature_len);
    }
}

test "signFinal card failure" {
    const Card = FailureCard(HealthyCard);

    for (test_helpers.key_files) |key_file| {
        var key_pair = try test_helpers.loadKeyPair(key_file);
        defer key_pair.deinit();

        var testing_state = test_helpers.newTestingState(Card);
        defer test_helpers.deinitTestingState(&testing_state);

        testing_state.initialized = true;
        const card = Card.init(.{ .key_pair = &key_pair }, .{ .fail_index = 0 });
        const id = try test_helpers.addNewSessionWithCard(&testing_state, card, &key_pair);
        try test_helpers.login();

        var mechanism = pkcs.CK_MECHANISM{ .mechanism = pkcs.CKM_RSA_PKCS };
        try p11_sign.signInit(&testing_state, id, &mechanism, test_helpers.private_key_handle);

        var data: [2]u8 = .{ 0x01, 0x02 };
        try p11_sign.signUpdate(&testing_state, id, &data, data.len);

        var signature: [KeyPair.max_size]u8 = undefined;
        var signature_len: pkcs.CK_ULONG = signature.len;
        const result = p11_sign.signFinal(&testing_state, id, &signature, &signature_len);
        try std.testing.expectError(error.DeviceError, result);
        try test_helpers.expectOperation(&testing_state, id, .none);
    }
}

test "signRecover not supported" {
    var testing_state = test_helpers.newTestingState(HealthyCard);
    defer test_helpers.deinitTestingState(&testing_state);

    try std.testing.expectError(error.FunctionNotSupported, p11_sign.signRecoverInit(&testing_state, 0, null, 0));
    try std.testing.expectError(error.FunctionNotSupported, p11_sign.signRecover(&testing_state, 0, null, 0, null, null));
}
