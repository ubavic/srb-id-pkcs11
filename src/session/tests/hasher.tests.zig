const std = @import("std");

const hasher = @import("../hasher.zig");
const pkcs = @import("../../pkcs.zig");

const HasherType = hasher.HasherType;

test "digest mechanisms" {
    try std.testing.expectEqual(hasher.fromDigestMechanism(pkcs.CKM_MD5), HasherType.md5);
    try std.testing.expectEqual(hasher.fromDigestMechanism(pkcs.CKM_SHA_1), HasherType.sha1);
    try std.testing.expectEqual(hasher.fromDigestMechanism(pkcs.CKM_SHA256), HasherType.sha256);
    try std.testing.expectEqual(hasher.fromDigestMechanism(pkcs.CKM_SHA384), HasherType.sha384);
    try std.testing.expectEqual(hasher.fromDigestMechanism(pkcs.CKM_SHA512), HasherType.sha512);
    try std.testing.expectEqual(hasher.fromDigestMechanism(pkcs.CKM_RIPEMD160), HasherType.ripemd160);

    try std.testing.expectError(error.MechanismInvalid, hasher.fromDigestMechanism(pkcs.CKM_MD2));
    try std.testing.expectError(error.MechanismInvalid, hasher.fromDigestMechanism(pkcs.CKM_MD5_RSA_PKCS));
    try std.testing.expectError(error.MechanismInvalid, hasher.fromDigestMechanism(pkcs.CKM_SHA256_RSA_PKCS));
    try std.testing.expectError(error.MechanismInvalid, hasher.fromDigestMechanism(pkcs.CKM_RIPEMD160_RSA_PKCS));
    try std.testing.expectError(error.MechanismInvalid, hasher.fromDigestMechanism(pkcs.CKM_RSA_PKCS));
    try std.testing.expectError(error.MechanismInvalid, hasher.fromDigestMechanism(pkcs.CKM_RSA_X_509));
}

test "sign mechanisms" {
    try std.testing.expectEqual(hasher.fromSignMechanism(pkcs.CKM_MD5_RSA_PKCS), HasherType.md5);
    try std.testing.expectEqual(hasher.fromSignMechanism(pkcs.CKM_SHA1_RSA_PKCS), HasherType.sha1);
    try std.testing.expectEqual(hasher.fromSignMechanism(pkcs.CKM_SHA256_RSA_PKCS), HasherType.sha256);
    try std.testing.expectEqual(hasher.fromSignMechanism(pkcs.CKM_SHA384_RSA_PKCS), HasherType.sha384);
    try std.testing.expectEqual(hasher.fromSignMechanism(pkcs.CKM_SHA512_RSA_PKCS), HasherType.sha512);
    try std.testing.expectEqual(hasher.fromSignMechanism(pkcs.CKM_RIPEMD160_RSA_PKCS), HasherType.ripemd160);
    try std.testing.expectEqual(hasher.fromSignMechanism(pkcs.CKM_RSA_PKCS), null);
    try std.testing.expectEqual(hasher.fromSignMechanism(pkcs.CKM_RSA_X_509), null);

    try std.testing.expectError(error.MechanismInvalid, hasher.fromSignMechanism(pkcs.CKM_MD2_RSA_PKCS));
    try std.testing.expectError(error.MechanismInvalid, hasher.fromSignMechanism(pkcs.CKM_MD5));
    try std.testing.expectError(error.MechanismInvalid, hasher.fromSignMechanism(pkcs.CKM_SHA256));
    try std.testing.expectError(error.MechanismInvalid, hasher.fromSignMechanism(pkcs.CKM_RIPEMD160));
}
