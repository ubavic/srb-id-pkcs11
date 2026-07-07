const std = @import("std");

const pkcs = @import("pkcs.zig");
const PkcsError = @import("pkcs_error.zig").PkcsError;
const Ripemd160 = @import("ripemd160.zig");

pub const HasherType = enum { md5, sha1, sha256, sha384, sha512, ripemd160 };

pub const Hasher = union(enum) {
    md5: std.crypto.hash.Md5,
    sha1: std.crypto.hash.Sha1,
    sha256: std.crypto.hash.sha2.Sha256,
    sha384: std.crypto.hash.sha2.Sha384,
    sha512: std.crypto.hash.sha2.Sha512,
    ripemd160: Ripemd160,

    pub fn update(self: *Hasher, data: []const u8) void {
        switch (self.*) {
            .md5 => |*o| o.update(data),
            .sha1 => |*o| o.update(data),
            .sha256 => |*o| o.update(data),
            .sha384 => |*o| o.update(data),
            .sha512 => |*o| o.update(data),
            .ripemd160 => |*o| o.update(data),
        }
    }

    pub fn finalize(
        self: *Hasher,
        allocator: std.mem.Allocator,
    ) std.mem.Allocator.Error![]u8 {
        const digest_length = self.digestLength();

        const hash: []u8 = try allocator.alloc(u8, digest_length);

        switch (self.*) {
            .md5 => |*o| o.final(@ptrCast(hash.ptr)),
            .sha1 => |*o| o.final(@ptrCast(hash.ptr)),
            .sha256 => |*o| o.final(@ptrCast(hash.ptr)),
            .sha384 => |*o| o.final(@ptrCast(hash.ptr)),
            .sha512 => |*o| o.final(@ptrCast(hash.ptr)),
            .ripemd160 => |*o| o.final(@ptrCast(hash.ptr)),
        }

        return hash;
    }

    pub fn digestLength(self: Hasher) usize {
        return switch (self) {
            .md5 => std.crypto.hash.Md5.digest_length,
            .sha1 => std.crypto.hash.Sha1.digest_length,
            .sha256 => std.crypto.hash.sha2.Sha256.digest_length,
            .sha384 => std.crypto.hash.sha2.Sha384.digest_length,
            .sha512 => std.crypto.hash.sha2.Sha512.digest_length,
            .ripemd160 => Ripemd160.digest_length,
        };
    }
};

pub fn createAndInit(hasherType: HasherType) Hasher {
    return switch (hasherType) {
        HasherType.md5 => Hasher{ .md5 = std.crypto.hash.Md5.init(.{}) },
        HasherType.sha1 => Hasher{ .sha1 = std.crypto.hash.Sha1.init(.{}) },
        HasherType.sha256 => Hasher{ .sha256 = std.crypto.hash.sha2.Sha256.init(.{}) },
        HasherType.sha384 => Hasher{ .sha384 = std.crypto.hash.sha2.Sha384.init(.{}) },
        HasherType.sha512 => Hasher{ .sha512 = std.crypto.hash.sha2.Sha512.init(.{}) },
        HasherType.ripemd160 => Hasher{ .ripemd160 = Ripemd160.init() },
    };
}

pub fn fromDigestMechanism(mechanism: pkcs.CK_MECHANISM_TYPE) PkcsError!HasherType {
    return switch (mechanism) {
        pkcs.CKM_MD5 => HasherType.md5,
        pkcs.CKM_SHA_1 => HasherType.sha1,
        pkcs.CKM_SHA256 => HasherType.sha256,
        pkcs.CKM_SHA384 => HasherType.sha384,
        pkcs.CKM_SHA512 => HasherType.sha512,
        pkcs.CKM_RIPEMD160 => HasherType.ripemd160,
        else => return PkcsError.MechanismInvalid,
    };
}

pub fn fromSignMechanism(mechanism: pkcs.CK_MECHANISM_TYPE) PkcsError!?HasherType {
    return switch (mechanism) {
        pkcs.CKM_MD5_RSA_PKCS => HasherType.md5,
        pkcs.CKM_SHA1_RSA_PKCS => HasherType.sha1,
        pkcs.CKM_SHA256_RSA_PKCS => HasherType.sha256,
        pkcs.CKM_SHA384_RSA_PKCS => HasherType.sha384,
        pkcs.CKM_SHA512_RSA_PKCS => HasherType.sha512,
        pkcs.CKM_RIPEMD160_RSA_PKCS => HasherType.ripemd160,
        pkcs.CKM_RSA_PKCS, pkcs.CKM_RSA_X_509 => null,
        else => return PkcsError.MechanismInvalid,
    };
}

test "digest mechanisms" {
    try std.testing.expectEqual(fromDigestMechanism(pkcs.CKM_MD5), HasherType.md5);
    try std.testing.expectEqual(fromDigestMechanism(pkcs.CKM_SHA_1), HasherType.sha1);
    try std.testing.expectEqual(fromDigestMechanism(pkcs.CKM_SHA256), HasherType.sha256);
    try std.testing.expectEqual(fromDigestMechanism(pkcs.CKM_SHA384), HasherType.sha384);
    try std.testing.expectEqual(fromDigestMechanism(pkcs.CKM_SHA512), HasherType.sha512);
    try std.testing.expectEqual(fromDigestMechanism(pkcs.CKM_RIPEMD160), HasherType.ripemd160);

    try std.testing.expectError(PkcsError.MechanismInvalid, fromDigestMechanism(pkcs.CKM_MD2));
    try std.testing.expectError(PkcsError.MechanismInvalid, fromDigestMechanism(pkcs.CKM_MD5_RSA_PKCS));
    try std.testing.expectError(PkcsError.MechanismInvalid, fromDigestMechanism(pkcs.CKM_SHA256_RSA_PKCS));
    try std.testing.expectError(PkcsError.MechanismInvalid, fromDigestMechanism(pkcs.CKM_RIPEMD160_RSA_PKCS));
    try std.testing.expectError(PkcsError.MechanismInvalid, fromDigestMechanism(pkcs.CKM_RSA_PKCS));
    try std.testing.expectError(PkcsError.MechanismInvalid, fromDigestMechanism(pkcs.CKM_RSA_X_509));
}

test "sign mechanisms" {
    try std.testing.expectEqual(fromSignMechanism(pkcs.CKM_MD5_RSA_PKCS), HasherType.md5);
    try std.testing.expectEqual(fromSignMechanism(pkcs.CKM_SHA1_RSA_PKCS), HasherType.sha1);
    try std.testing.expectEqual(fromSignMechanism(pkcs.CKM_SHA256_RSA_PKCS), HasherType.sha256);
    try std.testing.expectEqual(fromSignMechanism(pkcs.CKM_SHA384_RSA_PKCS), HasherType.sha384);
    try std.testing.expectEqual(fromSignMechanism(pkcs.CKM_SHA512_RSA_PKCS), HasherType.sha512);
    try std.testing.expectEqual(fromSignMechanism(pkcs.CKM_RIPEMD160_RSA_PKCS), HasherType.ripemd160);
    try std.testing.expectEqual(fromSignMechanism(pkcs.CKM_RSA_PKCS), null);
    try std.testing.expectEqual(fromSignMechanism(pkcs.CKM_RSA_X_509), null);

    try std.testing.expectError(PkcsError.MechanismInvalid, fromSignMechanism(pkcs.CKM_MD2_RSA_PKCS));
    try std.testing.expectError(PkcsError.MechanismInvalid, fromSignMechanism(pkcs.CKM_MD5));
    try std.testing.expectError(PkcsError.MechanismInvalid, fromSignMechanism(pkcs.CKM_SHA256));
    try std.testing.expectError(PkcsError.MechanismInvalid, fromSignMechanism(pkcs.CKM_RIPEMD160));
}
