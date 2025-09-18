const std = @import("std");

const PkcsError = @import("pkcs_error.zig").PkcsError;

const pkcs = @cImport({
    @cInclude("pkcs.h");
});

pub const HasherType = enum { md5, sha1, sha256, sha384, sha512 };

pub const Hasher = struct {
    hasherType: ?HasherType,
    md5: ?*std.crypto.hash.Md5 = null,
    sha1: ?*std.crypto.hash.Sha1 = null,
    sha256: ?*std.crypto.hash.sha2.Sha256 = null,
    sha384: ?*std.crypto.hash.sha2.Sha384 = null,
    sha512: ?*std.crypto.hash.sha2.Sha512 = null,

    pub fn update(self: *Hasher, data: []const u8) void {
        switch (self.hasherType.?) {
            HasherType.md5 => self.md5.?.*.update(data),
            HasherType.sha1 => self.sha1.?.*.update(data),
            HasherType.sha256 => self.sha256.?.*.update(data),
            HasherType.sha384 => self.sha384.?.*.update(data),
            HasherType.sha512 => self.sha512.?.*.update(data),
        }
    }

    pub fn finalize(
        self: *Hasher,
        allocator: std.mem.Allocator,
    ) std.mem.Allocator.Error![]u8 {
        const digest_length = self.digestLength();

        const hash: []u8 = try allocator.alloc(u8, digest_length);

        switch (self.hasherType.?) {
            HasherType.md5 => self.md5.?.final(@ptrCast(hash.ptr)),
            HasherType.sha1 => self.sha1.?.final(@ptrCast(hash.ptr)),
            HasherType.sha256 => self.sha256.?.final(@ptrCast(hash.ptr)),
            HasherType.sha384 => self.sha384.?.final(@ptrCast(hash.ptr)),
            HasherType.sha512 => self.sha512.?.final(@ptrCast(hash.ptr)),
        }

        self.destroy(allocator);

        return hash;
    }

    pub fn destroy(
        self: *Hasher,
        allocator: std.mem.Allocator,
    ) void {
        if (self.md5 != null) {
            allocator.destroy(self.md5.?);
            self.md5 = null;
        }

        if (self.sha1 != null) {
            allocator.destroy(self.sha1.?);
            self.sha1 = null;
        }

        if (self.sha256 != null) {
            allocator.destroy(self.sha256.?);
            self.sha256 = null;
        }

        if (self.sha384 != null) {
            allocator.destroy(self.sha384.?);
            self.sha384 = null;
        }

        if (self.sha512 != null) {
            allocator.destroy(self.sha512.?);
            self.sha512 = null;
        }
    }

    pub fn digestLength(self: Hasher) usize {
        if (self.hasherType == null)
            return 0;

        return switch (self.hasherType.?) {
            HasherType.md5 => std.crypto.hash.Md5.digest_length,
            HasherType.sha1 => std.crypto.hash.Sha1.digest_length,
            HasherType.sha256 => std.crypto.hash.sha2.Sha256.digest_length,
            HasherType.sha384 => std.crypto.hash.sha2.Sha384.digest_length,
            HasherType.sha512 => std.crypto.hash.sha2.Sha512.digest_length,
        };
    }
};

pub fn createAndInit(
    hasherType: HasherType,
    allocator: std.mem.Allocator,
) std.mem.Allocator.Error!Hasher {
    var hasher = Hasher{
        .hasherType = hasherType,
    };

    switch (hasherType) {
        HasherType.md5 => {
            const options = std.crypto.hash.Md5.Options{};
            hasher.md5 = try allocator.create(std.crypto.hash.Md5);
            hasher.md5.?.* = std.crypto.hash.Md5.init(options);
        },
        HasherType.sha1 => {
            const options = std.crypto.hash.Sha1.Options{};
            hasher.sha1 = try allocator.create(std.crypto.hash.Sha1);
            hasher.sha1.?.* = std.crypto.hash.Sha1.init(options);
        },
        HasherType.sha256 => {
            const options = std.crypto.hash.sha2.Sha256.Options{};
            hasher.sha256 = try allocator.create(std.crypto.hash.sha2.Sha256);
            hasher.sha256.?.* = std.crypto.hash.sha2.Sha256.init(options);
        },
        HasherType.sha384 => {
            const options = std.crypto.hash.sha2.Sha384.Options{};
            hasher.sha384 = try allocator.create(std.crypto.hash.sha2.Sha384);
            hasher.sha384.?.* = std.crypto.hash.sha2.Sha384.init(options);
        },
        HasherType.sha512 => {
            const options = std.crypto.hash.sha2.Sha512.Options{};
            hasher.sha512 = try allocator.create(std.crypto.hash.sha2.Sha512);
            hasher.sha512.?.* = std.crypto.hash.sha2.Sha512.init(options);
        },
    }

    return hasher;
}

pub fn fromMechanism(mechanism: pkcs.CK_MECHANISM_TYPE) PkcsError!?HasherType {
    return switch (mechanism) {
        pkcs.CKM_MD5_RSA_PKCS => HasherType.md5,
        pkcs.CKM_SHA1_RSA_PKCS => HasherType.sha1,
        pkcs.CKM_SHA256_RSA_PKCS => HasherType.sha256,
        pkcs.CKM_SHA384_RSA_PKCS => HasherType.sha384,
        pkcs.CKM_SHA512_RSA_PKCS => HasherType.sha512,
        pkcs.CKM_RSA_PKCS, pkcs.CKM_RSA_X_509 => null,
        else => return PkcsError.MechanismInvalid,
    };
}
