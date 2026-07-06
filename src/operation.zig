const std = @import("std");

const hasher = @import("hasher.zig");
const pkcs = @import("pkcs.zig");

const pkcs_error = @import("pkcs_error.zig");
const PkcsError = pkcs_error.PkcsError;

// rfc8017 - Section 9.2
const md5_prefix: [18]u8 = [_]u8{ 0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10 };
const sha1_prefix: [15]u8 = [_]u8{ 0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14 };
const sha256_prefix: [19]u8 = [_]u8{ 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20 };
const sha384_prefix: [19]u8 = [_]u8{ 0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30 };
const sha512_prefix: [19]u8 = [_]u8{ 0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40 };
const ripemd160_prefix: [15]u8 = [_]u8{ 0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x24, 0x03, 0x02, 0x01, 0x05, 0x00, 0x04, 0x14 };

pub const SignType = enum {
    RawRsa,
    Pkcs1Pad,
    DigestAndSign,
};

pub fn signTypeFromMechanism(mechanism: pkcs.CK_MECHANISM_TYPE) PkcsError!SignType {
    return switch (mechanism) {
        pkcs.CKM_RSA_X_509 => .RawRsa,
        pkcs.CKM_RSA_PKCS => .Pkcs1Pad,
        pkcs.CKM_MD5_RSA_PKCS => .DigestAndSign,
        pkcs.CKM_SHA1_RSA_PKCS => .DigestAndSign,
        pkcs.CKM_SHA256_RSA_PKCS => .DigestAndSign,
        pkcs.CKM_SHA384_RSA_PKCS => .DigestAndSign,
        pkcs.CKM_SHA512_RSA_PKCS => .DigestAndSign,
        pkcs.CKM_RIPEMD160_RSA_PKCS => .DigestAndSign,
        else => return PkcsError.MechanismInvalid,
    };
}

pub const Type = enum {
    None,
    Digest,
    Sign,
    Verify,
    Encrypt,
    Decrypt,
    Search,
};

pub const None = struct {};

pub const Digest = struct {
    hasher: hasher.Hasher,
    multipart_operation: bool,
};

pub const Sign = struct {
    private_key: pkcs.CK_OBJECT_HANDLE,
    key_size: usize,
    sign_type: SignType,
    multipart_operation: bool,
    hasher: ?hasher.Hasher,
    msg_buffer: ?std.ArrayList(u8),

    pub fn init(mechanism: pkcs.CK_MECHANISM_TYPE, key_size: usize, private_key: c_ulong) PkcsError!Sign {
        const sign_type = try signTypeFromMechanism(mechanism);
        const hash_mechanism = try hasher.fromSignMechanism(mechanism);

        var hash: ?hasher.Hasher = null;
        var msg_buffer: ?std.ArrayList(u8) = null;
        if (hash_mechanism != null) {
            hash = hasher.createAndInit(hash_mechanism.?) catch
                return PkcsError.HostMemory;
        } else msg_buffer = std.ArrayList(u8).empty;

        return Sign{
            .private_key = private_key,
            .key_size = key_size,
            .sign_type = sign_type,
            .hasher = hash,
            .msg_buffer = msg_buffer,
            .multipart_operation = false,
        };
    }

    pub fn update(self: *Sign, allocator: std.mem.Allocator, data: []const u8) PkcsError!void {
        switch (self.sign_type) {
            .DigestAndSign => self.hasher.?.update(data),
            .RawRsa, .Pkcs1Pad => {
                self.msg_buffer.?.appendSlice(allocator, data) catch
                    return PkcsError.HostMemory;
            },
        }
    }

    pub fn createSignRequest(self: *Sign, allocator: std.mem.Allocator) PkcsError![]u8 {
        return switch (self.sign_type) {
            .RawRsa => createRawSignRequest(&self.msg_buffer, allocator, self.key_size),
            .Pkcs1Pad => createPkcs1PaddedSignRequest(&self.msg_buffer, allocator, self.key_size),
            .DigestAndSign => createHashedSignRequest(&self.hasher.?, allocator),
        };
    }

    pub fn keySizeBytes(self: *Sign) usize {
        return self.key_size;
    }

    pub fn deinit(self: *Sign, allocator: std.mem.Allocator) void {
        self.hasher = null;

        if (self.msg_buffer != null)
            self.msg_buffer.?.deinit(allocator);
    }
};

pub const Verify = struct {
    public_key: std.crypto.Certificate.rsa.PublicKey,
    sign_type: SignType,
    multipart_operation: bool,
    hasher: ?hasher.Hasher,
    msg_buffer: ?std.ArrayList(u8),

    pub fn init(mechanism: pkcs.CK_MECHANISM_TYPE, public_key: std.crypto.Certificate.rsa.PublicKey) PkcsError!Verify {
        const sign_type = try signTypeFromMechanism(mechanism);
        const hash_mechanism = try hasher.fromSignMechanism(mechanism);

        var hash: ?hasher.Hasher = null;
        var msg_buffer: ?std.ArrayList(u8) = null;
        if (hash_mechanism != null) {
            hash = hasher.createAndInit(hash_mechanism.?) catch
                return PkcsError.HostMemory;
        } else msg_buffer = std.ArrayList(u8).empty;

        return Verify{
            .public_key = public_key,
            .hasher = hash,
            .sign_type = sign_type,
            .multipart_operation = false,
            .msg_buffer = msg_buffer,
        };
    }

    pub fn update(self: *Verify, allocator: std.mem.Allocator, data: []const u8) PkcsError!void {
        switch (self.sign_type) {
            .DigestAndSign => self.hasher.?.update(data),
            .RawRsa, .Pkcs1Pad => {
                self.msg_buffer.?.appendSlice(allocator, data) catch
                    return PkcsError.HostMemory;
            },
        }
    }

    pub fn verify(self: *Verify, allocator: std.mem.Allocator, signature: []const u8) PkcsError!void {
        const sign_request = try self.createVerifyBlock(allocator);
        defer allocator.free(sign_request);

        const Modulus = std.crypto.ff.Modulus(4096);
        const Fe = Modulus.Fe;

        const sig_fe = Fe.fromBytes(self.public_key.n, signature, .big) catch
            return PkcsError.SignatureInvalid;

        const recovered = self.public_key.n.powPublic(sig_fe, self.public_key.e) catch
            return PkcsError.SignatureInvalid;

        const recovered_bytes = allocator.alloc(u8, self.keySizeBytes()) catch
            return PkcsError.HostMemory;
        defer allocator.free(recovered_bytes);

        recovered.toBytes(recovered_bytes, .big) catch
            return PkcsError.GeneralError;

        if (sign_request.len != self.keySizeBytes())
            return PkcsError.GeneralError;

        var mismatch: u16 = 0;
        for (recovered_bytes, sign_request[0..]) |a, b|
            mismatch |= a ^ b;

        if (mismatch != 0)
            return PkcsError.SignatureInvalid;
    }

    fn createVerifyBlock(self: *Verify, allocator: std.mem.Allocator) PkcsError![]u8 {
        return switch (self.sign_type) {
            .RawRsa => createRawSignRequest(&self.msg_buffer, allocator, self.public_key.n.bits() / 8),
            .Pkcs1Pad => createPkcs1PaddedSignRequest(&self.msg_buffer, allocator, self.public_key.n.bits() / 8),
            .DigestAndSign => createPkcs1PaddedHashRequest(&self.hasher.?, allocator, self.public_key.n.bits() / 8),
        };
    }

    pub fn keySizeBytes(self: *Verify) usize {
        return self.public_key.n.bits() / 8;
    }

    pub fn deinit(self: *Verify, allocator: std.mem.Allocator) void {
        self.hasher = null;

        if (self.msg_buffer != null)
            self.msg_buffer.?.deinit(allocator);
    }
};

pub const Encrypt = struct {
    multipart_operation: bool,
    modulus: []const u8,
    exponent: []const u8,
    msg_buffer: std.ArrayList(u8),
    raw: bool,

    pub fn update(self: *Encrypt, allocator: std.mem.Allocator, data: []const u8) PkcsError![]u8 {
        self.msg_buffer.appendSlice(allocator, data) catch
            return PkcsError.HostMemory;

        return &[_]u8{};
    }

    fn pad(self: *Encrypt, allocator: std.mem.Allocator, io: std.Io) PkcsError![]u8 {
        var buf = allocator.alloc(u8, self.keySizeBytes()) catch
            return PkcsError.HostMemory;
        errdefer allocator.free(buf);

        @memset(buf, 0x00);

        if (self.raw) {
            if (self.msg_buffer.items.len != self.keySizeBytes())
                return PkcsError.DataLenRange;
        } else {
            if (self.msg_buffer.items.len > self.keySizeBytes() - 11)
                return PkcsError.DataLenRange;
        }

        const msg = self.msg_buffer.toOwnedSlice(allocator) catch
            return PkcsError.HostMemory;
        defer allocator.free(msg);
        defer std.crypto.secureZero(u8, msg);

        if (!self.raw) {
            const rand: std.Random.IoSource = .{ .io = io };
            const difference: usize = self.keySizeBytes() - msg.len - 3;

            buf[1] = 0x02;

            for (2..2 + difference) |i| {
                buf[i] = rand.interface().uintLessThan(u8, std.math.maxInt(u8)) + 1;
            }
        }

        @memcpy(buf[(self.keySizeBytes() - msg.len)..], msg);

        return buf;
    }

    pub fn encrypt(self: *Encrypt, allocator: std.mem.Allocator, io: std.Io) PkcsError![]u8 {
        const rsa_public_key = std.crypto.Certificate.rsa.PublicKey.fromBytes(self.exponent, self.modulus) catch
            return PkcsError.GeneralError;

        const Modulus = std.crypto.ff.Modulus(4096);
        const Fe = Modulus.Fe;

        const buffer = try self.pad(allocator, io);
        defer allocator.free(buffer);

        const m = Fe.fromBytes(rsa_public_key.n, buffer[0..], .big) catch
            return PkcsError.GeneralError;

        const e = rsa_public_key.n.powPublic(m, rsa_public_key.e) catch
            return PkcsError.GeneralError;

        const result = allocator.alloc(u8, self.keySizeBytes()) catch
            return PkcsError.HostMemory;
        errdefer allocator.free(result);

        e.toBytes(result, .big) catch
            return PkcsError.HostMemory;

        return result;
    }

    pub fn keySizeBytes(self: *Encrypt) usize {
        return self.modulus.len;
    }

    pub fn deinit(self: *Encrypt, allocator: std.mem.Allocator) void {
        self.msg_buffer.deinit(allocator);
        allocator.free(self.modulus);
        allocator.free(self.exponent);
    }
};

pub const Decrypt = struct {
    multipart_operation: bool,
    private_key: pkcs.CK_OBJECT_HANDLE,
    key_size: usize,
    msg_buffer: std.ArrayList(u8),
    raw: bool,

    pub fn update(self: *Decrypt, allocator: std.mem.Allocator, data: []const u8) PkcsError![]u8 {
        self.msg_buffer.appendSlice(allocator, data) catch
            return PkcsError.HostMemory;

        return &[_]u8{};
    }

    pub fn createDecryptRequest(self: *Decrypt, allocator: std.mem.Allocator) PkcsError![]u8 {
        return self.msg_buffer.toOwnedSlice(allocator) catch
            return PkcsError.HostMemory;
    }

    pub fn stripPad(self: *const Decrypt, data: []const u8) PkcsError![]const u8 {
        if (self.raw)
            return data;

        var start_index: usize = 0;

        for (data, 0..) |b, i| {
            start_index += 1;

            if (b == 0x00 and i > 0)
                break;
        }

        if (start_index >= data.len)
            return PkcsError.EncryptedDataInvalid;

        return data[start_index..];
    }

    pub fn keySizeBytes(self: *Decrypt) usize {
        return self.key_size;
    }

    pub fn deinit(self: *Decrypt, allocator: std.mem.Allocator) void {
        self.msg_buffer.deinit(allocator);
    }
};

pub const Search = struct {
    index: usize,
    found_objects: []pkcs.CK_OBJECT_HANDLE,

    pub fn deinit(self: *Search, allocator: std.mem.Allocator) void {
        allocator.free(self.found_objects);
    }
};

pub const Operation = union(enum) {
    none: None,
    digest: Digest,
    sign: Sign,
    verify: Verify,
    encrypt: Encrypt,
    decrypt: Decrypt,
    search: Search,

    pub fn deinit(self: *Operation, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .none, .digest => {},
            .sign => self.sign.deinit(allocator),
            .verify => self.verify.deinit(allocator),
            .encrypt => self.encrypt.deinit(allocator),
            .decrypt => self.decrypt.deinit(allocator),
            .search => self.search.deinit(allocator),
        }
    }
};

fn createRawSignRequest(msg_buffer: *?std.ArrayList(u8), allocator: std.mem.Allocator, key_size: usize) PkcsError![]u8 {
    const payload = msg_buffer.*.?.toOwnedSlice(allocator) catch
        return PkcsError.HostMemory;
    errdefer allocator.free(payload);

    msg_buffer.* = null;

    if (payload.len != key_size)
        return PkcsError.DataLenRange;

    return payload;
}

fn createPkcs1PaddedSignRequest(msg_buffer: *?std.ArrayList(u8), allocator: std.mem.Allocator, key_size: usize) PkcsError![]u8 {
    const payload = msg_buffer.*.?.toOwnedSlice(allocator) catch
        return PkcsError.HostMemory;
    defer allocator.free(payload);

    msg_buffer.* = null;

    if (payload.len > key_size - 11)
        return PkcsError.DataLenRange;

    var request = allocator.alloc(u8, key_size) catch
        return PkcsError.HostMemory;

    for (request) |*b|
        b.* = 0xff;

    const data_start_index = key_size - payload.len;
    request[0] = 0x00;
    request[1] = 0x01;
    request[data_start_index - 1] = 0x00;
    @memcpy(request[data_start_index..key_size], payload);

    return request;
}

fn createHashedSignRequest(hash: *hasher.Hasher, allocator: std.mem.Allocator) PkcsError![]u8 {
    const prefix = getPrefixFromHasher(hash);

    const payload = hash.finalize(allocator) catch
        return PkcsError.HostMemory;
    defer allocator.free(payload);

    var request = allocator.alloc(u8, prefix.len + payload.len) catch
        return PkcsError.HostMemory;

    @memcpy(request[0..prefix.len], prefix);
    @memcpy(request[prefix.len..], payload);

    return request;
}

fn createPkcs1PaddedHashRequest(hash: *hasher.Hasher, allocator: std.mem.Allocator, key_size: usize) PkcsError![]u8 {
    const prefix = getPrefixFromHasher(hash);
    const digest = hash.finalize(allocator) catch
        return PkcsError.HostMemory;
    defer allocator.free(digest);

    const digest_info_len = prefix.len + digest.len;
    if (digest_info_len > key_size - 11)
        return PkcsError.DataLenRange;

    const request = allocator.alloc(u8, key_size) catch
        return PkcsError.HostMemory;

    @memset(request, 0xff);
    const data_start = key_size - digest_info_len;
    request[0] = 0x00;
    request[1] = 0x01;
    request[data_start - 1] = 0x00;
    @memcpy(request[data_start..][0..prefix.len], prefix);
    @memcpy(request[data_start + prefix.len ..][0..digest.len], digest);

    return request;
}

fn getPrefixFromHasher(hash: *hasher.Hasher) []const u8 {
    return switch (hash.*) {
        .md5 => md5_prefix[0..md5_prefix.len],
        .sha1 => sha1_prefix[0..sha1_prefix.len],
        .sha256 => sha256_prefix[0..sha256_prefix.len],
        .sha384 => sha384_prefix[0..sha384_prefix.len],
        .sha512 => sha512_prefix[0..sha512_prefix.len],
        .ripemd160 => ripemd160_prefix[0..ripemd160_prefix.len],
    };
}

test "sha1" {
    const expected_sign_request = [_]u8{ 0x30, 0x21, 0x30, 0x9, 0x6, 0x5, 0x2b, 0xe, 0x3, 0x2, 0x1a, 0x5, 0x0, 0x4, 0x14, 0x71, 0x10, 0xed, 0xa4, 0xd0, 0x9e, 0x6, 0x2a, 0xa5, 0xe4, 0xa3, 0x90, 0xb0, 0xa5, 0x72, 0xac, 0xd, 0x2c, 0x2, 0x20 };
    const data = [_]u8{ 0x31, 0x32, 0x33, 0x34 };

    const hash = try hasher.createAndInit(hasher.HasherType.sha1);

    var sign_operation = Sign{
        .hasher = hash,
        .sign_type = .DigestAndSign,
        .key_size = 256,
        .multipart_operation = false,
        .private_key = 0,
        .msg_buffer = null,
    };

    try sign_operation.update(std.testing.allocator, data[0..data.len]);

    const sign_request = try sign_operation.createSignRequest(std.testing.allocator);
    defer std.testing.allocator.free(sign_request);

    try std.testing.expectEqualSlices(
        u8,
        expected_sign_request[0..expected_sign_request.len],
        sign_request,
    );
}

test "2 step sha1" {
    const expected_sign_request = [_]u8{ 0x30, 0x21, 0x30, 0x9, 0x6, 0x5, 0x2b, 0xe, 0x3, 0x2, 0x1a, 0x5, 0x0, 0x4, 0x14, 0x71, 0x10, 0xed, 0xa4, 0xd0, 0x9e, 0x6, 0x2a, 0xa5, 0xe4, 0xa3, 0x90, 0xb0, 0xa5, 0x72, 0xac, 0xd, 0x2c, 0x2, 0x20 };
    const data1 = [_]u8{ 0x31, 0x32 };
    const data2 = [_]u8{ 0x33, 0x34 };

    const hash = try hasher.createAndInit(hasher.HasherType.sha1);

    var sign_operation = Sign{
        .hasher = hash,
        .sign_type = .DigestAndSign,
        .key_size = 256,
        .multipart_operation = false,
        .private_key = 0,
        .msg_buffer = null,
    };

    try sign_operation.update(std.testing.allocator, data1[0..data1.len]);
    try sign_operation.update(std.testing.allocator, data2[0..data2.len]);

    const sign_request = try sign_operation.createSignRequest(std.testing.allocator);
    defer std.testing.allocator.free(sign_request);

    try std.testing.expectEqualSlices(
        u8,
        expected_sign_request[0..expected_sign_request.len],
        sign_request,
    );
}

test "deinit sha1 sign" {
    const data = [_]u8{ 0x31, 0x32, 0x33, 0x34 };

    const hash = try hasher.createAndInit(hasher.HasherType.sha1);

    var sign_operation = Sign{
        .hasher = hash,
        .key_size = 256,
        .sign_type = .DigestAndSign,
        .multipart_operation = false,
        .private_key = 0,
        .msg_buffer = null,
    };

    try sign_operation.update(std.testing.allocator, data[0..data.len]);

    sign_operation.deinit(std.testing.allocator);
}

test "deinit plain sign" {
    const data = [_]u8{ 0x31, 0x32, 0x33, 0x34 };
    const msg_buffer = std.ArrayList(u8).empty;

    var sign_operation = Sign{
        .hasher = null,
        .sign_type = .Pkcs1Pad,
        .key_size = 256,
        .multipart_operation = false,
        .private_key = 0,
        .msg_buffer = msg_buffer,
    };

    try sign_operation.update(std.testing.allocator, data[0..data.len]);

    sign_operation.deinit(std.testing.allocator);
}

test "sha512" {
    const expected_sign_request = [_]u8{
        0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40,
        0xd4, 0x04, 0x55, 0x9f, 0x60, 0x2e, 0xab, 0x6f, 0xd6, 0x02, 0xac, 0x76, 0x80, 0xda, 0xcb, 0xfa, //
        0xad, 0xd1, 0x36, 0x30, 0x33, 0x5e, 0x95, 0x1f, 0x09, 0x7a, 0xf3, 0x90, 0x0e, 0x9d, 0xe1, 0x76,
        0xb6, 0xdb, 0x28, 0x51, 0x2f, 0x2e, 0x00, 0x0b, 0x9d, 0x04, 0xfb, 0xa5, 0x13, 0x3e, 0x8b, 0x1c,
        0x6e, 0x8d, 0xf5, 0x9d, 0xb3, 0xa8, 0xab, 0x9d, 0x60, 0xbe, 0x4b, 0x97, 0xcc, 0x9e, 0x81, 0xdb,
    };
    const data = [_]u8{ 0x31, 0x32, 0x33, 0x34 };

    const hash = try hasher.createAndInit(hasher.HasherType.sha512);

    var sign_operation = Sign{
        .hasher = hash,
        .sign_type = .DigestAndSign,
        .key_size = 256,
        .multipart_operation = false,
        .private_key = 0,
        .msg_buffer = null,
    };

    try sign_operation.update(std.testing.allocator, data[0..data.len]);

    const sign_request = try sign_operation.createSignRequest(std.testing.allocator);
    defer std.testing.allocator.free(sign_request);

    try std.testing.expectEqualSlices(
        u8,
        expected_sign_request[0..expected_sign_request.len],
        sign_request,
    );
}

test "sha256" {
    const expected_sign_request = [_]u8{ 0x30, 0x31, 0x30, 0xd, 0x6, 0x9, 0x60, 0x86, 0x48, 0x1, 0x65, 0x3, 0x4, 0x2, 0x1, 0x5, 0x0, 0x4, 0x20, 0x3, 0xac, 0x67, 0x42, 0x16, 0xf3, 0xe1, 0x5c, 0x76, 0x1e, 0xe1, 0xa5, 0xe2, 0x55, 0xf0, 0x67, 0x95, 0x36, 0x23, 0xc8, 0xb3, 0x88, 0xb4, 0x45, 0x9e, 0x13, 0xf9, 0x78, 0xd7, 0xc8, 0x46, 0xf4 };
    const data = [_]u8{ 0x31, 0x32, 0x33, 0x34 };

    const hash = try hasher.createAndInit(hasher.HasherType.sha256);

    var sign_operation = Sign{
        .hasher = hash,
        .sign_type = .DigestAndSign,
        .key_size = 256,
        .multipart_operation = false,
        .private_key = 0,
        .msg_buffer = null,
    };

    try sign_operation.update(std.testing.allocator, data[0..data.len]);

    const sign_request = try sign_operation.createSignRequest(std.testing.allocator);
    defer std.testing.allocator.free(sign_request);

    try std.testing.expectEqualSlices(
        u8,
        expected_sign_request[0..expected_sign_request.len],
        sign_request,
    );
}

test "strip pad raw" {
    const decrypt = Decrypt{
        .private_key = 0,
        .key_size = 256,
        .multipart_operation = false,
        .msg_buffer = std.ArrayList(u8).empty,
        .raw = true,
    };

    const test_cases = [_][]const u8{
        &[_]u8{},
        &[_]u8{0x00},
        &[_]u8{ 0x01, 0x02, 0x00 },
        &[_]u8{ 0x01, 0x02, 0x03, 0x00, 0x04, 0x05 },
        &([_]u8{0x01} ** 256),
    };

    for (test_cases) |tc| {
        const result = try decrypt.stripPad(tc);
        try std.testing.expectEqualSlices(u8, tc, result);
    }
}

test "strip pad padded" {
    const decrypt = Decrypt{
        .private_key = 0,
        .key_size = 256,
        .multipart_operation = false,
        .msg_buffer = std.ArrayList(u8).empty,
        .raw = false,
    };

    const test_cases = [_]struct {
        input: []const u8,
        expected: []const u8,
    }{
        .{
            .input = &[_]u8{ 0x00, 0x00, 0x01, 0x02 },
            .expected = &[_]u8{ 0x01, 0x02 },
        },
        .{
            .input = &[_]u8{ 0x00, 0x01, 0x02, 0x00, 0x03, 0x04 },
            .expected = &[_]u8{ 0x03, 0x04 },
        },
        .{
            .input = &[_]u8{ 0x00, 0x01, 0x02, 0x00, 0x00, 0x00 },
            .expected = &[_]u8{ 0x00, 0x00 },
        },
        .{
            .input = &[_]u8{ 0x00, 0x01, 0x02, 0x00, 0xFF },
            .expected = &[_]u8{0xFF},
        },
    };

    for (test_cases) |tc| {
        const result = try decrypt.stripPad(tc.input);
        try std.testing.expectEqualSlices(u8, tc.expected, result);
    }
}

test "strip pad padded malformed" {
    const decrypt = Decrypt{
        .private_key = 0,
        .multipart_operation = false,
        .msg_buffer = std.ArrayList(u8).empty,
        .key_size = 256,
        .raw = false,
    };

    const test_cases = [_][]const u8{
        &[_]u8{},
        &[_]u8{0x00},
        &[_]u8{ 0x01, 0x02, 0x00 },
        &[_]u8{ 0x01, 0x02, 0x03 },
    };

    for (test_cases) |tc| {
        const result = decrypt.stripPad(tc);
        try std.testing.expectError(PkcsError.EncryptedDataInvalid, result);
    }
}

test "pad and strip" {
    const decrypt = Decrypt{
        .private_key = 0,
        .multipart_operation = false,
        .msg_buffer = std.ArrayList(u8).empty,
        .raw = false,
        .key_size = 256,
    };

    const test_cases = [_][]const u8{
        &[_]u8{0x00},
        &[_]u8{ 0x01, 0x02, 0x00 },
        &[_]u8{ 0x01, 0x02, 0x03, 0x00, 0x04, 0x05 },
        &([_]u8{0x01} ** 245),
    };

    const io = std.testing.io;

    for (test_cases) |tc| {
        var encrypt = Encrypt{
            .multipart_operation = false,
            .modulus = &([_]u8{0x01} ** 256),
            .exponent = &([_]u8{0x01} ** 256),
            .msg_buffer = std.ArrayList(u8).empty,
            .raw = false,
        };
        defer encrypt.msg_buffer.deinit(std.testing.allocator);

        _ = try encrypt.update(std.testing.allocator, tc);

        const padded = try encrypt.pad(std.testing.allocator, io);
        defer std.testing.allocator.free(padded);

        const result = try decrypt.stripPad(padded);

        try std.testing.expectEqualSlices(u8, tc, result);
    }
}

test "raw sign request with invalid length" {
    var msg_buffer: ?std.ArrayList(u8) = std.ArrayList(u8).empty;
    try msg_buffer.?.appendNTimes(std.testing.allocator, 0x01, 50);

    const result = createRawSignRequest(&msg_buffer, std.testing.allocator, 128);
    try std.testing.expectError(pkcs_error.PkcsError.DataLenRange, result);

    try std.testing.expectEqual(null, msg_buffer);
}

test "raw sign request with valid length" {
    const key_size: comptime_int = 128;

    var msg_buffer: ?std.ArrayList(u8) = std.ArrayList(u8).empty;
    try msg_buffer.?.appendNTimes(std.testing.allocator, 0x01, key_size);

    const result = try createRawSignRequest(&msg_buffer, std.testing.allocator, key_size);

    const expected: [key_size]u8 = [_]u8{0x01} ** 128;
    try std.testing.expectEqualSlices(u8, &expected, result);

    try std.testing.expectEqual(null, msg_buffer);

    std.testing.allocator.free(result);
}

test "pkcs1 padded sign request with invalid length" {
    var msg_buffer: ?std.ArrayList(u8) = std.ArrayList(u8).empty;
    try msg_buffer.?.appendNTimes(std.testing.allocator, 0x01, 118);

    const result = createPkcs1PaddedSignRequest(&msg_buffer, std.testing.allocator, 128);
    try std.testing.expectError(pkcs_error.PkcsError.DataLenRange, result);

    try std.testing.expectEqual(null, msg_buffer);
}

test "pkcs1 padded request with valid length" {
    const key_size: comptime_int = 128;

    var msg_buffer: ?std.ArrayList(u8) = std.ArrayList(u8).empty;
    try msg_buffer.?.appendNTimes(std.testing.allocator, 0x01, 117);

    const result = try createPkcs1PaddedSignRequest(&msg_buffer, std.testing.allocator, key_size);

    const expected: [key_size]u8 = [_]u8{ 0x00, 0x01 } ++ [_]u8{0xff} ** 8 ++ [_]u8{0x00} ++ [_]u8{0x01} ** 117;
    try std.testing.expectEqualSlices(u8, &expected, result);

    try std.testing.expectEqual(null, msg_buffer);

    std.testing.allocator.free(result);
}

const TestKey = struct {
    modulus: []u8,
    public_exponent: []u8,
    private_exponent: []u8,

    fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
        allocator.free(self.modulus);
        allocator.free(self.public_exponent);
        allocator.free(self.private_exponent);
    }
};

fn TestHelper(signature_size: usize) type {
    return struct {
        const Self = @This();

        key: TestKey,

        pub fn loadRsaKey(allocator: std.mem.Allocator, io: std.Io, filename: []const u8) !@This() {
            const pem = try std.Io.Dir.readFileAlloc(std.Io.Dir.cwd(), io, filename, allocator, .unlimited);
            defer allocator.free(pem);
            const der = try decodePem(allocator, pem);
            defer allocator.free(der);
            const Element = std.crypto.Certificate.der.Element;

            const private_key_info = try Element.parse(der, 0);
            const pki_version = try Element.parse(der, private_key_info.slice.start);
            const algorithm = try Element.parse(der, pki_version.slice.end);
            const private_key_octet = try Element.parse(der, algorithm.slice.end);

            const rsa_private_key = try Element.parse(der, private_key_octet.slice.start);
            const rsa_version = try Element.parse(der, rsa_private_key.slice.start);
            const modulus_elem = try Element.parse(der, rsa_version.slice.end);
            const public_exponent_elem = try Element.parse(der, modulus_elem.slice.end);
            const private_exponent_elem = try Element.parse(der, public_exponent_elem.slice.end);

            const modulus = try allocator.dupe(u8, trimLeadingZeros(der[modulus_elem.slice.start..modulus_elem.slice.end]));
            errdefer allocator.free(modulus);
            const public_exponent = try allocator.dupe(u8, trimLeadingZeros(der[public_exponent_elem.slice.start..public_exponent_elem.slice.end]));
            errdefer allocator.free(public_exponent);
            const private_exponent = try allocator.dupe(u8, trimLeadingZeros(der[private_exponent_elem.slice.start..private_exponent_elem.slice.end]));
            errdefer allocator.free(private_exponent);

            return Self{
                .key = TestKey{
                    .modulus = modulus,
                    .public_exponent = public_exponent,
                    .private_exponent = private_exponent,
                },
            };
        }

        pub fn testKernel(self: Self, m: pkcs.CK_MECHANISM_TYPE, ta: std.mem.Allocator, d: []const u8) !void {
            if (m == pkcs.CKM_RSA_X_509 and d.len != signature_size)
                return;

            if (m != pkcs.CKM_RSA_X_509 and d.len != signature_size - 11)
                return;

            const public_key = try std.crypto.Certificate.rsa.PublicKey.fromBytes(self.key.public_exponent, self.key.modulus);

            var sign_operation = try Sign.init(m, self.key.modulus.len, 1);
            defer sign_operation.deinit(ta);

            try sign_operation.update(ta, d);

            const sign_request = try sign_operation.createSignRequest(ta);
            defer ta.free(sign_request);

            const plain_sign = sign_operation.sign_type != .DigestAndSign;
            const block = buildSignedBlock(sign_request, plain_sign);

            const signature = try rsaOp(self.key.modulus, self.key.private_exponent, &block);

            var verify_operation = try Verify.init(m, public_key);
            defer verify_operation.deinit(ta);
            try verify_operation.update(ta, d);

            try verify_operation.verify(ta, &signature);

            var verify_operation_tampered = try Verify.init(m, public_key);
            defer verify_operation_tampered.deinit(ta);
            try verify_operation_tampered.update(ta, d);

            var tampered = signature;
            tampered[0] ^= 0xff;
            try std.testing.expectError(PkcsError.SignatureInvalid, verify_operation_tampered.verify(ta, &tampered));
        }

        fn buildSignedBlock(sign_request: []const u8, plain_sign: bool) [signature_size]u8 {
            var block: [signature_size]u8 = [_]u8{0x00} ** signature_size;

            if (plain_sign) {
                std.debug.assert(sign_request.len == signature_size);
                @memcpy(&block, sign_request);
                return block;
            }

            const data_start = signature_size - sign_request.len;
            block[1] = 0x01;
            @memset(block[2 .. data_start - 1], 0xff);
            @memcpy(block[data_start..], sign_request);

            return block;
        }

        fn decodePem(allocator: std.mem.Allocator, pem: []const u8) ![]u8 {
            var base64 = std.ArrayList(u8).empty;
            defer base64.deinit(allocator);
            var lines = std.mem.tokenizeScalar(u8, pem, '\n');
            while (lines.next()) |line| {
                const trimmed = std.mem.trim(u8, line, " \r\t");
                if (trimmed.len == 0 or std.mem.startsWith(u8, trimmed, "-----"))
                    continue;
                try base64.appendSlice(allocator, trimmed);
            }
            const decoder = std.base64.standard.Decoder;
            const len = try decoder.calcSizeForSlice(base64.items);
            const der = try allocator.alloc(u8, len);
            errdefer allocator.free(der);
            try decoder.decode(der, base64.items);
            return der;
        }

        fn rsaOp(modulus: []const u8, exponent: []const u8, input: []const u8) ![signature_size]u8 {
            const Modulus = std.crypto.ff.Modulus(signature_size * 8);

            const n = try Modulus.fromBytes(modulus, .big);
            const m = try Modulus.Fe.fromBytes(n, input, .big);
            const result = try n.powWithEncodedExponent(m, exponent, .big);

            var out: [signature_size]u8 = undefined;
            try result.toBytes(&out, .big);

            return out;
        }

        fn trimLeadingZeros(bytes: []const u8) []const u8 {
            var i: usize = 0;
            while (i < bytes.len and bytes[i] == 0x00)
                i += 1;
            return bytes[i..];
        }
    };
}

test "sign and verify" {
    const ta = std.testing.allocator;
    const tio = std.testing.io;

    const mechanisms = [_]pkcs.CK_MECHANISM_TYPE{
        pkcs.CKM_RSA_X_509,
        pkcs.CKM_RSA_PKCS,
        pkcs.CKM_MD5_RSA_PKCS,
        pkcs.CKM_SHA1_RSA_PKCS,
        pkcs.CKM_SHA256_RSA_PKCS,
        pkcs.CKM_SHA384_RSA_PKCS,
        pkcs.CKM_SHA512_RSA_PKCS,
        pkcs.CKM_RIPEMD160_RSA_PKCS,
    };

    const data_1024 = &[_][]const u8{
        &[_]u8{},
        &[_]u8{0x00},
        &[_]u8{ 0x01, 0x02, 0x03 },
        &([_]u8{0xAB} ** (128 - 11)),
        &([_]u8{0x00} ++ [_]u8{0x01} ** (128 - 1)),
    };

    var test_helper_1024 = try TestHelper(128).loadRsaKey(ta, tio, "testdata/1024.key");
    defer test_helper_1024.key.deinit(ta);

    for (data_1024) |d|
        for (mechanisms) |m|
            try test_helper_1024.testKernel(m, ta, d);

    const data_2048 = &[_][]const u8{
        &[_]u8{},
        &[_]u8{0x00},
        &[_]u8{ 0x01, 0x02, 0x03 },
        &([_]u8{0xAB} ** (256 - 11)),
        &([_]u8{0x00} ++ [_]u8{0x01} ** (256 - 1)),
    };

    var test_helper_2048 = try TestHelper(256).loadRsaKey(ta, tio, "testdata/2048.key");
    defer test_helper_2048.key.deinit(ta);

    for (data_2048) |d|
        for (mechanisms) |m|
            try test_helper_2048.testKernel(m, ta, d);
}
