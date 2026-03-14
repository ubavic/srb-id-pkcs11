const std = @import("std");

const hasher = @import("hasher.zig");
const pkcs = @import("pkcs.zig").pkcs;

const pkcs_error = @import("pkcs_error.zig");
const PkcsError = pkcs_error.PkcsError;

// rfc8017 - Section 9.2
const md5_prefix: [18]u8 = [_]u8{ 0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10 };
const sha1_prefix: [15]u8 = [_]u8{ 0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14 };
const sha256_prefix: [19]u8 = [_]u8{ 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20 };
const sha384_prefix: [19]u8 = [_]u8{ 0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30 };
const sha512_prefix: [19]u8 = [_]u8{ 0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40 };

pub const signature_size: usize = 256;
pub const encrypted_data_size: usize = 256;
const rsa_request_size: usize = 255;

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

    pub fn deinit(self: *Digest, allocator: std.mem.Allocator) void {
        self.hasher.destroy(allocator);
    }
};

pub const Sign = struct {
    private_key: pkcs.CK_OBJECT_HANDLE,
    multipart_operation: bool,
    hasher: ?hasher.Hasher,
    msg_buffer: ?std.ArrayList(u8),

    pub fn update(self: *Sign, allocator: std.mem.Allocator, data: []const u8) PkcsError!void {
        if (self.hasher != null) {
            self.hasher.?.update(data);
        } else if (self.msg_buffer != null) {
            self.msg_buffer.?.appendSlice(allocator, data) catch
                return PkcsError.HostMemory;
        } else unreachable;
    }

    pub fn createSignRequest(self: *Sign, allocator: std.mem.Allocator) PkcsError![]u8 {
        if (self.hasher != null) {
            return createHashedSignRequest(&self.hasher.?, allocator);
        } else if (self.msg_buffer != null) {
            return createPlainSignRequest(&self.msg_buffer, allocator);
        } else unreachable;
    }

    pub fn deinit(self: *Sign, allocator: std.mem.Allocator) void {
        if (self.hasher != null)
            self.hasher.?.destroy(allocator);

        if (self.msg_buffer != null)
            self.msg_buffer.?.deinit(allocator);
    }
};

pub const Verify = struct {
    private_key: pkcs.CK_OBJECT_HANDLE,
    multipart_operation: bool,
    hasher: ?hasher.Hasher,
    msg_buffer: ?std.ArrayList(u8),

    pub fn update(self: *Verify, allocator: std.mem.Allocator, data: []const u8) PkcsError!void {
        if (self.hasher != null) {
            self.hasher.?.update(data);
        } else if (self.msg_buffer != null) {
            self.msg_buffer.?.appendSlice(allocator, data) catch
                return PkcsError.HostMemory;
        } else unreachable;
    }

    pub fn createSignRequest(self: *Verify, allocator: std.mem.Allocator) PkcsError![]u8 {
        if (self.hasher != null) {
            return createHashedSignRequest(&self.hasher.?, allocator);
        } else if (self.msg_buffer != null) {
            return createPlainSignRequest(&self.msg_buffer, allocator);
        } else unreachable;
    }

    pub fn deinit(self: *Verify, allocator: std.mem.Allocator) void {
        if (self.hasher != null)
            self.hasher.?.destroy(allocator);

        if (self.msg_buffer != null)
            self.msg_buffer.?.deinit(allocator);
    }
};

pub const Encrypt = struct {
    multipart_operation: bool,
    public_key: pkcs.CK_OBJECT_HANDLE,
    modulus: []const u8,
    exponent: []const u8,
    msg_buffer: std.ArrayList(u8),
    raw: bool,

    pub fn update(self: *Encrypt, allocator: std.mem.Allocator, data: []const u8) PkcsError![]u8 {
        self.msg_buffer.appendSlice(allocator, data) catch
            return PkcsError.HostMemory;

        return &[_]u8{};
    }

    fn pad(self: *Encrypt, allocator: std.mem.Allocator) PkcsError![256]u8 {
        var buf: [256]u8 = [1]u8{0x00} ** encrypted_data_size;

        if (self.raw) {
            if (self.msg_buffer.items.len != encrypted_data_size)
                return PkcsError.DataLenRange;
        } else {
            if (self.msg_buffer.items.len > encrypted_data_size - 11)
                return PkcsError.DataLenRange;
        }

        const msg = self.msg_buffer.toOwnedSlice(allocator) catch
            return PkcsError.HostMemory;
        defer allocator.free(msg);
        defer std.crypto.secureZero(u8, msg);

        if (!self.raw) {
            const rand = std.crypto.random;
            const difference: usize = encrypted_data_size - msg.len - 3;

            buf[1] = 0x02;

            for (2..2 + difference) |i| {
                buf[i] = rand.uintLessThan(u8, std.math.maxInt(u8)) + 1;
            }
        }

        @memcpy(buf[(encrypted_data_size - msg.len)..], msg);

        return buf;
    }

    pub fn encrypt(self: *Encrypt, allocator: std.mem.Allocator) PkcsError![256]u8 {
        const rsa_public_key = std.crypto.Certificate.rsa.PublicKey.fromBytes(self.exponent, self.modulus) catch
            return PkcsError.GeneralError;

        const max_modulus_bits = 4096;
        const Modulus = std.crypto.ff.Modulus(max_modulus_bits);
        const Fe = Modulus.Fe;

        const buffer = try self.pad(allocator);

        const m = Fe.fromBytes(rsa_public_key.n, buffer[0..], .big) catch
            return PkcsError.GeneralError;

        const e = rsa_public_key.n.powPublic(m, rsa_public_key.e) catch
            return PkcsError.GeneralError;

        var result: [256]u8 = undefined;
        e.toBytes(&result, .big) catch
            return PkcsError.HostMemory;

        return result;
    }

    pub fn deinit(self: *Encrypt, allocator: std.mem.Allocator) void {
        self.msg_buffer.deinit(allocator);
    }
};

pub const Decrypt = struct {
    multipart_operation: bool,
    private_key: pkcs.CK_OBJECT_HANDLE,
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

            if (b == 0 and i > 0)
                break;
        }

        if (start_index >= data.len)
            return PkcsError.GeneralError;

        return data[start_index..];
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
            .none => {},
            .digest => self.digest.deinit(allocator),
            .sign => self.sign.deinit(allocator),
            .verify => self.verify.deinit(allocator),
            .encrypt => self.encrypt.deinit(allocator),
            .decrypt => self.decrypt.deinit(allocator),
            .search => self.search.deinit(allocator),
        }
    }
};

fn createPlainSignRequest(msg_buffer: *?std.ArrayList(u8), allocator: std.mem.Allocator) PkcsError![]u8 {
    const payload = msg_buffer.*.?.toOwnedSlice(allocator) catch
        return PkcsError.HostMemory;
    defer allocator.free(payload);

    msg_buffer.* = null;

    if (payload.len > rsa_request_size - 2)
        return PkcsError.DataLenRange;

    var request = allocator.alloc(u8, rsa_request_size) catch
        return PkcsError.HostMemory;

    for (request) |*b|
        b.* = 0xff;

    const data_start_index = rsa_request_size - payload.len;
    request[0] = 1;
    request[data_start_index - 1] = 0;
    @memcpy(request[data_start_index..rsa_request_size], payload);

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

fn getPrefixFromHasher(hash: *hasher.Hasher) []const u8 {
    return switch (hash.*.hasherType.?) {
        .md5 => md5_prefix[0..md5_prefix.len],
        .sha1 => sha1_prefix[0..sha1_prefix.len],
        .sha256 => sha256_prefix[0..sha256_prefix.len],
        .sha384 => sha384_prefix[0..sha384_prefix.len],
        .sha512 => sha512_prefix[0..sha512_prefix.len],
    };
}

test "sha1" {
    const expected_sign_request = [_]u8{ 0x30, 0x21, 0x30, 0x9, 0x6, 0x5, 0x2b, 0xe, 0x3, 0x2, 0x1a, 0x5, 0x0, 0x4, 0x14, 0x71, 0x10, 0xed, 0xa4, 0xd0, 0x9e, 0x6, 0x2a, 0xa5, 0xe4, 0xa3, 0x90, 0xb0, 0xa5, 0x72, 0xac, 0xd, 0x2c, 0x2, 0x20 };
    const data = [_]u8{ 0x31, 0x32, 0x33, 0x34 };

    const hash = try hasher.createAndInit(
        hasher.HasherType.sha1,
        std.testing.allocator,
    );

    var sign_operation = Sign{
        .hasher = hash,
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

    const hash = try hasher.createAndInit(
        hasher.HasherType.sha1,
        std.testing.allocator,
    );

    var sign_operation = Sign{
        .hasher = hash,
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

    const hash = try hasher.createAndInit(
        hasher.HasherType.sha1,
        std.testing.allocator,
    );

    var sign_operation = Sign{
        .hasher = hash,
        .multipart_operation = false,
        .private_key = 0,
        .msg_buffer = null,
    };

    try sign_operation.update(std.testing.allocator, data[0..data.len]);

    sign_operation.deinit(std.testing.allocator);
}

test "deinit plain sign" {
    const data = [_]u8{ 0x31, 0x32, 0x33, 0x34 };
    const msg_buffer = std.ArrayList(u8){};

    var sign_operation = Sign{
        .hasher = null,
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

    const hash = try hasher.createAndInit(
        hasher.HasherType.sha512,
        std.testing.allocator,
    );

    var sign_operation = Sign{
        .hasher = hash,
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

    const hash = try hasher.createAndInit(
        hasher.HasherType.sha256,
        std.testing.allocator,
    );

    var sign_operation = Sign{
        .hasher = hash,
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
        .multipart_operation = false,
        .msg_buffer = std.ArrayList(u8){},
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
        .multipart_operation = false,
        .msg_buffer = std.ArrayList(u8){},
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
        .msg_buffer = std.ArrayList(u8){},
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
        try std.testing.expectError(PkcsError.GeneralError, result);
    }
}

test "pad and strip" {
    const decrypt = Decrypt{
        .private_key = 0,
        .multipart_operation = false,
        .msg_buffer = std.ArrayList(u8){},
        .raw = false,
    };

    const test_cases = [_][]const u8{
        &[_]u8{0x00},
        &[_]u8{ 0x01, 0x02, 0x00 },
        &[_]u8{ 0x01, 0x02, 0x03, 0x00, 0x04, 0x05 },
        &([_]u8{0x01} ** 245),
    };

    for (test_cases) |tc| {
        var encrypt = Encrypt{
            .public_key = 0,
            .multipart_operation = false,
            .modulus = &[_]u8{ 0x01, 0x02, 0x00 },
            .exponent = &[_]u8{ 0x01, 0x02, 0x00 },
            .msg_buffer = std.ArrayList(u8){},
            .raw = false,
        };

        _ = try encrypt.update(std.testing.allocator, tc);

        const padded = try encrypt.pad(std.testing.allocator);
        defer encrypt.msg_buffer.deinit(std.testing.allocator);

        const result = try decrypt.stripPad(&padded);

        try std.testing.expectEqualSlices(u8, tc, result);
    }
}
