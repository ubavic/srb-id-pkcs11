const std = @import("std");

const Attribute = @import("Attribute.zig");
const hasher = @import("hasher.zig");
const object = @import("object.zig");
const pkcs = @import("../pkcs.zig");

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

pub fn signTypeFromMechanism(mechanism: ?*const pkcs.CK_MECHANISM) !SignType {
    if (mechanism == null)
        return error.ArgumentsBad;

    return switch (mechanism.?.*.mechanism) {
        pkcs.CKM_RSA_X_509 => .RawRsa,
        pkcs.CKM_RSA_PKCS => .Pkcs1Pad,
        pkcs.CKM_MD5_RSA_PKCS => .DigestAndSign,
        pkcs.CKM_SHA1_RSA_PKCS => .DigestAndSign,
        pkcs.CKM_SHA256_RSA_PKCS => .DigestAndSign,
        pkcs.CKM_SHA384_RSA_PKCS => .DigestAndSign,
        pkcs.CKM_SHA512_RSA_PKCS => .DigestAndSign,
        pkcs.CKM_RIPEMD160_RSA_PKCS => .DigestAndSign,
        else => return error.MechanismInvalid,
    };
}

pub fn encryptTypeFromMechanism(mechanism: ?*const pkcs.CK_MECHANISM) !bool {
    if (mechanism == null)
        return error.ArgumentsBad;

    if (mechanism.?.mechanism != pkcs.CKM_RSA_PKCS and mechanism.?.mechanism != pkcs.CKM_RSA_X_509)
        return error.MechanismInvalid;

    if (mechanism.?.ulParameterLen != 0)
        return error.MechanismParamInvalid;

    return mechanism.?.mechanism == pkcs.CKM_RSA_X_509;
}

pub const Digest = struct {
    hasher: hasher.Hasher,
    multipart_operation: bool,

    pub fn init(mechanism: ?*pkcs.CK_MECHANISM) !Digest {
        if (mechanism == null)
            return error.ArgumentsBad;

        const hash_mechanism = try hasher.fromDigestMechanism(mechanism.?.mechanism);
        const hash = hasher.createAndInit(hash_mechanism);

        return .{
            .hasher = hash,
            .multipart_operation = false,
        };
    }
};

pub const Sign = struct {
    private_key: pkcs.CK_OBJECT_HANDLE,
    key_size: usize,
    sign_type: SignType,
    multipart_operation: bool,
    hasher: ?hasher.Hasher,
    msg_buffer: ?std.ArrayList(u8),

    pub fn init(mechanism: ?*const pkcs.CK_MECHANISM, key_size: usize, private_key: pkcs.CK_OBJECT_HANDLE) !Sign {
        const sign_type = try signTypeFromMechanism(mechanism);
        const hash_mechanism = try hasher.fromSignMechanism(mechanism.?.*.mechanism);

        var hash: ?hasher.Hasher = null;
        var msg_buffer: ?std.ArrayList(u8) = null;
        if (hash_mechanism != null) {
            hash = hasher.createAndInit(hash_mechanism.?);
        } else msg_buffer = std.ArrayList(u8).empty;

        return .{
            .private_key = private_key,
            .key_size = key_size,
            .sign_type = sign_type,
            .hasher = hash,
            .msg_buffer = msg_buffer,
            .multipart_operation = false,
        };
    }

    pub fn update(self: *Sign, allocator: std.mem.Allocator, data: []const u8) !void {
        switch (self.sign_type) {
            .DigestAndSign => self.hasher.?.update(data),
            .RawRsa, .Pkcs1Pad => {
                self.msg_buffer.?.appendSlice(allocator, data) catch
                    return error.HostMemory;
            },
        }
    }

    pub fn createSignRequest(self: *Sign, allocator: std.mem.Allocator) ![]u8 {
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

    pub fn init(mechanism: ?*const pkcs.CK_MECHANISM, public_key: std.crypto.Certificate.rsa.PublicKey) !Verify {
        const sign_type = try signTypeFromMechanism(mechanism);
        const hash_mechanism = try hasher.fromSignMechanism(mechanism.?.*.mechanism);

        var hash: ?hasher.Hasher = null;
        var msg_buffer: ?std.ArrayList(u8) = null;
        if (hash_mechanism != null)
            hash = hasher.createAndInit(hash_mechanism.?)
        else
            msg_buffer = std.ArrayList(u8).empty;

        return Verify{
            .public_key = public_key,
            .hasher = hash,
            .sign_type = sign_type,
            .multipart_operation = false,
            .msg_buffer = msg_buffer,
        };
    }

    pub fn update(self: *Verify, allocator: std.mem.Allocator, data: []const u8) !void {
        switch (self.sign_type) {
            .DigestAndSign => self.hasher.?.update(data),
            .RawRsa, .Pkcs1Pad => {
                self.msg_buffer.?.appendSlice(allocator, data) catch
                    return error.HostMemory;
            },
        }
    }

    pub fn verify(self: *Verify, allocator: std.mem.Allocator, signature: []const u8) !void {
        const sign_request = try self.createVerifyBlock(allocator);
        defer allocator.free(sign_request);

        const Modulus = std.crypto.ff.Modulus(4096);
        const Fe = Modulus.Fe;

        const sig_fe = Fe.fromBytes(self.public_key.n, signature, .big) catch
            return error.SignatureInvalid;

        const recovered = self.public_key.n.powPublic(sig_fe, self.public_key.e) catch
            return error.SignatureInvalid;

        const recovered_bytes = allocator.alloc(u8, self.keySizeBytes()) catch
            return error.HostMemory;
        defer allocator.free(recovered_bytes);

        recovered.toBytes(recovered_bytes, .big) catch
            return error.GeneralError;

        if (sign_request.len != self.keySizeBytes())
            return error.GeneralError;

        var mismatch: u16 = 0;
        for (recovered_bytes, sign_request[0..]) |a, b|
            mismatch |= a ^ b;

        if (mismatch != 0)
            return error.SignatureInvalid;
    }

    fn createVerifyBlock(self: *Verify, allocator: std.mem.Allocator) ![]u8 {
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
    public_key: std.crypto.Certificate.rsa.PublicKey,
    multipart_operation: bool,
    msg_buffer: std.ArrayList(u8),
    raw: bool,

    pub fn init(mechanism: ?*const pkcs.CK_MECHANISM, public_key: std.crypto.Certificate.rsa.PublicKey) !Encrypt {
        const raw = try encryptTypeFromMechanism(mechanism);

        return .{
            .multipart_operation = false,
            .msg_buffer = std.ArrayList(u8).empty,
            .raw = raw,
            .public_key = public_key,
        };
    }

    pub fn update(self: *Encrypt, allocator: std.mem.Allocator, data: []const u8) ![]u8 {
        self.msg_buffer.appendSlice(allocator, data) catch
            return error.HostMemory;

        return &[_]u8{};
    }

    pub fn pad(self: *Encrypt, allocator: std.mem.Allocator, io: std.Io) ![]u8 {
        var buf = allocator.alloc(u8, self.keySizeBytes()) catch
            return error.HostMemory;
        errdefer allocator.free(buf);

        @memset(buf, 0x00);

        if (self.raw) {
            if (self.msg_buffer.items.len != self.keySizeBytes())
                return error.DataLenRange;
        } else {
            if (self.msg_buffer.items.len > self.keySizeBytes() - 11)
                return error.DataLenRange;
        }

        const msg = self.msg_buffer.toOwnedSlice(allocator) catch
            return error.HostMemory;
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

    pub fn encrypt(self: *Encrypt, allocator: std.mem.Allocator, io: std.Io) ![]u8 {
        const Modulus = std.crypto.ff.Modulus(4096);
        const Fe = Modulus.Fe;

        const buffer = try self.pad(allocator, io);
        defer allocator.free(buffer);

        const m = Fe.fromBytes(self.public_key.n, buffer[0..], .big) catch
            return error.GeneralError;

        const e = self.public_key.n.powPublic(m, self.public_key.e) catch
            return error.GeneralError;

        const result = allocator.alloc(u8, self.keySizeBytes()) catch
            return error.HostMemory;
        errdefer allocator.free(result);

        e.toBytes(result, .big) catch
            return error.HostMemory;

        return result;
    }

    pub fn keySizeBytes(self: *Encrypt) usize {
        return self.public_key.n.bits() / 8;
    }

    pub fn deinit(self: *Encrypt, allocator: std.mem.Allocator) void {
        self.msg_buffer.deinit(allocator);
    }
};

pub const Decrypt = struct {
    multipart_operation: bool,
    private_key: pkcs.CK_OBJECT_HANDLE,
    key_size: usize,
    msg_buffer: std.ArrayList(u8),
    raw: bool,

    pub fn init(mechanism: ?*pkcs.CK_MECHANISM, private_key: pkcs.CK_OBJECT_HANDLE, key_size: usize) !Decrypt {
        const raw = try encryptTypeFromMechanism(mechanism);

        return .{
            .private_key = private_key,
            .key_size = key_size,
            .multipart_operation = false,
            .msg_buffer = std.ArrayList(u8).empty,
            .raw = raw,
        };
    }

    pub fn update(self: *Decrypt, allocator: std.mem.Allocator, data: []const u8) ![]u8 {
        self.msg_buffer.appendSlice(allocator, data) catch
            return error.HostMemory;

        return &[_]u8{};
    }

    pub fn createDecryptRequest(self: *Decrypt, allocator: std.mem.Allocator) ![]u8 {
        return self.msg_buffer.toOwnedSlice(allocator) catch
            return error.HostMemory;
    }

    pub fn stripPad(self: *const Decrypt, data: []const u8) ![]const u8 {
        if (self.raw)
            return data;

        var start_index: usize = 0;

        for (data, 0..) |b, i| {
            start_index += 1;

            if (b == 0x00 and i > 0)
                break;
        }

        if (start_index >= data.len)
            return error.EncryptedDataInvalid;

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
    search_template: []Attribute,
    objects: []object.Object,
    logged_in: bool,

    pub fn deinit(self: *Search, allocator: std.mem.Allocator) void {
        object.deinitSearchTemplate(allocator, self.search_template);
    }

    pub fn findNextObjects(
        self: *Search,
        allocator: std.mem.Allocator,
        buffer: []pkcs.CK_OBJECT_HANDLE,
    ) !usize {
        var i: usize = 0;

        while (i < buffer.len and self.index < self.objects.len) {
            const current_object = self.objects[self.index];

            if (current_object.private() and !self.logged_in) {
                self.index += 1;
                continue;
            }

            var matches = true;
            for (self.search_template) |attribute| {
                if (!try current_object.hasAttributeValue(allocator, attribute)) {
                    matches = false;
                    break;
                }
            }

            self.index += 1;

            if (!matches)
                continue;

            buffer[i] = current_object.handle();
            i += 1;
        }

        return i;
    }
};

pub const Operation = union(enum) {
    none,
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

pub fn createRawSignRequest(msg_buffer: *?std.ArrayList(u8), allocator: std.mem.Allocator, key_size: usize) ![]u8 {
    const payload = msg_buffer.*.?.toOwnedSlice(allocator) catch
        return error.HostMemory;
    errdefer allocator.free(payload);

    msg_buffer.* = null;

    if (payload.len != key_size)
        return error.DataLenRange;

    return payload;
}

pub fn createPkcs1PaddedSignRequest(msg_buffer: *?std.ArrayList(u8), allocator: std.mem.Allocator, key_size: usize) ![]u8 {
    const payload = msg_buffer.*.?.toOwnedSlice(allocator) catch
        return error.HostMemory;
    defer allocator.free(payload);

    msg_buffer.* = null;

    if (payload.len > key_size - 11)
        return error.DataLenRange;

    var request = allocator.alloc(u8, key_size) catch
        return error.HostMemory;

    for (request) |*b|
        b.* = 0xff;

    const data_start_index = key_size - payload.len;
    request[0] = 0x00;
    request[1] = 0x01;
    request[data_start_index - 1] = 0x00;
    @memcpy(request[data_start_index..key_size], payload);

    return request;
}

fn createHashedSignRequest(hash: *hasher.Hasher, allocator: std.mem.Allocator) ![]u8 {
    const digest_length = hash.digestLength();

    const prefix = getPrefixFromHasher(hash);

    const request = allocator.alloc(u8, prefix.len + digest_length) catch
        return error.HostMemory;
    errdefer allocator.free(request);

    @memcpy(request[0..prefix.len], prefix);
    _ = try hash.finalize(request[prefix.len..]);

    return request;
}

fn createPkcs1PaddedHashRequest(hash: *hasher.Hasher, allocator: std.mem.Allocator, key_size: usize) ![]u8 {
    const digest_length = hash.digestLength();

    const prefix = getPrefixFromHasher(hash);

    const digest_info_len = prefix.len + digest_length;
    if (digest_info_len > key_size - 11)
        return error.DataLenRange;

    const request = allocator.alloc(u8, key_size) catch
        return error.HostMemory;
    errdefer allocator.free(request);

    @memset(request, 0xff);
    const data_start = key_size - digest_info_len;
    request[0] = 0x00;
    request[1] = 0x01;
    request[data_start - 1] = 0x00;
    @memcpy(request[data_start..][0..prefix.len], prefix);
    _ = try hash.finalize(request[data_start + prefix.len ..]);

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
