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
const sha521_prefix: [18]u8 = [_]u8{ 0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x04, 0x40 };

pub const signature_size: usize = 256;
const rsa_request_size: usize = 255;

pub const Type = enum {
    None,
    Digest,
    Sign,
    Verify,
    Search,
};

pub const None = struct {};

pub const Digest = struct {
    hasher: hasher.Hasher,
    multipart_operation: bool,
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
};

pub const Search = struct {
    index: usize,
    found_objects: []pkcs.CK_OBJECT_HANDLE,
};

pub const Operation = union(enum) {
    none: None,
    digest: Digest,
    sign: Sign,
    verify: Verify,
    search: Search,

    pub fn deinit(self: *Operation, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .none => {},
            .digest => self.digest.hasher.destroy(allocator),
            .sign => {
                if (self.sign.hasher != null)
                    self.sign.hasher.?.destroy(allocator);
            },
            .verify => {
                if (self.verify.hasher != null)
                    self.verify.hasher.?.destroy(allocator);
            },
            .search => allocator.free(self.search.found_objects),
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
    std.mem.copyForwards(u8, request[data_start_index..rsa_request_size], payload);

    return request;
}

fn createHashedSignRequest(hash: *hasher.Hasher, allocator: std.mem.Allocator) PkcsError![]u8 {
    const prefix = getPrefixFromHasher(hash);

    const payload = hash.finalize(allocator) catch
        return PkcsError.HostMemory;
    defer allocator.free(payload);

    var request = allocator.alloc(u8, prefix.len + payload.len) catch
        return PkcsError.HostMemory;

    std.mem.copyForwards(u8, request[0..prefix.len], prefix);
    std.mem.copyForwards(u8, request[prefix.len..request.len], payload);

    return request;
}

fn getPrefixFromHasher(hash: *hasher.Hasher) []const u8 {
    return switch (hash.*.hasherType.?) {
        .md5 => md5_prefix[0..md5_prefix.len],
        .sha1 => sha1_prefix[0..sha1_prefix.len],
        .sha256 => sha256_prefix[0..sha256_prefix.len],
        .sha384 => sha384_prefix[0..sha384_prefix.len],
        .sha512 => sha521_prefix[0..sha521_prefix.len],
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
