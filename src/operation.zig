const std = @import("std");

const pkcs = @cImport({
    @cInclude("pkcs.h");
});

const hasher = @import("hasher.zig");

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

    pub fn signatureSize(self: *const Sign) usize {
        _ = self;
        unreachable;
    }

    pub fn update(self: *Sign, data: []const u8) void {
        _ = self;
        _ = data;
        unreachable;
    }

    pub fn finalize(self: *Sign) std.mem.Allocator.Error![]u8 {
        _ = self;
        unreachable;
    }
};

pub const Verify = struct {
    private_key: pkcs.CK_OBJECT_HANDLE,
    multipart_operation: bool,
    hasher: ?hasher.Hasher,

    pub fn signatureSize(self: *const Verify) usize {
        _ = self;
        unreachable;
    }

    pub fn update(self: *Verify, data: []const u8) void {
        _ = self;
        _ = data;
        unreachable;
    }

    pub fn finalize(self: *Verify) std.mem.Allocator.Error![]u8 {
        _ = self;
        unreachable;
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

    pub fn deinit(_: *Operation) void {
        unreachable;
    }
};
