const std = @import("std");

inline fn rotl32(x: u32, n: u5) u32 {
    return std.math.rotl(u32, x, n);
}

inline fn F1(x: u32, y: u32, z: u32) u32 {
    return x ^ y ^ z;
}

inline fn F2(x: u32, y: u32, z: u32) u32 {
    return (((y ^ z) & x) ^ z);
}

inline fn F3(x: u32, y: u32, z: u32) u32 {
    return ((x | ~y) ^ z);
}

inline fn F4(x: u32, y: u32, z: u32) u32 {
    return (((x ^ y) & z) ^ y);
}

inline fn F5(x: u32, y: u32, z: u32) u32 {
    return (x ^ (y | ~z));
}

inline fn rmdFunc(comptime func: anytype, a: *u32, b: u32, c: *u32, d: u32, e: u32, x: u32, s: u5, k: u32) void {
    a.* +%= func(b, c.*, d);
    a.* +%= x;
    a.* +%= k;

    a.* = rotl32(a.*, s) +% e;
    c.* = rotl32(c.*, 10);
}

inline fn L1(A: *u32, B: u32, C: *u32, D: u32, E: u32, X: u32, S: u5) void {
    rmdFunc(F1, A, B, C, D, E, X, S, 0);
}

inline fn L2(A: *u32, B: u32, C: *u32, D: u32, E: u32, X: u32, S: u5) void {
    rmdFunc(F2, A, B, C, D, E, X, S, 0x5a827999);
}

inline fn L3(A: *u32, B: u32, C: *u32, D: u32, E: u32, X: u32, S: u5) void {
    rmdFunc(F3, A, B, C, D, E, X, S, 0x6ed9eba1);
}

inline fn L4(A: *u32, B: u32, C: *u32, D: u32, E: u32, X: u32, S: u5) void {
    rmdFunc(F4, A, B, C, D, E, X, S, 0x8f1bbcdc);
}

inline fn L5(A: *u32, B: u32, C: *u32, D: u32, E: u32, X: u32, S: u5) void {
    rmdFunc(F5, A, B, C, D, E, X, S, 0xa953fd4e);
}

inline fn R1(A: *u32, B: u32, C: *u32, D: u32, E: u32, X: u32, S: u5) void {
    rmdFunc(F5, A, B, C, D, E, X, S, 0x50a28be6);
}

inline fn R2(A: *u32, B: u32, C: *u32, D: u32, E: u32, X: u32, S: u5) void {
    rmdFunc(F4, A, B, C, D, E, X, S, 0x5c4dd124);
}

inline fn R3(A: *u32, B: u32, C: *u32, D: u32, E: u32, X: u32, S: u5) void {
    rmdFunc(F3, A, B, C, D, E, X, S, 0x6d703ef3);
}

inline fn R4(A: *u32, B: u32, C: *u32, D: u32, E: u32, X: u32, S: u5) void {
    rmdFunc(F2, A, B, C, D, E, X, S, 0x7a6d76e9);
}

inline fn R5(A: *u32, B: u32, C: *u32, D: u32, E: u32, X: u32, S: u5) void {
    rmdFunc(F1, A, B, C, D, E, X, S, 0);
}

pub const block_length = 64;
pub const digest_length = 20;

message: [block_length / 4]u32,
length: u64,
hash: [5]u32,

pub fn init() @This() {
    return @This(){
        .length = 0,
        .message = std.mem.zeroes([block_length / 4]u32),
        .hash = [5]u32{ 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0 },
    };
}

pub fn update(self: *@This(), msg: []const u8) void {
    var input = msg;
    var block_buffer: [block_length / 4]u32 = undefined;

    const index: usize = @intCast(self.length & 63);
    self.length += input.len;

    if (index != 0) {
        const left = block_length - index;
        const take = @min(left, input.len);

        @memcpy(@as([*]u8, @ptrCast(&self.message)) + index, input[0..take]);

        if (input.len < left)
            return;

        @memcpy(&block_buffer, self.message[0 .. block_length / 4]);
        self.round(block_buffer);

        input = input[take..];
    }

    while (input.len >= block_length) {
        @memcpy(std.mem.asBytes(&block_buffer), input[0..block_length]);
        self.round(block_buffer);
        input = input[block_length..];
    }

    if (input.len != 0)
        @memcpy(@as([*]u8, @ptrCast(&self.message)), input);
}

pub fn final(self: *@This(), out: *[digest_length]u8) void {
    var index: usize = @intCast((self.length & 63) >> 2);
    const shift: u5 = @intCast((self.length & 3) * 8);

    self.message[index] &= ~(@as(u32, 0xffffffff) << shift);
    self.message[index] ^= (@as(u32, 0x80) << shift);

    index += 1;

    if (index > 14) {
        while (index < 16) : (index += 1) {
            self.message[index] = 0;
        }

        self.round(self.message);
        index = 0;
    }

    while (index < 14) : (index += 1)
        self.message[index] = 0;

    self.message[14] = @truncate(self.length << 3);
    self.message[15] = @truncate(self.length >> 29);

    self.round(self.message);

    const hash_bytes = std.mem.asBytes(&self.hash);

    @memcpy(out, hash_bytes[0..digest_length]);
}

fn round(self: *@This(), X: [16]u32) void {
    var A = self.hash[0];
    var B = self.hash[1];
    var C = self.hash[2];
    var D = self.hash[3];
    var E = self.hash[4];

    var a1 = self.hash[0];
    var b1 = self.hash[1];
    var c1 = self.hash[2];
    var d1 = self.hash[3];
    var e1 = self.hash[4];

    L1(&a1, b1, &c1, d1, e1, X[0], 11);
    R1(&A, B, &C, D, E, X[5], 8);
    L1(&e1, a1, &b1, c1, d1, X[1], 14);
    R1(&E, A, &B, C, D, X[14], 9);
    L1(&d1, e1, &a1, b1, c1, X[2], 15);
    R1(&D, E, &A, B, C, X[7], 9);
    L1(&c1, d1, &e1, a1, b1, X[3], 12);
    R1(&C, D, &E, A, B, X[0], 11);
    L1(&b1, c1, &d1, e1, a1, X[4], 5);
    R1(&B, C, &D, E, A, X[9], 13);
    L1(&a1, b1, &c1, d1, e1, X[5], 8);
    R1(&A, B, &C, D, E, X[2], 15);
    L1(&e1, a1, &b1, c1, d1, X[6], 7);
    R1(&E, A, &B, C, D, X[11], 15);
    L1(&d1, e1, &a1, b1, c1, X[7], 9);
    R1(&D, E, &A, B, C, X[4], 5);
    L1(&c1, d1, &e1, a1, b1, X[8], 11);
    R1(&C, D, &E, A, B, X[13], 7);
    L1(&b1, c1, &d1, e1, a1, X[9], 13);
    R1(&B, C, &D, E, A, X[6], 7);
    L1(&a1, b1, &c1, d1, e1, X[10], 14);
    R1(&A, B, &C, D, E, X[15], 8);
    L1(&e1, a1, &b1, c1, d1, X[11], 15);
    R1(&E, A, &B, C, D, X[8], 11);
    L1(&d1, e1, &a1, b1, c1, X[12], 6);
    R1(&D, E, &A, B, C, X[1], 14);
    L1(&c1, d1, &e1, a1, b1, X[13], 7);
    R1(&C, D, &E, A, B, X[10], 14);
    L1(&b1, c1, &d1, e1, a1, X[14], 9);
    R1(&B, C, &D, E, A, X[3], 12);
    L1(&a1, b1, &c1, d1, e1, X[15], 8);
    R1(&A, B, &C, D, E, X[12], 6);
    L2(&e1, a1, &b1, c1, d1, X[7], 7);
    R2(&E, A, &B, C, D, X[6], 9);
    L2(&d1, e1, &a1, b1, c1, X[4], 6);
    R2(&D, E, &A, B, C, X[11], 13);
    L2(&c1, d1, &e1, a1, b1, X[13], 8);
    R2(&C, D, &E, A, B, X[3], 15);
    L2(&b1, c1, &d1, e1, a1, X[1], 13);
    R2(&B, C, &D, E, A, X[7], 7);
    L2(&a1, b1, &c1, d1, e1, X[10], 11);
    R2(&A, B, &C, D, E, X[0], 12);
    L2(&e1, a1, &b1, c1, d1, X[6], 9);
    R2(&E, A, &B, C, D, X[13], 8);
    L2(&d1, e1, &a1, b1, c1, X[15], 7);
    R2(&D, E, &A, B, C, X[5], 9);
    L2(&c1, d1, &e1, a1, b1, X[3], 15);
    R2(&C, D, &E, A, B, X[10], 11);
    L2(&b1, c1, &d1, e1, a1, X[12], 7);
    R2(&B, C, &D, E, A, X[14], 7);
    L2(&a1, b1, &c1, d1, e1, X[0], 12);
    R2(&A, B, &C, D, E, X[15], 7);
    L2(&e1, a1, &b1, c1, d1, X[9], 15);
    R2(&E, A, &B, C, D, X[8], 12);
    L2(&d1, e1, &a1, b1, c1, X[5], 9);
    R2(&D, E, &A, B, C, X[12], 7);
    L2(&c1, d1, &e1, a1, b1, X[2], 11);
    R2(&C, D, &E, A, B, X[4], 6);
    L2(&b1, c1, &d1, e1, a1, X[14], 7);
    R2(&B, C, &D, E, A, X[9], 15);
    L2(&a1, b1, &c1, d1, e1, X[11], 13);
    R2(&A, B, &C, D, E, X[1], 13);
    L2(&e1, a1, &b1, c1, d1, X[8], 12);
    R2(&E, A, &B, C, D, X[2], 11);
    L3(&d1, e1, &a1, b1, c1, X[3], 11);
    R3(&D, E, &A, B, C, X[15], 9);
    L3(&c1, d1, &e1, a1, b1, X[10], 13);
    R3(&C, D, &E, A, B, X[5], 7);
    L3(&b1, c1, &d1, e1, a1, X[14], 6);
    R3(&B, C, &D, E, A, X[1], 15);
    L3(&a1, b1, &c1, d1, e1, X[4], 7);
    R3(&A, B, &C, D, E, X[3], 11);
    L3(&e1, a1, &b1, c1, d1, X[9], 14);
    R3(&E, A, &B, C, D, X[7], 8);
    L3(&d1, e1, &a1, b1, c1, X[15], 9);
    R3(&D, E, &A, B, C, X[14], 6);
    L3(&c1, d1, &e1, a1, b1, X[8], 13);
    R3(&C, D, &E, A, B, X[6], 6);
    L3(&b1, c1, &d1, e1, a1, X[1], 15);
    R3(&B, C, &D, E, A, X[9], 14);
    L3(&a1, b1, &c1, d1, e1, X[2], 14);
    R3(&A, B, &C, D, E, X[11], 12);
    L3(&e1, a1, &b1, c1, d1, X[7], 8);
    R3(&E, A, &B, C, D, X[8], 13);
    L3(&d1, e1, &a1, b1, c1, X[0], 13);
    R3(&D, E, &A, B, C, X[12], 5);
    L3(&c1, d1, &e1, a1, b1, X[6], 6);
    R3(&C, D, &E, A, B, X[2], 14);
    L3(&b1, c1, &d1, e1, a1, X[13], 5);
    R3(&B, C, &D, E, A, X[10], 13);
    L3(&a1, b1, &c1, d1, e1, X[11], 12);
    R3(&A, B, &C, D, E, X[0], 13);
    L3(&e1, a1, &b1, c1, d1, X[5], 7);
    R3(&E, A, &B, C, D, X[4], 7);
    L3(&d1, e1, &a1, b1, c1, X[12], 5);
    R3(&D, E, &A, B, C, X[13], 5);
    L4(&c1, d1, &e1, a1, b1, X[1], 11);
    R4(&C, D, &E, A, B, X[8], 15);
    L4(&b1, c1, &d1, e1, a1, X[9], 12);
    R4(&B, C, &D, E, A, X[6], 5);
    L4(&a1, b1, &c1, d1, e1, X[11], 14);
    R4(&A, B, &C, D, E, X[4], 8);
    L4(&e1, a1, &b1, c1, d1, X[10], 15);
    R4(&E, A, &B, C, D, X[1], 11);
    L4(&d1, e1, &a1, b1, c1, X[0], 14);
    R4(&D, E, &A, B, C, X[3], 14);
    L4(&c1, d1, &e1, a1, b1, X[8], 15);
    R4(&C, D, &E, A, B, X[11], 14);
    L4(&b1, c1, &d1, e1, a1, X[12], 9);
    R4(&B, C, &D, E, A, X[15], 6);
    L4(&a1, b1, &c1, d1, e1, X[4], 8);
    R4(&A, B, &C, D, E, X[0], 14);
    L4(&e1, a1, &b1, c1, d1, X[13], 9);
    R4(&E, A, &B, C, D, X[5], 6);
    L4(&d1, e1, &a1, b1, c1, X[3], 14);
    R4(&D, E, &A, B, C, X[12], 9);
    L4(&c1, d1, &e1, a1, b1, X[7], 5);
    R4(&C, D, &E, A, B, X[2], 12);
    L4(&b1, c1, &d1, e1, a1, X[15], 6);
    R4(&B, C, &D, E, A, X[13], 9);
    L4(&a1, b1, &c1, d1, e1, X[14], 8);
    R4(&A, B, &C, D, E, X[9], 12);
    L4(&e1, a1, &b1, c1, d1, X[5], 6);
    R4(&E, A, &B, C, D, X[7], 5);
    L4(&d1, e1, &a1, b1, c1, X[6], 5);
    R4(&D, E, &A, B, C, X[10], 15);
    L4(&c1, d1, &e1, a1, b1, X[2], 12);
    R4(&C, D, &E, A, B, X[14], 8);
    L5(&b1, c1, &d1, e1, a1, X[4], 9);
    R5(&B, C, &D, E, A, X[12], 8);
    L5(&a1, b1, &c1, d1, e1, X[0], 15);
    R5(&A, B, &C, D, E, X[15], 5);
    L5(&e1, a1, &b1, c1, d1, X[5], 5);
    R5(&E, A, &B, C, D, X[10], 12);
    L5(&d1, e1, &a1, b1, c1, X[9], 11);
    R5(&D, E, &A, B, C, X[4], 9);
    L5(&c1, d1, &e1, a1, b1, X[7], 6);
    R5(&C, D, &E, A, B, X[1], 12);
    L5(&b1, c1, &d1, e1, a1, X[12], 8);
    R5(&B, C, &D, E, A, X[5], 5);
    L5(&a1, b1, &c1, d1, e1, X[2], 13);
    R5(&A, B, &C, D, E, X[8], 14);
    L5(&e1, a1, &b1, c1, d1, X[10], 12);
    R5(&E, A, &B, C, D, X[7], 6);
    L5(&d1, e1, &a1, b1, c1, X[14], 5);
    R5(&D, E, &A, B, C, X[6], 8);
    L5(&c1, d1, &e1, a1, b1, X[1], 12);
    R5(&C, D, &E, A, B, X[2], 13);
    L5(&b1, c1, &d1, e1, a1, X[3], 13);
    R5(&B, C, &D, E, A, X[13], 6);
    L5(&a1, b1, &c1, d1, e1, X[8], 14);
    R5(&A, B, &C, D, E, X[14], 5);
    L5(&e1, a1, &b1, c1, d1, X[11], 11);
    R5(&E, A, &B, C, D, X[0], 15);
    L5(&d1, e1, &a1, b1, c1, X[6], 8);
    R5(&D, E, &A, B, C, X[3], 13);
    L5(&c1, d1, &e1, a1, b1, X[15], 5);
    R5(&C, D, &E, A, B, X[9], 11);
    L5(&b1, c1, &d1, e1, a1, X[13], 6);
    R5(&B, C, &D, E, A, X[11], 11);

    D +%= c1 +% self.hash[1];
    self.hash[1] = self.hash[2] +% d1 +% E;
    self.hash[2] = self.hash[3] +% e1 +% A;
    self.hash[3] = self.hash[4] +% a1 +% B;
    self.hash[4] = self.hash[0] +% b1 +% C;
    self.hash[0] = D;
}

test "RIPEMD160" {
    const MdTest = struct {
        expected: []const u8,
        input: []const u8,
    };

    const vectors = [_]MdTest{
        .{
            .input = "",
            .expected = "9c1185a5c5e9fc54612808977ee8f548b2258d31",
        },
        .{
            .input = "a",
            .expected = "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe",
        },
        .{
            .input = "abc",
            .expected = "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc",
        },
        .{
            .input = "message digest",
            .expected = "5d0689ef49d2fae572b881b123a85ffa21595f36",
        },
        .{
            .input = "abcdefghijklmnopqrstuvwxyz",
            .expected = "f71c27109c692c1b56bbdceb5b9d2865b3708dbc",
        },
        .{
            .input = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            .expected = "12a053384a9c0c88e405a06c27dcf49ada62eb2b",
        },
        .{
            .input = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            .expected = "b0e20b6e3116640286ed3a87a5713079b21f5189",
        },
        .{
            .input = "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
            .expected = "9b752e45573d4b39f4dbd3323cab82bf63326bfb",
        },
    };

    var expected_buffer: [digest_length]u8 = std.mem.zeroes([digest_length]u8);
    var result_buffer: [digest_length]u8 = std.mem.zeroes([digest_length]u8);

    for (vectors) |tv| {
        const expected = try std.fmt.hexToBytes(&expected_buffer, tv.expected);

        var hasher = @This().init();
        hasher.update(tv.input);
        hasher.final(&result_buffer);

        try std.testing.expectEqualSlices(u8, expected, &result_buffer);
    }

    for (vectors) |tv| {
        const first_part_len = tv.input.len / 2;

        const expected = try std.fmt.hexToBytes(&expected_buffer, tv.expected);

        var hasher = @This().init();
        hasher.update(tv.input[0..first_part_len]);
        hasher.update(tv.input[first_part_len..]);
        hasher.final(&result_buffer);

        try std.testing.expectEqualSlices(u8, expected, &result_buffer);
    }

    for (vectors) |tv| {
        if (tv.input.len < 1)
            continue;

        const expected = try std.fmt.hexToBytes(&expected_buffer, tv.expected);

        var hasher = @This().init();
        hasher.update(tv.input[1..]);
        hasher.final(&result_buffer);

        try std.testing.expect(!std.mem.eql(u8, expected, &result_buffer));
    }
}

test "RIPEMD160 mililion" {
    var hasher = @This().init();

    const data: [10]u8 = [_]u8{'a'} ** 10;
    for (0..100000) |_|
        hasher.update(&data);

    var result_buffer: [digest_length]u8 = std.mem.zeroes([digest_length]u8);
    hasher.final(&result_buffer);

    var out_buffer: [digest_length]u8 = std.mem.zeroes([digest_length]u8);
    const out = try std.fmt.hexToBytes(&out_buffer, "52783243c1697bdbe16d37f97f68f08325dc1528");

    try std.testing.expectEqualSlices(u8, out, &result_buffer);
}
