const std = @import("std");

const Ripemd160 = @import("../Ripemd160.zig");

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

    var expected_buffer: [Ripemd160.digest_length]u8 = std.mem.zeroes([Ripemd160.digest_length]u8);
    var result_buffer: [Ripemd160.digest_length]u8 = std.mem.zeroes([Ripemd160.digest_length]u8);

    for (vectors) |tv| {
        const expected = try std.fmt.hexToBytes(&expected_buffer, tv.expected);

        var hasher = Ripemd160.init();
        hasher.update(tv.input);
        hasher.final(&result_buffer);

        try std.testing.expectEqualSlices(u8, expected, &result_buffer);
    }

    for (vectors) |tv| {
        const first_part_len = tv.input.len / 2;

        const expected = try std.fmt.hexToBytes(&expected_buffer, tv.expected);

        var hasher = Ripemd160.init();
        hasher.update(tv.input[0..first_part_len]);
        hasher.update(tv.input[first_part_len..]);
        hasher.final(&result_buffer);

        try std.testing.expectEqualSlices(u8, expected, &result_buffer);
    }

    for (vectors) |tv| {
        if (tv.input.len < 1)
            continue;

        const expected = try std.fmt.hexToBytes(&expected_buffer, tv.expected);

        var hasher = Ripemd160.init();
        hasher.update(tv.input[1..]);
        hasher.final(&result_buffer);

        try std.testing.expect(!std.mem.eql(u8, expected, &result_buffer));
    }
}

test "RIPEMD160 mililion" {
    var hasher = Ripemd160.init();

    const data: [10]u8 = @splat('a');
    for (0..100000) |_|
        hasher.update(&data);

    var result_buffer: [Ripemd160.digest_length]u8 = std.mem.zeroes([Ripemd160.digest_length]u8);
    hasher.final(&result_buffer);

    var out_buffer: [Ripemd160.digest_length]u8 = std.mem.zeroes([Ripemd160.digest_length]u8);
    const out = try std.fmt.hexToBytes(&out_buffer, "52783243c1697bdbe16d37f97f68f08325dc1528");

    try std.testing.expectEqualSlices(u8, out, &result_buffer);
}
