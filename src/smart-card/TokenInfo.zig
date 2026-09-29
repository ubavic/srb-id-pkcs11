const std = @import("std");

const TokenInfo = @This();

token_label: [32]u8 = [_]u8{0x20} ** 32,
token_serial_number: [16]u8 = [_]u8{0x20} ** 16,

pub fn parse(data: []const u8) TokenInfo {
    var token_info = TokenInfo{};

    if (data.len <= 48)
        return token_info;

    @memcpy(&token_info.token_label, data[0..32]);

    var pos: usize = 0;
    for (32..48) |i| {
        if (data[i] == 0x00)
            break;

        token_info.token_serial_number[pos] = data[i];

        pos += 1;
    }

    return token_info;
}

test "parse token info" {
    const test_cases = [_]struct {
        data: []const u8,
        expected: TokenInfo,
    }{
        .{
            .data = &.{},
            .expected = TokenInfo{},
        },
        .{
            .data = &.{0x10},
            .expected = TokenInfo{},
        },
        .{
            .data = &([_]u8{0x10} ** 48),
            .expected = TokenInfo{},
        },
        .{
            .data = &([_]u8{0x20} ** 49),
            .expected = TokenInfo{
                .token_label = [_]u8{0x20} ** 32,
                .token_serial_number = [_]u8{0x20} ** 16,
            },
        },
        .{
            .data = &[_]u8{
                0x4E, 0x65, 0x74, 0x53, 0x65, 0x54, 0x27, 0x73,
                0x20, 0x43, 0x61, 0x72, 0x64, 0x45, 0x64, 0x67,
                0x65, 0x20, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x20,
                0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
                0x49, 0x44, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
                0x37, 0x38, 0x39, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x90, 0x00,
            },
            .expected = TokenInfo{
                .token_label = [_]u8{
                    0x4E, 0x65, 0x74, 0x53, 0x65, 0x54, 0x27, 0x73,
                    0x20, 0x43, 0x61, 0x72, 0x64, 0x45, 0x64, 0x67,
                    0x65, 0x20, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x20,
                    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
                },
                .token_serial_number = [_]u8{
                    0x49, 0x44, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
                    0x37, 0x38, 0x39, 0x20, 0x20, 0x20, 0x20, 0x20,
                },
            },
        },
    };

    for (test_cases) |tc| {
        const parsed_token_info = parse(tc.data);
        try std.testing.expectEqualSlices(u8, &tc.expected.token_label, &parsed_token_info.token_label);
        try std.testing.expectEqualSlices(u8, &tc.expected.token_serial_number, &parsed_token_info.token_serial_number);
    }
}
