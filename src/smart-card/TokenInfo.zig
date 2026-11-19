const std = @import("std");

const TokenInfo = @This();

token_label: [32]u8 = @splat(0x20),
token_serial_number: [16]u8 = @splat(0x20),

pub fn parse(data: []const u8) TokenInfo {
    var token_info = TokenInfo{};

    if (data.len < 48)
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
