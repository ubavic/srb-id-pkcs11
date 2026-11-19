const std = @import("std");

const PkcsError = @import("../pkcs_error.zig").PkcsError;

const MetaFile = @This();

class: u8,
file_name: [2]u8,
label: ?[]const u8,
id: [20]u8,

pub fn parse(buffer: []const u8) !MetaFile {
    if (buffer.len < 4)
        return error.GeneralError;

    const class = buffer[0];
    if (class == 0 or class > 3)
        return error.GeneralError;

    const file_name = [2]u8{ buffer[1], buffer[2] };

    var position: usize = 3;
    var label: ?[]const u8 = null;

    const label_length = buffer[position];
    position += 1;

    if (label_length > 0) {
        if (position + label_length > buffer.len)
            return error.GeneralError;

        label = buffer[position .. position + label_length];

        position += label_length;
    }

    if (position >= buffer.len)
        return error.GeneralError;

    const id_length = buffer[position];
    position += 1;

    if (id_length != 20)
        return error.GeneralError;

    if (position + id_length > buffer.len)
        return error.GeneralError;

    var id: [20]u8 = std.mem.zeroes([20]u8);
    @memcpy(&id, buffer[position .. position + id_length]);

    return .{
        .class = class,
        .file_name = file_name,
        .label = label,
        .id = id,
    };
}
