const std = @import("std");

const PkcsError = @import("../pkcs_error.zig").PkcsError;

const Index = @This();

buffer: []const u8,
length: u16,
i: usize,

pub fn init(buffer: []const u8) !Index {
    if (buffer.len < 2)
        return error.GeneralError;

    const length = std.mem.readInt(u16, buffer[0..2], .little);

    if (2 * @as(usize, length) > buffer.len - 2)
        return error.GeneralError;

    return .{
        .buffer = buffer,
        .length = length,
        .i = 0,
    };
}

pub fn next(self: *Index) ?[2]u8 {
    if (self.i >= self.length)
        return null;

    const position = 2 + 2 * self.i;
    self.i += 1;

    return [2]u8{ self.buffer[position + 1], self.buffer[position] };
}

pub fn deinit(self: *Index, allocator: std.mem.Allocator) void {
    allocator.free(self.buffer);
}
