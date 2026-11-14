const std = @import("std");

const session = @import("session.zig");

test "operation assertion" {
    var s = session.Session{
        .allocator = std.testing.allocator,
        .card = undefined,
        .id = 1,
        .objects = &.{},
        .reader_id = 1,
        .closed = false,
        .write_enabled = true,
        .operation = .{ .sign = .{
            .hasher = null,
            .key_size = 1024,
            .private_key = 8,
            .multipart_operation = false,
            .msg_buffer = null,
            .sign_type = .RawRsa,
        } },
    };

    const op = try s.assertOperation(.sign);
    try std.testing.expectEqual(&s.operation.sign, op);

    try std.testing.expectError(error.OperationNotInitialized, s.assertOperation(.digest));
}
