const std = @import("std");

const object = @import("../object.zig");
const pkcs = @import("../../pkcs.zig");

test "parse certificate" {
    const ta = std.testing.allocator;
    const tio = std.testing.io;

    const test_data = [_]struct {
        file_name: []const u8,
        serial_number: []const u8,
        modulus: []const u8,
    }{
        .{
            .file_name = "testdata/1024.der",
            .serial_number = &[_]u8{
                0x02, 0x14, 0x1f, 0xe7, 0xb0, 0x8b, 0x5d, 0xb4,
                0x90, 0xf7, 0x5e, 0xa0, 0xc1, 0xc5, 0xf0, 0x08,
                0x54, 0xba, 0xd7, 0xa1, 0x80, 0x7d,
            },
            .modulus = &[_]u8{
                0xa2, 0xc8, 0xa7, 0x03, 0xb0, 0x78, 0xd7, 0xcd,
                0x91, 0x6f, 0x4e, 0x93, 0x80, 0x34, 0xad, 0xa4,
                0x80, 0xb0, 0xe0, 0x88, 0x17, 0xa4, 0xa0, 0x3e,
                0x49, 0x5b, 0x20, 0x09, 0x1f, 0x85, 0xc2, 0xd3,
                0xdd, 0xc9, 0x5c, 0x04, 0x92, 0x15, 0xd5, 0xdb,
                0xbf, 0x22, 0x9a, 0x74, 0x67, 0x0b, 0x0f, 0x32,
                0xa3, 0x6a, 0x01, 0x7d, 0xce, 0x1a, 0x3e, 0x36,
                0x50, 0xf0, 0x9f, 0x15, 0xaf, 0x37, 0x12, 0x28,
                0xba, 0x68, 0xc6, 0x2b, 0xda, 0x56, 0x35, 0x6f,
                0x22, 0xc6, 0x28, 0x90, 0x33, 0xe4, 0x39, 0x4b,
                0xca, 0x9a, 0xff, 0xe0, 0xeb, 0x22, 0x28, 0xbb,
                0x5a, 0x11, 0x86, 0x0f, 0x46, 0x81, 0x9c, 0x23,
                0xa0, 0x35, 0x69, 0x17, 0x9a, 0x1f, 0xcb, 0x85,
                0x36, 0x7c, 0x82, 0x57, 0xc5, 0xa2, 0xc1, 0x56,
                0x63, 0xfc, 0xa2, 0x9d, 0x06, 0x1d, 0xd3, 0xa4,
                0x26, 0x68, 0xcb, 0xb4, 0x50, 0x0a, 0x60, 0x23,
            },
        },
        .{
            .file_name = "testdata/2048.der",
            .serial_number = &[_]u8{
                0x02, 0x14, 0x3b, 0x7a, 0x59, 0x6a, 0xe8, 0x89,
                0xbc, 0x22, 0xfa, 0xf9, 0x4c, 0x27, 0x01, 0xab,
                0x70, 0x45, 0x80, 0xbd, 0x02, 0xc4,
            },
            .modulus = &[_]u8{
                0xb9, 0x0a, 0x72, 0xdb, 0x65, 0x9e, 0xc4, 0x71,
                0x1b, 0x34, 0xbb, 0xa3, 0x71, 0xf9, 0xc5, 0x28,
                0x7f, 0xdf, 0x60, 0x58, 0x19, 0xd0, 0x29, 0xf1,
                0xdb, 0xb4, 0x59, 0xe6, 0x1b, 0x84, 0x6f, 0x7c,
                0x28, 0xa1, 0x68, 0xcf, 0x9d, 0x6b, 0xfe, 0x9e,
                0xc8, 0xb6, 0xe2, 0xd1, 0xcc, 0xa6, 0xf9, 0x40,
                0xa3, 0x86, 0x07, 0x28, 0xc6, 0x1e, 0x19, 0xa7,
                0x59, 0x50, 0x67, 0xcb, 0x99, 0x07, 0x59, 0x41,
                0xf0, 0x3d, 0xf7, 0x49, 0x8a, 0xa1, 0x16, 0x99,
                0x6c, 0x03, 0x73, 0x32, 0x77, 0x03, 0xc0, 0xc8,
                0x68, 0xd0, 0x9f, 0xc0, 0x05, 0x6a, 0x10, 0x5f,
                0x47, 0xaa, 0xa6, 0xd5, 0xf1, 0x0d, 0x87, 0x29,
                0x22, 0xa3, 0xfc, 0x93, 0x0b, 0x5f, 0x83, 0x2f,
                0x31, 0x6b, 0x44, 0x7d, 0x68, 0xf8, 0x70, 0x2c,
                0x8c, 0xeb, 0xe0, 0x07, 0xa0, 0x6e, 0xf3, 0x27,
                0xff, 0x56, 0x94, 0x66, 0x77, 0x53, 0x92, 0x5c,
                0x6a, 0xe9, 0xe9, 0xb3, 0xc9, 0x42, 0xa5, 0xc8,
                0x3b, 0xd3, 0x08, 0xbd, 0x01, 0x70, 0x15, 0xdb,
                0xef, 0x62, 0xe0, 0x1d, 0x85, 0xcf, 0x3a, 0xcd,
                0xca, 0x65, 0x14, 0xf9, 0x9e, 0x7e, 0xf7, 0x04,
                0x4b, 0x0b, 0xed, 0x63, 0x2c, 0xc6, 0x86, 0x5c,
                0x40, 0x7d, 0x8e, 0xbd, 0xda, 0xf7, 0x49, 0x7b,
                0xa0, 0xc0, 0x49, 0x02, 0xbc, 0x73, 0x53, 0xbf,
                0xf7, 0x58, 0x23, 0xc7, 0x67, 0x40, 0x04, 0xbd,
                0x30, 0xba, 0x72, 0x5f, 0x2c, 0xe6, 0x49, 0xf3,
                0x75, 0x28, 0xe5, 0x5a, 0xe3, 0xcf, 0x49, 0xf5,
                0xe2, 0x16, 0x10, 0xfe, 0x22, 0x2a, 0x09, 0xbb,
                0x7c, 0x93, 0xcb, 0x35, 0x08, 0x92, 0x21, 0x9c,
                0x2b, 0x25, 0xee, 0xe8, 0x58, 0x93, 0xbd, 0xbf,
                0x6c, 0xfb, 0x5a, 0xf9, 0xc1, 0x60, 0x22, 0x91,
                0x2b, 0x20, 0x19, 0x5f, 0x89, 0xee, 0xa2, 0xfd,
                0xfc, 0x60, 0x38, 0x3e, 0xa2, 0x4c, 0x6f, 0x23,
            },
        },
    };

    const id = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
    const label: []const u8 = "Test Cert";
    const file_name = [2]u8{ 0x01, 0x02 };

    for (test_data, 0..) |td, i| {
        const der = try std.Io.Dir.readFileAlloc(std.Io.Dir.cwd(), tio, td.file_name, ta, .unlimited);
        defer ta.free(der);

        var certificate_object = try object.CertificateObject.parse(ta, @intCast(0x8000 + i), der, id, file_name, 1234);
        defer certificate_object.deinit(ta);

        try std.testing.expectEqual(1234, certificate_object.size);
        try std.testing.expectEqual(0x8000 + i, certificate_object.handle);
        try std.testing.expectEqualSlices(u8, td.serial_number, certificate_object.serial_number);
        try std.testing.expectEqualSlices(u8, &id, &certificate_object.id);
        try std.testing.expectEqualSlices(u8, label, certificate_object.label);
        try std.testing.expectEqualSlices(u8, &file_name, &certificate_object.file_name);
    }
}

test "encoding scalars" {
    var buffer = std.mem.zeroes([16]u8);

    const bool_value: pkcs.CK_BBOOL = pkcs.CK_TRUE;
    const bool_value_slice = try object.encode(&buffer, bool_value);
    try std.testing.expectEqualSlices(u8, std.mem.asBytes(&bool_value), bool_value_slice);

    const class_value: pkcs.CK_OBJECT_CLASS = pkcs.CKO_CERTIFICATE;
    const class_value_slice = try object.encode(&buffer, class_value);
    try std.testing.expectEqualSlices(u8, std.mem.asBytes(&class_value), class_value_slice);
}

test "encoding zero length arrays" {
    var buffer = std.mem.zeroes([0]u8);

    const zero_array = [0]u8{};
    const zero_array_value_slice = try object.encode(&buffer, zero_array);
    try std.testing.expectEqualSlices(u8, std.mem.asBytes(&zero_array), zero_array_value_slice);

    const zero_slice_value = try object.encode(&buffer, @as([]const u8, &zero_array));
    try std.testing.expectEqualSlices(u8, std.mem.asBytes(&zero_array), zero_slice_value);

    const mechanism_array = [0]pkcs.CK_MECHANISM_TYPE{};
    const mechanism_array_value = try object.encode(&buffer, &mechanism_array);
    try std.testing.expectEqualSlices(u8, std.mem.asBytes(&mechanism_array), mechanism_array_value);

    const mechanism_slice_value = try object.encode(&buffer, @as([]const pkcs.CK_MECHANISM_TYPE, &mechanism_array));
    try std.testing.expectEqualSlices(u8, std.mem.asBytes(&mechanism_array), mechanism_slice_value);
}

test "encoding arrays" {
    var buffer = std.mem.zeroes([16]u8);

    const byte_array = [_]u8{ 1, 2, 3 };
    const byte_array_value_slice = try object.encode(&buffer, byte_array);
    try std.testing.expectEqualSlices(u8, std.mem.asBytes(&byte_array), byte_array_value_slice);

    const byte_array_pointer_value = try object.encode(&buffer, &byte_array);
    try std.testing.expectEqualSlices(u8, std.mem.asBytes(&byte_array), byte_array_pointer_value);

    const byte_slice_value = try object.encode(&buffer, @as([]const u8, &byte_array));
    try std.testing.expectEqualSlices(u8, std.mem.asBytes(&byte_array), byte_slice_value);

    const mechanism_array = [_]pkcs.CK_MECHANISM_TYPE{ pkcs.CKM_ECDSA, pkcs.CKM_AES_GCM };
    const mechanism_array_value = try object.encode(&buffer, &mechanism_array);
    try std.testing.expectEqualSlices(u8, std.mem.asBytes(&mechanism_array), mechanism_array_value);

    const mechanism_slice_value = try object.encode(&buffer, @as([]const pkcs.CK_MECHANISM_TYPE, &mechanism_array));
    try std.testing.expectEqualSlices(u8, std.mem.asBytes(&mechanism_array), mechanism_slice_value);

    const date_array = [_]pkcs.CK_DATE{
        .{
            .year = .{ '1', '9', '8', '2' },
            .month = .{ '0', '7' },
            .day = .{ '3', '1' },
        },
        .{
            .year = .{ '2', '0', '1', '4' },
            .month = .{ '0', '5' },
            .day = .{ '0', '6' },
        },
    };

    const date_array_value = try object.encode(&buffer, &date_array);
    try std.testing.expectEqualSlices(u8, std.mem.asBytes(&date_array), date_array_value);

    const date_slice_value = try object.encode(&buffer, @as([]const pkcs.CK_DATE, &date_array));
    try std.testing.expectEqualSlices(u8, std.mem.asBytes(&date_array), date_slice_value);
}

test "key object size" {
    const ta = std.testing.allocator;
    const PublicKeyFile = @import("../../smart-card/PublicKeyFile.zig");

    const key_file = PublicKeyFile{
        .id = @splat(0x01),
        .pub_key_file_name = .{ 0x60, 0x04 },
        .priv_key_file_name = .{ 0x60, 0x05 },
        .modulus_len = 1,
        .exponent_len = 1,
    };

    var public_key = object.Object{ .public_key = try .createPublicKeyObject(ta, key_file, 1, 90) };
    defer public_key.deinit(ta);
    try std.testing.expectEqual(90, public_key.size());

    var private_key = object.Object{ .private_key = try .createPrivateKeyObject(ta, key_file, 2, 512) };
    defer private_key.deinit(ta);
    try std.testing.expectEqual(512, private_key.size());
}

test "encoding to small buffer" {
    var buffer = std.mem.zeroes([2]u8);

    const class_value: pkcs.CK_OBJECT_CLASS = pkcs.CKO_CERTIFICATE;
    try std.testing.expectError(error.HostMemory, object.encode(&buffer, class_value));
}
