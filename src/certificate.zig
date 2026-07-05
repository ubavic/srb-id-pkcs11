const std = @import("std");
const Certificate = std.crypto.Certificate;

const object = @import("object.zig");
const pkcs = @import("pkcs.zig");
const pkcs_error = @import("pkcs_error.zig");
const PkcsError = pkcs_error.PkcsError;

pub fn loadObjects(
    allocator: std.mem.Allocator,
    buffer: []const u8,
    certificate_handle: pkcs.CK_OBJECT_HANDLE,
    private_key_handle: pkcs.CK_OBJECT_HANDLE,
    public_key_handle: pkcs.CK_OBJECT_HANDLE,
    id: []const u8,
    alow_encrypt: bool,
) PkcsError![3]object.Object {
    const cert = Certificate{ .buffer = buffer, .index = 0 };

    const parsed = Certificate.parse(cert) catch
        return PkcsError.GeneralError;

    if (parsed.pub_key_algo != .rsaEncryption)
        return PkcsError.GeneralError;

    const public_key_components = Certificate.rsa.PublicKey.parseDer(parsed.pubKey()) catch
        return PkcsError.GeneralError;

    const cert_id = try clone(allocator, id);
    errdefer allocator.free(cert_id);
    const certificate_value = try clone(allocator, buffer);
    errdefer allocator.free(certificate_value);

    const serial_number_slice = extractSerialNumber(buffer) catch return PkcsError.GeneralError;
    const serial_number = try clone(allocator, serial_number_slice);
    errdefer allocator.free(serial_number);

    // empty on the original token
    const certificate_url = try allocEmptySlice(u8, allocator);
    errdefer allocator.free(certificate_url);
    const public_key_hash = try allocEmptySlice(u8, allocator);
    errdefer allocator.free(public_key_hash);
    const check_value = try allocEmptySlice(u8, allocator);
    errdefer allocator.free(check_value);

    // invalid on the original token
    const public_key_info = try allocEmptySlice(u8, allocator);
    errdefer allocator.free(public_key_info);
    const name_hash_algorithm = 0;

    // iffy but it should work
    const subject = try clone(allocator, buffer[parsed.subject_slice.start - 3 .. parsed.subject_slice.end]);
    const issuer = try clone(allocator, buffer[parsed.issuer_slice.start - 3 .. parsed.issuer_slice.end]);

    const label_slice = extractLabel(subject);
    const label = try clone(allocator, label_slice);
    errdefer allocator.free(label);

    const certificate_object: object.CertificateObject = object.CertificateObject{
        .handle = certificate_handle,
        .class = pkcs.CKO_CERTIFICATE,
        .token = pkcs.CK_TRUE,
        .private = pkcs.CK_FALSE,
        .modifiable = pkcs.CK_FALSE,
        .label = label,
        .copyable = pkcs.CK_FALSE,
        .destroyable = pkcs.CK_FALSE,
        .certificate_type = pkcs.CKC_X_509,
        .trusted = pkcs.CK_FALSE,
        .certificate_category = pkcs.CK_CERTIFICATE_CATEGORY_TOKEN_USER,
        .check_value = check_value,
        .start_date = pkcs.CK_DATE{},
        .end_date = pkcs.CK_DATE{},
        .public_key_info = public_key_info,
        .subject = subject,
        .id = cert_id,
        .issuer = issuer,
        .serial_number = serial_number,
        .value = certificate_value,
        .url = certificate_url,
        .hash_of_subject_public_key = public_key_hash,
        .name_hash_algorithm = name_hash_algorithm,
    };

    const priv_id = try clone(allocator, id);
    errdefer allocator.free(priv_id);
    const private_key_label = try allocEmptySlice(u8, allocator);
    errdefer allocator.free(private_key_label);
    const private_key_subject = try allocEmptySlice(u8, allocator);
    errdefer allocator.free(private_key_subject);
    const private_key_modulus = try clone(allocator, public_key_components.modulus);
    errdefer allocator.free(private_key_modulus);
    const priv_key_public_exponent = try clone(allocator, public_key_components.exponent);
    errdefer allocator.free(priv_key_public_exponent);

    // invalid on original token
    const priv_public_key_info = try allocEmptySlice(u8, allocator);
    errdefer allocator.free(priv_public_key_info);
    const private_allowed_mechanisms: []c_ulong = try allocEmptySlice(c_ulong, allocator);
    errdefer allocator.free(private_allowed_mechanisms);
    const unwrap_template: []pkcs.CK_ATTRIBUTE = try allocEmptySlice(pkcs.CK_ATTRIBUTE, allocator);
    errdefer allocator.free(unwrap_template);

    const private_key_object: object.PrivateKeyObject = object.PrivateKeyObject{
        .handle = private_key_handle,
        .class = pkcs.CKO_PRIVATE_KEY,
        .token = pkcs.CK_TRUE,
        .private = pkcs.CK_TRUE,
        .modifiable = pkcs.CK_TRUE,
        .label = private_key_label,
        .copyable = pkcs.CK_FALSE, // invalid on original token
        .destroyable = pkcs.CK_FALSE, // invalid on original token
        .key_type = pkcs.CKK_RSA,
        .id = priv_id,
        .start_date = pkcs.CK_DATE{},
        .end_date = pkcs.CK_DATE{},
        .derive = pkcs.CK_FALSE,
        .local = pkcs.CK_TRUE,
        .key_gen_mechanism = 0, // invalid on original token
        .allowed_mechanisms = private_allowed_mechanisms,
        .subject = private_key_subject,
        .sensitive = pkcs.CK_TRUE,
        .decrypt = if (alow_encrypt) pkcs.CK_TRUE else pkcs.CK_FALSE,
        .sign = pkcs.CK_TRUE,
        .sign_recover = pkcs.CK_FALSE,
        .unwrap = pkcs.CK_FALSE,
        .extractable = pkcs.CK_FALSE,
        .always_sensitive = pkcs.CK_TRUE,
        .never_extractable = pkcs.CK_TRUE,
        .wrap_with_trusted = if (alow_encrypt) pkcs.CK_TRUE else pkcs.CK_FALSE,
        .unwrap_template = unwrap_template,
        .always_authenticate = pkcs.CK_FALSE,
        .public_key_info = priv_public_key_info,
        .modulus = private_key_modulus,
        .public_exponent = priv_key_public_exponent,
    };

    const pub_id = try clone(allocator, id);
    errdefer allocator.free(pub_id);
    const public_key_label = try allocEmptySlice(u8, allocator);
    errdefer allocator.free(public_key_label);
    const public_key_subject = try allocEmptySlice(u8, allocator);
    errdefer allocator.free(public_key_subject);
    const public_key_modulus = try clone(allocator, public_key_components.modulus);
    errdefer allocator.free(public_key_modulus);
    const pub_public_exponent = try clone(allocator, public_key_components.exponent);
    errdefer allocator.free(pub_public_exponent);

    // invalid on original token
    const pub_public_key_info = try allocEmptySlice(u8, allocator);
    errdefer allocator.free(pub_public_key_info);
    const public_allowed_mechanisms: []c_ulong = try allocEmptySlice(c_ulong, allocator);
    errdefer allocator.free(public_allowed_mechanisms);
    const wrap_template: []pkcs.CK_ATTRIBUTE = try allocEmptySlice(pkcs.CK_ATTRIBUTE, allocator);
    errdefer allocator.free(wrap_template);

    const public_key_object: object.PublicKeyObject = object.PublicKeyObject{
        .handle = public_key_handle,
        .class = pkcs.CKO_PUBLIC_KEY,
        .token = pkcs.CK_TRUE,
        .private = pkcs.CK_FALSE,
        .modifiable = pkcs.CK_TRUE,
        .label = public_key_label,
        .copyable = pkcs.CK_FALSE, // invalid on original token
        .destroyable = pkcs.CK_FALSE, // invalid on original token
        .key_type = pkcs.CKK_RSA,
        .id = pub_id,
        .start_date = pkcs.CK_DATE{},
        .end_date = pkcs.CK_DATE{},
        .derive = pkcs.CK_FALSE,
        .local = pkcs.CK_TRUE,
        .key_gen_mechanism = 0, // invalid on original token
        .allowed_mechanisms = public_allowed_mechanisms,
        .subject = public_key_subject,
        .encrypt = if (alow_encrypt) pkcs.CK_TRUE else pkcs.CK_FALSE,
        .verify = pkcs.CK_TRUE,
        .verify_recover = pkcs.CK_FALSE,
        .wrap = pkcs.CK_FALSE,
        .trusted = pkcs.CK_FALSE,
        .wrap_template = wrap_template,
        .public_key_info = pub_public_key_info,
        .modulus = public_key_modulus,
        .modulus_bits = @intCast(public_key_modulus.len * 8),
        .public_exponent = pub_public_exponent,
    };

    const object2 = object.Object{ .private_key = private_key_object };
    const object1 = object.Object{ .certificate = certificate_object };
    const object3 = object.Object{ .public_key = public_key_object };

    return [3]object.Object{ object1, object2, object3 };
}

fn allocEmptySlice(comptime T: type, allocator: std.mem.Allocator) PkcsError![]T {
    return allocator.alloc(T, 0) catch
        return PkcsError.HostMemory;
}

fn clone(allocator: std.mem.Allocator, src: []const u8) PkcsError![]u8 {
    return allocator.dupe(u8, src) catch
        return PkcsError.HostMemory;
}

fn extractSerialNumber(cert_bytes: []const u8) Certificate.der.Element.ParseError![]const u8 {
    const certificate = try Certificate.der.Element.parse(cert_bytes, 0);
    const tbs_certificate = try Certificate.der.Element.parse(cert_bytes, certificate.slice.start);
    const version_elem = try Certificate.der.Element.parse(cert_bytes, tbs_certificate.slice.start);
    const serial_number = if (@as(u8, @bitCast(version_elem.identifier)) == 0xa0)
        try Certificate.der.Element.parse(cert_bytes, version_elem.slice.end)
    else
        version_elem;

    return cert_bytes[serial_number.slice.start - 2 .. serial_number.slice.end];
}

fn extractLabel(subject_bytes: []const u8) []const u8 {
    var i: usize = subject_bytes.len;

    while (i > 0) {
        i -= 1;
        if (subject_bytes[i] == 0x0C)
            break;
    }

    return subject_bytes[i + 2 .. subject_bytes.len];
}

pub fn decompressCertificate(allocator: std.mem.Allocator, compressed_certificate_data: []const u8) PkcsError![]u8 {
    if (compressed_certificate_data.len < 8)
        return PkcsError.GeneralError;

    var list = std.ArrayList(u8).initCapacity(allocator, 2 * compressed_certificate_data.len) catch
        return PkcsError.HostMemory;
    defer list.deinit(allocator);

    const decompress_buffer = allocator.alloc(u8, std.compress.flate.max_window_len) catch
        return PkcsError.HostMemory;
    defer allocator.free(decompress_buffer);

    var reader = std.Io.Reader.fixed(compressed_certificate_data[6..]);
    var decompress: std.compress.flate.Decompress = .init(&reader, std.compress.flate.Container.zlib, decompress_buffer);

    var buf2: [512]u8 = undefined;
    while (true) {
        const size = decompress.reader.readSliceShort(&buf2) catch
            return PkcsError.HostMemory;

        list.appendSlice(allocator, buf2[0..size]) catch
            return PkcsError.HostMemory;

        if (size < buf2.len)
            break;
    }

    const decompressed_certificate = list.toOwnedSlice(allocator) catch
        return PkcsError.HostMemory;

    return decompressed_certificate;
}

test "parse objects" {
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

    const id = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7 };
    const label: []const u8 = "Test Cert";
    const empty_slice = [_]u8{};

    for (test_data) |td| {
        const der = try std.Io.Dir.readFileAlloc(std.Io.Dir.cwd(), tio, td.file_name, ta, .unlimited);
        defer ta.free(der);

        var objects = try loadObjects(ta, der, 1, 2, 3, &id, false);
        defer {
            for (&objects) |*o|
                o.deinit(ta);
        }

        for (&objects) |*o| {
            switch (o.*) {
                .certificate => |c| {
                    try std.testing.expectEqual(1, c.handle);
                    try std.testing.expectEqualSlices(u8, td.serial_number, c.serial_number);
                    try std.testing.expectEqualSlices(u8, &id, c.id);
                    try std.testing.expectEqualSlices(u8, label, c.label);
                },
                .private_key => |c| {
                    try std.testing.expectEqual(2, c.handle);
                    try std.testing.expectEqualSlices(u8, &id, c.id);
                    try std.testing.expectEqualSlices(u8, &empty_slice, c.label);
                    try std.testing.expectEqualSlices(u8, td.modulus, c.modulus);
                },
                .public_key => |c| {
                    try std.testing.expectEqual(3, c.handle);
                    try std.testing.expectEqualSlices(u8, &id, c.id);
                    try std.testing.expectEqualSlices(u8, &empty_slice, c.label);
                    try std.testing.expectEqualSlices(u8, td.modulus, c.modulus);
                },
            }
        }
    }
}
