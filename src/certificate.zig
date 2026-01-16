const std = @import("std");
const Certificate = std.crypto.Certificate;

const object = @import("object.zig");
const pkcs = @import("pkcs.zig").pkcs;
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

    switch (parsed.pub_key_algo) {
        .rsaEncryption => {},
        else => return PkcsError.GeneralError,
    }

    const public_key_components = std.crypto.Certificate.rsa.PublicKey.parseDer(parsed.pubKey()) catch
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
        .modulus_bits = public_key_modulus.len * 8,
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
    const buf = allocator.alloc(u8, src.len) catch
        return PkcsError.HostMemory;

    std.mem.copyForwards(u8, buf, src);

    return buf;
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

    var reader = std.io.Reader.fixed(compressed_certificate_data[6..]);
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

test "allocate and deallocate objects" {
    const ta = std.testing.allocator;

    const der = try std.fs.Dir.readFileAlloc(std.fs.cwd(), ta, "testdata/test.der", 1024 * 1024);
    defer ta.free(der);

    const id = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7 };
    var objects = try loadObjects(ta, der, 1, 2, 3, &id, false);

    for (&objects) |*o| {
        o.deinit(ta);
    }
}

test "parse objects" {
    const ta = std.testing.allocator;

    const der = try std.fs.Dir.readFileAlloc(std.fs.cwd(), ta, "testdata/test.der", 1024 * 1024);
    defer ta.free(der);

    const id = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7 };
    const label: []const u8 = "Test Cert";
    const empty_slice = [_]u8{};
    const serial_number = [_]u8{
        0x02, 0x14, 0x08, 0xCA, 0x8E, 0x29, 0x70, 0x68,
        0x39, 0x10, 0xEE, 0xF1, 0x72, 0x5F, 0xFE, 0xCD,
        0xB2, 0x25, 0x7E, 0x03, 0x3E, 0x72,
    };
    const modulus = [_]u8{
        0xBC, 0xE3, 0xD4, 0x7E, 0xF2, 0xAF, 0x3A, 0xB4,
        0xC8, 0x38, 0x63, 0x6D, 0xD4, 0xDD, 0x65, 0xDC,
        0x5D, 0x93, 0x34, 0x06, 0xF3, 0xAA, 0x37, 0xC8,
        0xCB, 0x1C, 0x66, 0x8A, 0x85, 0x7E, 0xEF, 0xAC,
        0x22, 0xDA, 0xBE, 0xF3, 0x96, 0xEB, 0xE4, 0xC5,
        0x57, 0xDB, 0x09, 0x20, 0xFF, 0xCE, 0xA4, 0x87,
        0x3D, 0xF7, 0x69, 0xF6, 0x9E, 0xFC, 0x4F, 0xAD,
        0x7E, 0x32, 0xA6, 0xE3, 0x16, 0xDB, 0x4A, 0x1C,
        0xD5, 0x77, 0xF6, 0x0E, 0xDC, 0xA2, 0xA4, 0xAE,
        0x6B, 0x34, 0xA2, 0x3C, 0x89, 0xFD, 0x1A, 0x79,
        0x9E, 0x0B, 0x0A, 0xC7, 0x27, 0xA5, 0x5F, 0x9F,
        0x25, 0x2C, 0xF9, 0xD1, 0xC3, 0x85, 0xD8, 0x97,
        0xFF, 0xE1, 0xC5, 0x6B, 0xA1, 0x03, 0x2B, 0xF6,
        0x4A, 0xDF, 0x5A, 0x9C, 0xAE, 0xCE, 0xCC, 0x82,
        0x88, 0xD8, 0x55, 0x72, 0x57, 0x7E, 0x90, 0x92,
        0xA4, 0x74, 0x54, 0x08, 0x1F, 0xDA, 0x85, 0x9B,
        0x41, 0xE0, 0x69, 0x36, 0xC0, 0x81, 0xB0, 0x30,
        0xF6, 0x93, 0xA3, 0xED, 0xED, 0xEE, 0x7D, 0xCE,
        0xAE, 0x39, 0x47, 0x6F, 0xF7, 0x85, 0x21, 0x9D,
        0xEC, 0x5F, 0x44, 0x5C, 0x15, 0x41, 0xC9, 0xAA,
        0x2B, 0x75, 0x30, 0x41, 0x81, 0x86, 0x8F, 0x63,
        0x36, 0x4B, 0x67, 0x09, 0x58, 0xAE, 0xF5, 0x1B,
        0xD8, 0x20, 0xC6, 0xE8, 0x4D, 0xB1, 0x78, 0x85,
        0xFD, 0x9E, 0x70, 0x6F, 0x70, 0x59, 0xF6, 0xC2,
        0x49, 0x62, 0xE6, 0x64, 0xF7, 0x6D, 0x6B, 0x58,
        0xCF, 0x46, 0x7D, 0x79, 0x9D, 0xF3, 0x86, 0x89,
        0xDB, 0x9D, 0x35, 0x02, 0xCD, 0x46, 0x61, 0x67,
        0xC3, 0xC8, 0xC0, 0xCE, 0xC0, 0x1E, 0xE9, 0x7C,
        0x2E, 0x1A, 0x37, 0x0C, 0x8E, 0xF4, 0xB8, 0xCF,
        0x3C, 0x5B, 0xC1, 0x09, 0xC2, 0x4E, 0x27, 0x2D,
        0x76, 0x4D, 0x88, 0xC7, 0xA9, 0x78, 0x41, 0x8D,
        0x83, 0xBD, 0x90, 0xF1, 0x9D, 0x3A, 0xF6, 0x23,
    };

    var objects = try loadObjects(ta, der, 1, 2, 3, &id, false);

    for (&objects) |*o| {
        switch (o.*) {
            .certificate => |c| {
                try std.testing.expectEqual(1, c.handle);
                try std.testing.expectEqualSlices(u8, &serial_number, c.serial_number);
                try std.testing.expectEqualSlices(u8, &id, c.id);
                try std.testing.expectEqualSlices(u8, label, c.label);
            },
            .private_key => |c| {
                try std.testing.expectEqual(2, c.handle);
                try std.testing.expectEqualSlices(u8, &id, c.id);
                try std.testing.expectEqualSlices(u8, &empty_slice, c.label);
                try std.testing.expectEqualSlices(u8, &modulus, c.modulus);
            },
            .public_key => |c| {
                try std.testing.expectEqual(3, c.handle);
                try std.testing.expectEqualSlices(u8, &id, c.id);
                try std.testing.expectEqualSlices(u8, &empty_slice, c.label);
                try std.testing.expectEqualSlices(u8, &modulus, c.modulus);
            },
        }
    }

    for (&objects) |*o| {
        o.deinit(ta);
    }
}
