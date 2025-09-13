const std = @import("std");
const Certificate = std.crypto.Certificate;

const pkcs = @cImport({
    @cInclude("pkcs.h");
});

const object = @import("object.zig");
const pkcs_error = @import("pkcs_error.zig");
const PkcsError = pkcs_error.PkcsError;

pub fn loadObjects(
    allocator: std.mem.Allocator,
    buffer: []const u8,
    certificate_handle: pkcs.CK_OBJECT_HANDLE,
    private_key_handle: pkcs.CK_OBJECT_HANDLE,
    public_key_handle: pkcs.CK_OBJECT_HANDLE,
    alow_encrypt: bool,
) PkcsError![3]object.Object {
    const cert = Certificate{ .buffer = buffer, .index = 0 };

    const parsed = Certificate.parse(cert) catch
        return PkcsError.GeneralError;

    const id = try allocEmptySlice(allocator); // TODO
    errdefer allocator.free(id);

    const certificate_value = try clone(allocator, buffer);
    errdefer allocator.free(certificate_value);

    const serial_number_slice = extractSerialNumber(buffer) catch return PkcsError.GeneralError;
    const serial_number = try clone(allocator, serial_number_slice);
    errdefer allocator.free(serial_number);

    // empty on the original token
    const certificate_url = try allocEmptySlice(allocator);
    errdefer allocator.free(certificate_url);
    const public_key_hash = try allocEmptySlice(allocator);
    errdefer allocator.free(public_key_hash);
    const check_value = try allocEmptySlice(allocator);
    errdefer allocator.free(check_value);

    // invalid on the original token
    const public_key_info = try allocEmptySlice(allocator);
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
        .id = id,
        .issuer = issuer,
        .serial_number = serial_number,
        .value = certificate_value,
        .url = certificate_url,
        .hash_of_subject_public_key = public_key_hash,
        .name_hash_algorithm = name_hash_algorithm,
    };

    const priv_id = try clone(allocator, id);
    errdefer allocator.free(priv_id);
    const private_key_label = try allocEmptySlice(allocator);
    errdefer allocator.free(private_key_label);
    const private_key_subject = try allocEmptySlice(allocator);
    errdefer allocator.free(private_key_subject);

    // invalid on original token
    const priv_public_key_info = try allocEmptySlice(allocator);
    errdefer allocator.free(priv_public_key_info);

    const private_key_object: object.PrivateKeyObject = object.PrivateKeyObject{
        .handle = private_key_handle,
        .class = pkcs.CKO_PRIVATE_KEY,
        .token = pkcs.CK_TRUE,
        .private = pkcs.CK_TRUE,
        .modifiable = pkcs.CK_FALSE,
        .label = private_key_label,
        .copyable = pkcs.CK_FALSE,
        .destroyable = pkcs.CK_FALSE,
        .key_type = undefined,
        .id = priv_id,
        .start_date = pkcs.CK_DATE{},
        .end_date = pkcs.CK_DATE{},
        .derive = pkcs.CK_FALSE,
        .local = pkcs.CK_TRUE,
        .key_gen_mechanism = undefined,
        .allowed_mechanisms = undefined,
        .subject = private_key_subject,
        .sensitive = undefined,
        .decrypt = pkcs.CK_TRUE,
        .sign = pkcs.CK_TRUE,
        .sign_recover = undefined,
        .unwrap = undefined,
        .extractable = pkcs.CK_FALSE,
        .always_sensitive = pkcs.CK_TRUE,
        .never_extractable = pkcs.CK_TRUE,
        .wrap_with_trusted = undefined,
        .unwrap_template = undefined,
        .always_authenticate = undefined,
        .public_key_info = priv_public_key_info,
    };

    const pub_id = try clone(allocator, id);
    errdefer allocator.free(pub_id);
    const public_key_label = try allocEmptySlice(allocator);
    errdefer allocator.free(public_key_label);
    const public_key_subject = try allocEmptySlice(allocator);
    errdefer allocator.free(public_key_subject);

    // invalid on original token
    const pub_public_key_info = try allocEmptySlice(allocator);
    errdefer allocator.free(pub_public_key_info);

    const public_key_object: object.PublicKeyObject = object.PublicKeyObject{
        .handle = public_key_handle,
        .class = pkcs.CKO_PUBLIC_KEY,
        .token = pkcs.CK_TRUE,
        .private = pkcs.CK_FALSE,
        .modifiable = undefined,
        .label = public_key_label,
        .copyable = undefined,
        .destroyable = undefined,
        .key_type = undefined,
        .id = pub_id,
        .start_date = pkcs.CK_DATE{},
        .end_date = pkcs.CK_DATE{},
        .derive = pkcs.CK_FALSE,
        .local = pkcs.CK_TRUE,
        .key_gen_mechanism = undefined,
        .allowed_mechanisms = undefined,
        .subject = public_key_subject,
        .encrypt = if (alow_encrypt) pkcs.CK_TRUE else pkcs.CK_FALSE,
        .verify = pkcs.CK_TRUE,
        .verify_recover = pkcs.CK_FALSE,
        .wrap = pkcs.CK_FALSE,
        .trusted = pkcs.CK_FALSE,
        .wrap_template = undefined,
        .public_key_info = pub_public_key_info,
    };

    const object2 = object.Object{ .private_key = private_key_object };
    const object1 = object.Object{ .certificate = certificate_object };
    const object3 = object.Object{ .public_key = public_key_object };

    return [3]object.Object{ object1, object2, object3 };
}

fn allocEmptySlice(allocator: std.mem.Allocator) PkcsError![]u8 {
    return allocator.alloc(u8, 0) catch
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

fn printHex(data: []const u8) void {
    for (data) |b| {
        std.debug.print("{x:02}", .{b});
    }
    std.debug.print("\n\n", .{});
}
