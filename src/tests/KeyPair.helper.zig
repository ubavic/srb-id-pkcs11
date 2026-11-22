//! RSA key pair loaded from a PKCS#8 PEM file.

const std = @import("std");
const der = std.crypto.Certificate.der;

const PublicKeyFile = @import("../smart-card/PublicKeyFile.zig");

const KeyPair = @This();

/// The largest modulus, in bytes, that fits into `PublicKeyFile`.
pub const max_size = @typeInfo(@FieldType(PublicKeyFile, "modulus")).array.len;

pub const public_key_file_name: [2]u8 = .{ 0x60, 0x04 };
pub const private_key_file_name: [2]u8 = .{ 0x60, 0x05 };

allocator: std.mem.Allocator,
/// Decoded PKCS#8 structure, key components point into it.
der_bytes: []u8,
modulus: []const u8,
public_exponent: []const u8,
private_exponent: []const u8,

pub fn load(allocator: std.mem.Allocator, io: std.Io, path: []const u8) !KeyPair {
    const pem = try std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(16 * 1024));
    defer allocator.free(pem);

    const der_bytes = try decodePem(allocator, pem);
    errdefer allocator.free(der_bytes);

    // PrivateKeyInfo ::= SEQUENCE { version, privateKeyAlgorithm, privateKey OCTET STRING }
    const private_key_info = try parseElement(der_bytes, 0, .sequence);
    const info_version = try parseElement(der_bytes, private_key_info.slice.start, .integer);
    const algorithm = try parseElement(der_bytes, info_version.slice.end, .sequence);
    const private_key = try parseElement(der_bytes, algorithm.slice.end, .octetstring);

    // RSAPrivateKey ::= SEQUENCE { version, modulus, publicExponent, privateExponent, ... }
    const rsa_private_key = try parseElement(der_bytes, private_key.slice.start, .sequence);
    const rsa_version = try parseElement(der_bytes, rsa_private_key.slice.start, .integer);
    const modulus = try parseElement(der_bytes, rsa_version.slice.end, .integer);
    const public_exponent = try parseElement(der_bytes, modulus.slice.end, .integer);
    const private_exponent = try parseElement(der_bytes, public_exponent.slice.end, .integer);

    const key_pair = KeyPair{
        .allocator = allocator,
        .der_bytes = der_bytes,
        .modulus = integerBytes(der_bytes, modulus),
        .public_exponent = integerBytes(der_bytes, public_exponent),
        .private_exponent = integerBytes(der_bytes, private_exponent),
    };

    if (key_pair.size() > max_size)
        return error.KeyTooLarge;

    return key_pair;
}

pub fn deinit(self: *KeyPair) void {
    self.allocator.free(self.der_bytes);
    self.* = undefined;
}

/// Size of the modulus in bytes.
pub fn size(self: *const KeyPair) usize {
    return self.modulus.len;
}

fn decodePem(allocator: std.mem.Allocator, pem: []const u8) ![]u8 {
    const begin_marker = "-----BEGIN PRIVATE KEY-----";
    const end_marker = "-----END PRIVATE KEY-----";

    const begin = std.mem.indexOf(u8, pem, begin_marker) orelse
        return error.InvalidPem;
    const end = std.mem.indexOfPos(u8, pem, begin, end_marker) orelse
        return error.InvalidPem;
    const encoded = pem[begin + begin_marker.len .. end];

    const decoder = std.base64.standard.decoderWithIgnore(" \t\r\n");
    const decoded = try allocator.alloc(u8, decoder.calcSizeUpperBound(encoded.len));
    errdefer allocator.free(decoded);

    const decoded_len = try decoder.decode(decoded, encoded);
    return allocator.realloc(decoded, decoded_len);
}

fn parseElement(bytes: []const u8, index: u32, tag: der.Tag) !der.Element {
    if (index + 2 > bytes.len)
        return error.InvalidDer;

    const element = try der.Element.parse(bytes, index);
    if (element.slice.end > bytes.len or element.identifier.tag != tag)
        return error.InvalidDer;

    return element;
}

/// Content of a DER integer without leading zero bytes.
fn integerBytes(bytes: []const u8, element: der.Element) []const u8 {
    const content = bytes[element.slice.start..element.slice.end];
    const first_non_zero = std.mem.indexOfNone(u8, content, &.{0x00}) orelse content.len;
    return content[first_non_zero..];
}
