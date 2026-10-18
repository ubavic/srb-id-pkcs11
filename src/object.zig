const std = @import("std");

const Attribute = @import("Attribute.zig");
const pkcs = @import("pkcs.zig");
const PkcsError = @import("pkcs_error.zig").PkcsError;
const PublicKeyFile = @import("smart-card/PublicKeyFile.zig").PublicKeyFile;

const CKT_NETSCAPE_TRUSTED_DELEGATOR: pkcs.CK_ATTRIBUTE_TYPE = 0xce534352;

const id_size: comptime_int = 20;

pub const Object = union(enum) {
    certificate: CertificateObject,
    private_key: PrivateKeyObject,
    public_key: PublicKeyObject,

    pub fn handle(self: *const Object) pkcs.CK_OBJECT_HANDLE {
        return switch (self.*) {
            .certificate => |o| o.handle,
            .private_key => |o| o.handle,
            .public_key => |o| o.handle,
        };
    }

    pub fn class(self: *const Object) pkcs.CK_OBJECT_CLASS {
        return switch (self.*) {
            .certificate => |o| o.class,
            .private_key => |o| o.class,
            .public_key => |o| o.class,
        };
    }

    pub fn fileName(self: *const Object) [2]u8 {
        return switch (self.*) {
            .certificate => |o| o.file_name,
            .private_key => |o| o.file_name,
            .public_key => |o| o.file_name,
        };
    }

    pub fn getAttribute(self: *const Object, buffer: []u8, attribute_type: pkcs.CK_ATTRIBUTE_TYPE) PkcsError!Attribute {
        const value = try switch (self.*) {
            .certificate => |o| o.getAttributeValue(buffer, attribute_type),
            .private_key => |o| o.getAttributeValue(buffer, attribute_type),
            .public_key => |o| o.getAttributeValue(buffer, attribute_type),
        };

        return Attribute{
            .attribute_type = attribute_type,
            .value = value,
        };
    }

    pub fn getAttributeSize(self: *const Object, attribute_type: pkcs.CK_ATTRIBUTE_TYPE) PkcsError!usize {
        return try switch (self.*) {
            .certificate => |o| o.getAttributeSize(attribute_type),
            .private_key => |o| o.getAttributeSize(attribute_type),
            .public_key => |o| o.getAttributeSize(attribute_type),
        };
    }

    pub fn hasAttributeValue(self: *const Object, allocator: std.mem.Allocator, attribute: Attribute) PkcsError!bool {
        const attribute_size = self.getAttributeSize(attribute.attribute_type) catch |err| switch (err) {
            PkcsError.AttributeTypeInvalid => return false,
            else => return err,
        };

        if (attribute_size != attribute.value.len)
            return false;

        const buffer = allocator.alloc(u8, attribute_size) catch
            return PkcsError.HostMemory;
        defer allocator.free(buffer);

        const object_attribute = try self.getAttribute(buffer, attribute.attribute_type);

        return std.mem.eql(u8, object_attribute.value, attribute.value);
    }

    pub fn private(self: *const Object) bool {
        return switch (self.*) {
            .certificate => |o| o.private == pkcs.CK_TRUE,
            .private_key => |o| o.private == pkcs.CK_TRUE,
            .public_key => |o| o.private == pkcs.CK_TRUE,
        };
    }

    pub fn deinit(self: *Object, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .certificate => |*o| o.deinit(allocator),
            .private_key => |*o| o.deinit(allocator),
            .public_key => |*o| o.deinit(allocator),
        }
    }
};

pub const CertificateObject = struct {
    file_name: [2]u8,
    id: [id_size]u8,
    handle: pkcs.CK_OBJECT_HANDLE,
    class: pkcs.CK_OBJECT_CLASS,
    token: pkcs.CK_BBOOL,
    private: pkcs.CK_BBOOL,
    modifiable: pkcs.CK_BBOOL,
    label: []u8,
    copyable: pkcs.CK_BBOOL,
    destroyable: pkcs.CK_BBOOL,
    certificate_type: pkcs.CK_CERTIFICATE_TYPE,
    trusted: pkcs.CK_BBOOL,
    certificate_category: pkcs.CK_CERTIFICATE_CATEGORY,
    check_value: []u8,
    start_date: pkcs.CK_DATE,
    end_date: pkcs.CK_DATE,
    public_key_info: []u8,
    subject: []u8,
    issuer: []u8,
    serial_number: []u8,
    value: []u8,
    url: []u8,
    hash_of_subject_public_key: []u8,
    name_hash_algorithm: pkcs.CK_MECHANISM_TYPE,

    pub fn deinit(self: *CertificateObject, allocator: std.mem.Allocator) void {
        std.crypto.secureZero(u8, &self.id);

        std.crypto.secureZero(u8, self.label);
        allocator.free(self.label);

        std.crypto.secureZero(u8, self.check_value);
        allocator.free(self.check_value);

        std.crypto.secureZero(u8, self.public_key_info);
        allocator.free(self.public_key_info);

        std.crypto.secureZero(u8, self.subject);
        allocator.free(self.subject);

        std.crypto.secureZero(u8, self.issuer);
        allocator.free(self.issuer);

        std.crypto.secureZero(u8, self.serial_number);
        allocator.free(self.serial_number);

        std.crypto.secureZero(u8, self.value);
        allocator.free(self.value);

        std.crypto.secureZero(u8, self.url);
        allocator.free(self.url);

        std.crypto.secureZero(u8, self.hash_of_subject_public_key);
        allocator.free(self.hash_of_subject_public_key);

        std.crypto.secureZero(u8, std.mem.asBytes(self));
    }

    pub fn getAttributeValue(self: *const CertificateObject, buffer: []u8, attribute_type: pkcs.CK_ATTRIBUTE_TYPE) PkcsError![]u8 {
        return switch (attribute_type) {
            pkcs.CKA_CLASS => encodeLong(buffer, self.class),
            pkcs.CKA_TOKEN => encodeBool(buffer, self.token),
            pkcs.CKA_PRIVATE => encodeBool(buffer, self.private),
            pkcs.CKA_MODIFIABLE => encodeBool(buffer, self.modifiable),
            pkcs.CKA_LABEL => encodeByteArray(buffer, self.label),
            pkcs.CKA_COPYABLE => encodeBool(buffer, self.copyable),
            pkcs.CKA_DESTROYABLE => encodeBool(buffer, self.destroyable),
            pkcs.CKA_CERTIFICATE_TYPE => encodeLong(buffer, self.certificate_type),
            pkcs.CKA_TRUSTED => encodeBool(buffer, self.trusted),
            pkcs.CKA_CERTIFICATE_CATEGORY => encodeLong(buffer, self.certificate_category),
            pkcs.CKA_CHECK_VALUE => encodeByteArray(buffer, self.check_value),
            pkcs.CKA_START_DATE => encodeDate(buffer, self.start_date),
            pkcs.CKA_END_DATE => encodeDate(buffer, self.end_date),
            pkcs.CKA_PUBLIC_KEY_INFO => encodeByteArray(buffer, self.public_key_info),
            pkcs.CKA_SUBJECT => encodeByteArray(buffer, self.subject),
            pkcs.CKA_ID => encodeByteArray(buffer, &self.id),
            pkcs.CKA_ISSUER => encodeByteArray(buffer, self.issuer),
            pkcs.CKA_SERIAL_NUMBER => encodeByteArray(buffer, self.serial_number),
            pkcs.CKA_VALUE => encodeByteArray(buffer, self.value),
            pkcs.CKA_URL => encodeByteArray(buffer, self.url),
            pkcs.CKA_HASH_OF_SUBJECT_PUBLIC_KEY => encodeByteArray(buffer, self.hash_of_subject_public_key),
            pkcs.CKA_NAME_HASH_ALGORITHM => encodeLong(buffer, self.name_hash_algorithm),
            CKT_NETSCAPE_TRUSTED_DELEGATOR => encodeBool(buffer, pkcs.CK_TRUE),
            else => PkcsError.AttributeTypeInvalid,
        };
    }

    pub fn getAttributeSize(self: *const CertificateObject, attribute_type: pkcs.CK_ATTRIBUTE_TYPE) PkcsError!usize {
        return switch (attribute_type) {
            pkcs.CKA_CLASS => @sizeOf(pkcs.CK_ULONG),
            pkcs.CKA_TOKEN => @sizeOf(pkcs.CK_BBOOL),
            pkcs.CKA_PRIVATE => @sizeOf(pkcs.CK_BBOOL),
            pkcs.CKA_MODIFIABLE => @sizeOf(pkcs.CK_BBOOL),
            pkcs.CKA_LABEL => self.label.len,
            pkcs.CKA_COPYABLE => @sizeOf(pkcs.CK_BBOOL),
            pkcs.CKA_DESTROYABLE => @sizeOf(pkcs.CK_BBOOL),
            pkcs.CKA_CERTIFICATE_TYPE => @sizeOf(pkcs.CK_ULONG),
            pkcs.CKA_TRUSTED => @sizeOf(pkcs.CK_BBOOL),
            pkcs.CKA_CERTIFICATE_CATEGORY => @sizeOf(pkcs.CK_ULONG),
            pkcs.CKA_CHECK_VALUE => self.check_value.len,
            pkcs.CKA_START_DATE => @sizeOf(pkcs.CK_DATE),
            pkcs.CKA_END_DATE => @sizeOf(pkcs.CK_DATE),
            pkcs.CKA_PUBLIC_KEY_INFO => self.public_key_info.len,
            pkcs.CKA_SUBJECT => self.subject.len,
            pkcs.CKA_ID => self.id.len,
            pkcs.CKA_ISSUER => self.issuer.len,
            pkcs.CKA_SERIAL_NUMBER => self.serial_number.len,
            pkcs.CKA_VALUE => self.value.len,
            pkcs.CKA_URL => self.url.len,
            pkcs.CKA_HASH_OF_SUBJECT_PUBLIC_KEY => self.hash_of_subject_public_key.len,
            pkcs.CKA_NAME_HASH_ALGORITHM => @sizeOf(pkcs.CK_ULONG),
            CKT_NETSCAPE_TRUSTED_DELEGATOR => @sizeOf(pkcs.CK_BBOOL),
            else => PkcsError.AttributeTypeInvalid,
        };
    }

    pub fn parse(
        allocator: std.mem.Allocator,
        certificate_handle: pkcs.CK_OBJECT_HANDLE,
        buffer: []const u8,
        id: [20]u8,
        file_name: [2]u8,
    ) PkcsError!CertificateObject {
        const cert = std.crypto.Certificate{ .buffer = buffer, .index = 0 };

        const parsed = std.crypto.Certificate.parse(cert) catch
            return PkcsError.GeneralError;

        if (parsed.pub_key_algo != .rsaEncryption)
            return PkcsError.GeneralError;

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

        return .{
            .file_name = file_name,
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
    }

    fn extractSerialNumber(cert_bytes: []const u8) std.crypto.Certificate.der.Element.ParseError![]const u8 {
        const certificate = try std.crypto.Certificate.der.Element.parse(cert_bytes, 0);
        const tbs_certificate = try std.crypto.Certificate.der.Element.parse(cert_bytes, certificate.slice.start);
        const version_elem = try std.crypto.Certificate.der.Element.parse(cert_bytes, tbs_certificate.slice.start);
        const serial_number = if (@as(u8, @bitCast(version_elem.identifier)) == 0xa0)
            try std.crypto.Certificate.der.Element.parse(cert_bytes, version_elem.slice.end)
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
};

pub const PrivateKeyObject = struct {
    file_name: [2]u8,
    id: [id_size]u8,
    handle: pkcs.CK_OBJECT_HANDLE,
    class: pkcs.CK_OBJECT_CLASS,
    token: pkcs.CK_BBOOL,
    private: pkcs.CK_BBOOL,
    modifiable: pkcs.CK_BBOOL,
    label: []u8,
    copyable: pkcs.CK_BBOOL,
    destroyable: pkcs.CK_BBOOL,
    key_type: pkcs.CK_KEY_TYPE,
    start_date: pkcs.CK_DATE,
    end_date: pkcs.CK_DATE,
    derive: pkcs.CK_BBOOL,
    local: pkcs.CK_BBOOL,
    key_gen_mechanism: pkcs.CK_MECHANISM_TYPE,
    allowed_mechanisms: []pkcs.CK_MECHANISM_TYPE,
    subject: []u8,
    sensitive: pkcs.CK_BBOOL,
    decrypt: pkcs.CK_BBOOL,
    sign: pkcs.CK_BBOOL,
    sign_recover: pkcs.CK_BBOOL,
    unwrap: pkcs.CK_BBOOL,
    extractable: pkcs.CK_BBOOL,
    always_sensitive: pkcs.CK_BBOOL,
    never_extractable: pkcs.CK_BBOOL,
    wrap_with_trusted: pkcs.CK_BBOOL,
    unwrap_template: []pkcs.CK_ATTRIBUTE,
    always_authenticate: pkcs.CK_BBOOL,
    public_key_info: []u8,
    modulus: []u8,
    public_exponent: []u8,

    pub fn deinit(self: *PrivateKeyObject, allocator: std.mem.Allocator) void {
        std.crypto.secureZero(u8, &self.id);

        std.crypto.secureZero(u8, self.label);
        allocator.free(self.label);

        std.crypto.secureZero(pkcs.CK_MECHANISM_TYPE, self.allowed_mechanisms);
        allocator.free(self.allowed_mechanisms);

        std.crypto.secureZero(u8, self.subject);
        allocator.free(self.subject);

        allocator.free(self.unwrap_template);

        std.crypto.secureZero(u8, self.public_key_info);
        allocator.free(self.public_key_info);

        std.crypto.secureZero(u8, self.modulus);
        allocator.free(self.modulus);

        std.crypto.secureZero(u8, self.public_exponent);
        allocator.free(self.public_exponent);

        std.crypto.secureZero(u8, std.mem.asBytes(self));
    }

    pub fn getAttributeValue(self: *const PrivateKeyObject, buffer: []u8, attribute_type: pkcs.CK_ATTRIBUTE_TYPE) PkcsError![]u8 {
        return switch (attribute_type) {
            pkcs.CKA_CLASS => encodeLong(buffer, self.class),
            pkcs.CKA_TOKEN => encodeBool(buffer, self.token),
            pkcs.CKA_PRIVATE => encodeBool(buffer, self.private),
            pkcs.CKA_MODIFIABLE => encodeBool(buffer, self.modifiable),
            pkcs.CKA_LABEL => encodeByteArray(buffer, self.label),
            pkcs.CKA_COPYABLE => encodeBool(buffer, self.copyable),
            pkcs.CKA_DESTROYABLE => encodeBool(buffer, self.destroyable),
            pkcs.CKA_KEY_TYPE => encodeLong(buffer, self.key_type),
            pkcs.CKA_ID => encodeByteArray(buffer, &self.id),
            pkcs.CKA_START_DATE => encodeDate(buffer, self.start_date),
            pkcs.CKA_END_DATE => encodeDate(buffer, self.end_date),
            pkcs.CKA_DERIVE => encodeBool(buffer, self.derive),
            pkcs.CKA_LOCAL => encodeBool(buffer, self.local),
            pkcs.CKA_KEY_GEN_MECHANISM => encodeLong(buffer, self.key_gen_mechanism),
            // pkcs.CKA_ALLOWED_MECHANISMS => unreachable, // TODO
            pkcs.CKA_SUBJECT => encodeByteArray(buffer, self.subject),
            pkcs.CKA_SENSITIVE => encodeBool(buffer, self.sensitive),
            pkcs.CKA_DECRYPT => encodeBool(buffer, self.decrypt),
            pkcs.CKA_SIGN => encodeBool(buffer, self.sign),
            pkcs.CKA_SIGN_RECOVER => encodeBool(buffer, self.sign_recover),
            pkcs.CKA_UNWRAP => encodeBool(buffer, self.unwrap),
            pkcs.CKA_EXTRACTABLE => encodeBool(buffer, self.extractable),
            pkcs.CKA_ALWAYS_SENSITIVE => encodeBool(buffer, self.always_sensitive),
            pkcs.CKA_NEVER_EXTRACTABLE => encodeBool(buffer, self.never_extractable),
            pkcs.CKA_WRAP_WITH_TRUSTED => encodeBool(buffer, self.wrap_with_trusted),
            // pkcs.CKA_UNWRAP_TEMPLATE => unreachable,
            pkcs.CKA_ALWAYS_AUTHENTICATE => encodeBool(buffer, self.always_authenticate),
            pkcs.CKA_PUBLIC_KEY_INFO => encodeByteArray(buffer, self.public_key_info),
            pkcs.CKA_MODULUS => encodeByteArray(buffer, self.modulus),
            pkcs.CKA_PUBLIC_EXPONENT => encodeByteArray(buffer, self.public_exponent),
            else => PkcsError.AttributeTypeInvalid,
        };
    }

    pub fn getAttributeSize(self: *const PrivateKeyObject, attribute_type: pkcs.CK_ATTRIBUTE_TYPE) PkcsError!usize {
        return switch (attribute_type) {
            pkcs.CKA_CLASS => @sizeOf(pkcs.CK_ULONG),
            pkcs.CKA_TOKEN => @sizeOf(pkcs.CK_BBOOL),
            pkcs.CKA_PRIVATE => @sizeOf(pkcs.CK_BBOOL),
            pkcs.CKA_MODIFIABLE => @sizeOf(pkcs.CK_BBOOL),
            pkcs.CKA_LABEL => self.label.len,
            pkcs.CKA_COPYABLE => @sizeOf(pkcs.CK_BBOOL),
            pkcs.CKA_DESTROYABLE => @sizeOf(pkcs.CK_BBOOL),
            pkcs.CKA_KEY_TYPE => @sizeOf(pkcs.CK_ULONG),
            pkcs.CKA_ID => self.id.len,
            pkcs.CKA_START_DATE => @sizeOf(pkcs.CK_DATE),
            pkcs.CKA_END_DATE => @sizeOf(pkcs.CK_DATE),
            pkcs.CKA_DERIVE => @sizeOf(pkcs.CK_BBOOL),
            pkcs.CKA_LOCAL => @sizeOf(pkcs.CK_BBOOL),
            pkcs.CKA_KEY_GEN_MECHANISM => @sizeOf(pkcs.CK_ULONG),
            // pkcs.CKA_ALLOWED_MECHANISMS => unreachable, // TODO
            pkcs.CKA_SUBJECT => self.subject.len,
            pkcs.CKA_SENSITIVE => @sizeOf(pkcs.CK_BBOOL),
            pkcs.CKA_DECRYPT => @sizeOf(pkcs.CK_BBOOL),
            pkcs.CKA_SIGN => @sizeOf(pkcs.CK_BBOOL),
            pkcs.CKA_SIGN_RECOVER => @sizeOf(pkcs.CK_BBOOL),
            pkcs.CKA_UNWRAP => @sizeOf(pkcs.CK_BBOOL),
            pkcs.CKA_EXTRACTABLE => @sizeOf(pkcs.CK_BBOOL),
            pkcs.CKA_ALWAYS_SENSITIVE => @sizeOf(pkcs.CK_BBOOL),
            pkcs.CKA_NEVER_EXTRACTABLE => @sizeOf(pkcs.CK_BBOOL),
            pkcs.CKA_WRAP_WITH_TRUSTED => @sizeOf(pkcs.CK_BBOOL),
            // pkcs.CKA_UNWRAP_TEMPLATE => unreachable,
            pkcs.CKA_ALWAYS_AUTHENTICATE => @sizeOf(pkcs.CK_BBOOL),
            pkcs.CKA_PUBLIC_KEY_INFO => self.public_key_info.len,
            pkcs.CKA_MODULUS => self.modulus.len,
            pkcs.CKA_PUBLIC_EXPONENT => self.public_exponent.len,
            else => PkcsError.AttributeTypeInvalid,
        };
    }

    pub fn createPrivateKeyObject(
        allocator: std.mem.Allocator,
        public_key_file: PublicKeyFile,
        private_key_handle: pkcs.CK_OBJECT_HANDLE,
    ) PkcsError!PrivateKeyObject {
        const private_key_label = try allocEmptySlice(u8, allocator);
        errdefer allocator.free(private_key_label);
        const private_key_subject = try allocEmptySlice(u8, allocator);
        errdefer allocator.free(private_key_subject);
        const private_key_modulus = try clone(allocator, public_key_file.modulus[0..public_key_file.modulus_len]);
        errdefer allocator.free(private_key_modulus);
        const priv_key_public_exponent = try clone(allocator, public_key_file.exponent[0..public_key_file.exponent_len]);
        errdefer allocator.free(priv_key_public_exponent);

        // invalid on original token
        const priv_public_key_info = try allocEmptySlice(u8, allocator);
        errdefer allocator.free(priv_public_key_info);
        const private_allowed_mechanisms: []pkcs.CK_MECHANISM_TYPE = try allocEmptySlice(pkcs.CK_MECHANISM_TYPE, allocator);
        errdefer allocator.free(private_allowed_mechanisms);
        const unwrap_template: []pkcs.CK_ATTRIBUTE = try allocEmptySlice(pkcs.CK_ATTRIBUTE, allocator);
        errdefer allocator.free(unwrap_template);

        return .{
            .file_name = public_key_file.priv_key_file_name,
            .handle = private_key_handle,
            .class = pkcs.CKO_PRIVATE_KEY,
            .token = pkcs.CK_TRUE,
            .private = pkcs.CK_TRUE,
            .modifiable = pkcs.CK_TRUE,
            .label = private_key_label,
            .copyable = pkcs.CK_FALSE, // invalid on original token
            .destroyable = pkcs.CK_FALSE, // invalid on original token
            .key_type = pkcs.CKK_RSA,
            .id = public_key_file.id,
            .start_date = pkcs.CK_DATE{},
            .end_date = pkcs.CK_DATE{},
            .derive = pkcs.CK_FALSE,
            .local = pkcs.CK_TRUE,
            .key_gen_mechanism = 0, // invalid on original token
            .allowed_mechanisms = private_allowed_mechanisms,
            .subject = private_key_subject,
            .sensitive = pkcs.CK_TRUE,
            .decrypt = if (public_key_file.allow_encrypt) pkcs.CK_TRUE else pkcs.CK_FALSE,
            .sign = pkcs.CK_TRUE,
            .sign_recover = pkcs.CK_FALSE,
            .unwrap = pkcs.CK_FALSE,
            .extractable = pkcs.CK_FALSE,
            .always_sensitive = pkcs.CK_TRUE,
            .never_extractable = pkcs.CK_TRUE,
            .wrap_with_trusted = if (public_key_file.allow_encrypt) pkcs.CK_TRUE else pkcs.CK_FALSE,
            .unwrap_template = unwrap_template,
            .always_authenticate = pkcs.CK_FALSE,
            .public_key_info = priv_public_key_info,
            .modulus = private_key_modulus,
            .public_exponent = priv_key_public_exponent,
        };
    }
};

pub const PublicKeyObject = struct {
    file_name: [2]u8,
    id: [id_size]u8,
    handle: pkcs.CK_OBJECT_HANDLE,
    class: pkcs.CK_OBJECT_CLASS,
    token: pkcs.CK_BBOOL,
    private: pkcs.CK_BBOOL,
    modifiable: pkcs.CK_BBOOL,
    label: []u8,
    copyable: pkcs.CK_BBOOL,
    destroyable: pkcs.CK_BBOOL,
    key_type: pkcs.CK_KEY_TYPE,
    start_date: pkcs.CK_DATE,
    end_date: pkcs.CK_DATE,
    derive: pkcs.CK_BBOOL,
    local: pkcs.CK_BBOOL,
    key_gen_mechanism: pkcs.CK_MECHANISM_TYPE,
    allowed_mechanisms: []pkcs.CK_MECHANISM_TYPE,
    subject: []u8,
    encrypt: pkcs.CK_BBOOL,
    verify: pkcs.CK_BBOOL,
    verify_recover: pkcs.CK_BBOOL,
    wrap: pkcs.CK_BBOOL,
    trusted: pkcs.CK_BBOOL,
    wrap_template: []pkcs.CK_ATTRIBUTE,
    public_key_info: []u8,
    modulus: []u8,
    modulus_bits: pkcs.CK_ULONG,
    public_exponent: []u8,

    pub fn deinit(self: *PublicKeyObject, allocator: std.mem.Allocator) void {
        std.crypto.secureZero(u8, &self.id);

        std.crypto.secureZero(u8, self.label);
        allocator.free(self.label);

        std.crypto.secureZero(pkcs.CK_MECHANISM_TYPE, self.allowed_mechanisms);
        allocator.free(self.allowed_mechanisms);

        std.crypto.secureZero(u8, self.subject);
        allocator.free(self.subject);

        std.crypto.secureZero(u8, self.public_key_info);
        allocator.free(self.public_key_info);

        // TODO: secure zero
        // for now we don't put here anything
        allocator.free(self.wrap_template);

        std.crypto.secureZero(u8, self.modulus);
        allocator.free(self.modulus);

        std.crypto.secureZero(u8, self.public_exponent);
        allocator.free(self.public_exponent);

        std.crypto.secureZero(u8, std.mem.asBytes(self));
    }

    pub fn getAttributeValue(self: *const PublicKeyObject, buffer: []u8, attribute_type: pkcs.CK_ATTRIBUTE_TYPE) PkcsError![]u8 {
        return switch (attribute_type) {
            pkcs.CKA_CLASS => encodeLong(buffer, self.class),
            pkcs.CKA_TOKEN => encodeBool(buffer, self.token),
            pkcs.CKA_PRIVATE => encodeBool(buffer, self.private),
            pkcs.CKA_MODIFIABLE => encodeBool(buffer, self.modifiable),
            pkcs.CKA_LABEL => encodeByteArray(buffer, self.label),
            pkcs.CKA_COPYABLE => encodeBool(buffer, self.copyable),
            pkcs.CKA_DESTROYABLE => encodeBool(buffer, self.destroyable),
            pkcs.CKA_KEY_TYPE => encodeLong(buffer, self.key_type),
            pkcs.CKA_ID => encodeByteArray(buffer, &self.id),
            pkcs.CKA_START_DATE => encodeDate(buffer, self.start_date),
            pkcs.CKA_END_DATE => encodeDate(buffer, self.end_date),
            pkcs.CKA_DERIVE => encodeBool(buffer, self.derive),
            pkcs.CKA_LOCAL => encodeBool(buffer, self.local),
            pkcs.CKA_KEY_GEN_MECHANISM => encodeLong(buffer, self.key_gen_mechanism),
            // pkcs.CKA_ALLOWED_MECHANISMS => unreachable,
            pkcs.CKA_SUBJECT => encodeByteArray(buffer, self.subject),
            pkcs.CKA_ENCRYPT => encodeBool(buffer, self.encrypt),
            pkcs.CKA_VERIFY => encodeBool(buffer, self.verify),
            pkcs.CKA_VERIFY_RECOVER => encodeBool(buffer, self.verify_recover),
            pkcs.CKA_WRAP => encodeBool(buffer, self.wrap),
            pkcs.CKA_TRUSTED => encodeBool(buffer, self.trusted),
            // pkcs.CKA_WRAP_TEMPLATE => unreachable,
            pkcs.CKA_PUBLIC_KEY_INFO => encodeByteArray(buffer, self.public_key_info),
            pkcs.CKA_MODULUS => encodeByteArray(buffer, self.modulus),
            pkcs.CKA_MODULUS_BITS => encodeLong(buffer, self.modulus_bits),
            pkcs.CKA_PUBLIC_EXPONENT => encodeByteArray(buffer, self.public_exponent),
            else => PkcsError.AttributeTypeInvalid,
        };
    }

    pub fn getAttributeSize(self: *const PublicKeyObject, attribute_type: pkcs.CK_ATTRIBUTE_TYPE) PkcsError!usize {
        return switch (attribute_type) {
            pkcs.CKA_CLASS => @sizeOf(pkcs.CK_ULONG),
            pkcs.CKA_TOKEN => @sizeOf(pkcs.CK_BBOOL),
            pkcs.CKA_PRIVATE => @sizeOf(pkcs.CK_BBOOL),
            pkcs.CKA_MODIFIABLE => @sizeOf(pkcs.CK_BBOOL),
            pkcs.CKA_LABEL => self.label.len,
            pkcs.CKA_COPYABLE => @sizeOf(pkcs.CK_BBOOL),
            pkcs.CKA_DESTROYABLE => @sizeOf(pkcs.CK_BBOOL),
            pkcs.CKA_KEY_TYPE => @sizeOf(pkcs.CK_ULONG),
            pkcs.CKA_ID => self.id.len,
            pkcs.CKA_START_DATE => @sizeOf(pkcs.CK_DATE),
            pkcs.CKA_END_DATE => @sizeOf(pkcs.CK_DATE),
            pkcs.CKA_DERIVE => @sizeOf(pkcs.CK_BBOOL),
            pkcs.CKA_LOCAL => @sizeOf(pkcs.CK_BBOOL),
            pkcs.CKA_KEY_GEN_MECHANISM => @sizeOf(pkcs.CK_ULONG),
            // pkcs.CKA_ALLOWED_MECHANISMS => unreachable,
            pkcs.CKA_SUBJECT => self.subject.len,
            pkcs.CKA_ENCRYPT => @sizeOf(pkcs.CK_BBOOL),
            pkcs.CKA_VERIFY => @sizeOf(pkcs.CK_BBOOL),
            pkcs.CKA_VERIFY_RECOVER => @sizeOf(pkcs.CK_BBOOL),
            pkcs.CKA_WRAP => @sizeOf(pkcs.CK_BBOOL),
            pkcs.CKA_TRUSTED => @sizeOf(pkcs.CK_BBOOL),
            // pkcs.CKA_WRAP_TEMPLATE => unreachable,
            pkcs.CKA_PUBLIC_KEY_INFO => self.public_key_info.len,
            pkcs.CKA_MODULUS => self.modulus.len,
            pkcs.CKA_MODULUS_BITS => @sizeOf(pkcs.CK_ULONG),
            pkcs.CKA_PUBLIC_EXPONENT => self.public_exponent.len,
            else => PkcsError.AttributeTypeInvalid,
        };
    }

    pub fn createPublicKeyObject(
        allocator: std.mem.Allocator,
        public_key_file: PublicKeyFile,
        public_key_handle: pkcs.CK_OBJECT_HANDLE,
    ) PkcsError!PublicKeyObject {
        const public_key_label = try allocEmptySlice(u8, allocator);
        errdefer allocator.free(public_key_label);
        const public_key_subject = try allocEmptySlice(u8, allocator);
        errdefer allocator.free(public_key_subject);
        const public_key_modulus = try clone(allocator, public_key_file.modulus[0..public_key_file.modulus_len]);
        errdefer allocator.free(public_key_modulus);
        const pub_public_exponent = try clone(allocator, public_key_file.exponent[0..public_key_file.exponent_len]);
        errdefer allocator.free(pub_public_exponent);

        // invalid on original token
        const pub_public_key_info = try allocEmptySlice(u8, allocator);
        errdefer allocator.free(pub_public_key_info);
        const public_allowed_mechanisms: []pkcs.CK_MECHANISM_TYPE = try allocEmptySlice(pkcs.CK_MECHANISM_TYPE, allocator);
        errdefer allocator.free(public_allowed_mechanisms);
        const wrap_template: []pkcs.CK_ATTRIBUTE = try allocEmptySlice(pkcs.CK_ATTRIBUTE, allocator);
        errdefer allocator.free(wrap_template);

        return .{
            .file_name = public_key_file.pub_key_file_name,
            .handle = public_key_handle,
            .class = pkcs.CKO_PUBLIC_KEY,
            .token = pkcs.CK_TRUE,
            .private = pkcs.CK_FALSE,
            .modifiable = pkcs.CK_TRUE,
            .label = public_key_label,
            .copyable = pkcs.CK_FALSE, // invalid on original token
            .destroyable = pkcs.CK_FALSE, // invalid on original token
            .key_type = pkcs.CKK_RSA,
            .id = public_key_file.id,
            .start_date = pkcs.CK_DATE{},
            .end_date = pkcs.CK_DATE{},
            .derive = pkcs.CK_FALSE,
            .local = pkcs.CK_TRUE,
            .key_gen_mechanism = 0, // invalid on original token
            .allowed_mechanisms = public_allowed_mechanisms,
            .subject = public_key_subject,
            .encrypt = if (public_key_file.allow_encrypt) pkcs.CK_TRUE else pkcs.CK_FALSE,
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
    }
};

pub fn deinitSearchTemplate(allocator: std.mem.Allocator, search_template: []Attribute) void {
    if (search_template.len == 0)
        return;

    for (search_template) |*attr|
        attr.deinit(allocator);

    allocator.free(search_template);
}

fn encodeBool(buff: []u8, value: pkcs.CK_BBOOL) PkcsError![]u8 {
    if (buff.len < @sizeOf(pkcs.CK_BBOOL))
        return PkcsError.HostMemory;

    const src: *const [@sizeOf(pkcs.CK_BBOOL)]u8 = @ptrCast(&value);
    @memcpy(buff[0..src.len], src);

    return buff[0..src.len];
}

fn encodeLong(buff: []u8, value: pkcs.CK_ULONG) PkcsError![]u8 {
    if (buff.len < @sizeOf(pkcs.CK_ULONG))
        return PkcsError.HostMemory;

    const src: *const [@sizeOf(pkcs.CK_ULONG)]u8 = @ptrCast(&value);
    @memcpy(buff[0..src.len], src);

    return buff[0..src.len];
}

fn encodeByteArray(buff: []u8, value: []const u8) PkcsError![]u8 {
    if (buff.len < value.len)
        return PkcsError.HostMemory;

    @memcpy(buff[0..value.len], value);

    return buff[0..value.len];
}

fn encodeDate(buff: []u8, value: pkcs.CK_DATE) PkcsError![]u8 {
    if (buff.len < @sizeOf(pkcs.CK_DATE))
        return PkcsError.HostMemory;

    const src: *const [@sizeOf(pkcs.CK_DATE)]u8 = @ptrCast(&value);
    @memcpy(buff[0..src.len], src);

    return buff[0..src.len];
}

fn encodeMechanismTypeList(allocator: std.mem.Allocator, value: []const pkcs.CK_MECHANISM_TYPE) PkcsError![]u8 {
    const buff = allocator.alloc(u8, value.len * @sizeOf(pkcs.CK_MECHANISM_TYPE)) catch
        return PkcsError.HostMemory;

    return buff;
}

fn allocEmptySlice(comptime T: type, allocator: std.mem.Allocator) PkcsError![]T {
    return allocator.alloc(T, 0) catch
        return PkcsError.HostMemory;
}

fn clone(allocator: std.mem.Allocator, src: []const u8) PkcsError![]u8 {
    return allocator.dupe(u8, src) catch
        return PkcsError.HostMemory;
}
