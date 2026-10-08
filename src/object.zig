const std = @import("std");

const pkcs = @import("pkcs.zig");
const PkcsError = @import("pkcs_error.zig").PkcsError;

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

        std.crypto.secureZero(c_ulong, self.allowed_mechanisms);
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

        std.crypto.secureZero(c_ulong, self.allowed_mechanisms);
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
};

pub const Attribute = struct {
    attribute_type: pkcs.CK_ATTRIBUTE_TYPE,
    value: []const u8,

    pub fn deinit(self: *const Attribute, allocator: std.mem.Allocator) void {
        allocator.free(self.value);
    }
};

pub fn parseAttributes(
    allocator: std.mem.Allocator,
    template: []pkcs.CK_ATTRIBUTE,
) PkcsError![]Attribute {
    var search_template = std.ArrayList(Attribute).initCapacity(allocator, template.len) catch
        return PkcsError.HostMemory;
    errdefer search_template.deinit(allocator);

    for (template) |attribute| {
        const parsed_attribute = try parseAttribute(allocator, attribute);
        errdefer parsed_attribute.deinit(allocator);

        search_template.append(allocator, parsed_attribute) catch
            return PkcsError.HostMemory;
    }

    const slice = search_template.toOwnedSlice(allocator) catch
        return PkcsError.HostMemory;

    return slice;
}

pub fn parseAttribute(
    allocator: std.mem.Allocator,
    attribute: pkcs.CK_ATTRIBUTE,
) PkcsError!Attribute {
    if (attribute.pValue == null and attribute.ulValueLen != 0)
        return PkcsError.ArgumentsBad;

    const value = allocator.alloc(u8, attribute.ulValueLen) catch
        return PkcsError.HostMemory;

    if (attribute.ulValueLen > 0) {
        const src: [*c]u8 = @ptrCast(attribute.pValue.?);
        std.mem.copyForwards(u8, value, src[0..attribute.ulValueLen]);
    }

    return Attribute{
        .attribute_type = attribute.type,
        .value = value,
    };
}

pub fn deinitSearchTemplate(allocator: std.mem.Allocator, search_template: []Attribute) void {
    if (search_template.len == 0)
        return;

    for (search_template) |*attr|
        attr.deinit(allocator);

    allocator.free(search_template);
}

pub fn encodeBool(buff: []u8, value: pkcs.CK_BBOOL) PkcsError![]u8 {
    if (buff.len < @sizeOf(pkcs.CK_BBOOL))
        return PkcsError.HostMemory;

    const src: *const [@sizeOf(pkcs.CK_BBOOL)]u8 = @ptrCast(&value);
    @memcpy(buff[0..src.len], src);

    return buff[0..src.len];
}

pub fn encodeLong(buff: []u8, value: pkcs.CK_ULONG) PkcsError![]u8 {
    if (buff.len < @sizeOf(pkcs.CK_ULONG))
        return PkcsError.HostMemory;

    const src: *const [@sizeOf(pkcs.CK_ULONG)]u8 = @ptrCast(&value);
    @memcpy(buff[0..src.len], src);

    return buff[0..src.len];
}

pub fn encodeByteArray(buff: []u8, value: []const u8) PkcsError![]u8 {
    if (buff.len < value.len)
        return PkcsError.HostMemory;

    @memcpy(buff[0..value.len], value);

    return buff[0..value.len];
}

pub fn encodeDate(buff: []u8, value: pkcs.CK_DATE) PkcsError![]u8 {
    if (buff.len < @sizeOf(pkcs.CK_DATE))
        return PkcsError.HostMemory;

    const src: *const [@sizeOf(pkcs.CK_DATE)]u8 = @ptrCast(&value);
    @memcpy(buff[0..src.len], src);

    return buff[0..src.len];
}

pub fn encodeMechanismTypeList(allocator: std.mem.Allocator, value: []const pkcs.CK_MECHANISM_TYPE) PkcsError![]u8 {
    const buff = allocator.alloc(u8, value.len * @sizeOf(pkcs.CK_MECHANISM_TYPE)) catch
        return PkcsError.HostMemory;

    return buff;
}
