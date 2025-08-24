const std = @import("std");

const pkcs = @cImport({
    @cInclude("pkcs.h");
});

const pkcs_error = @import("pkcs_error.zig");

const PkcsError = pkcs_error.PkcsError;

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

    pub fn getAttribute(self: *const Object, allocator: std.mem.Allocator, attribute_type: pkcs.CK_ATTRIBUTE_TYPE) PkcsError!Attribute {
        const value = try switch (self.*) {
            .certificate => |o| o.getAttributeValue(allocator, attribute_type),
            .private_key => |o| o.getAttributeValue(allocator, attribute_type),
            .public_key => |o| o.getAttributeValue(allocator, attribute_type),
        };

        return Attribute{
            .attribute_type = attribute_type,
            .value = value,
        };
    }

    pub fn hasAttributeValue(self: *const Object, allocator: std.mem.Allocator, attribute: Attribute) PkcsError!bool {
        const object_attribute = try self.getAttribute(allocator, attribute.attribute_type);
        defer object_attribute.deinit(allocator);

        return std.mem.eql(u8, object_attribute.value, attribute.value);
    }

    pub fn deinit(self: *const Object, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .certificate => |o| o.deinit(allocator),
            .private_key => |o| o.deinit(allocator),
            .public_key => |o| o.deinit(allocator),
        }
    }
};

pub const CertificateObject = struct {
    handle: pkcs.CK_OBJECT_HANDLE,
    class: pkcs.CK_OBJECT_CLASS,
    token: pkcs.CK_BBOOL,
    private: pkcs.CK_BBOOL,
    modifiable: pkcs.CK_BBOOL,
    label: []const u8,
    copyable: pkcs.CK_BBOOL,
    destroyable: pkcs.CK_BBOOL,
    certificate_type: pkcs.CK_CERTIFICATE_TYPE,
    trusted: pkcs.CK_BBOOL,
    certificate_category: pkcs.CK_CERTIFICATE_CATEGORY,
    check_value: []const u8,
    start_date: pkcs.CK_DATE,
    end_date: pkcs.CK_DATE,
    public_key_info: []const u8,
    subject: []const u8,
    id: []const u8,
    issuer: []const u8,
    serial_number: []const u8,
    value: []const u8,
    url: []const u8,
    hash_of_subject_public_key: []const u8,
    name_hash_algorithm: pkcs.CK_MECHANISM_TYPE,

    pub fn deinit(self: *Attribute, allocator: std.mem.Allocator) void {
        allocator.free(self.label);
        allocator.free(self.check_value);
        allocator.free(self.public_key_info);
        allocator.free(self.subject);
        allocator.free(self.id);
        allocator.free(self.issuer);
        allocator.free(self.serial_number);
        allocator.free(self.value);
        allocator.free(self.url);
        allocator.free(self.hash_of_subject_public_key);
    }

    pub fn getAttributeValue(self: *const CertificateObject, allocator: std.mem.Allocator, attribute_type: pkcs.CK_ATTRIBUTE_TYPE) PkcsError![]u8 {
        return switch (attribute_type) {
            pkcs.CKA_CLASS => encodeLong(allocator, self.class),
            pkcs.CKA_TOKEN => encodeBool(allocator, self.token),
            pkcs.CKA_PRIVATE => encodeBool(allocator, self.private),
            pkcs.CKA_MODIFIABLE => encodeBool(allocator, self.modifiable),
            pkcs.CKA_LABEL => encodeByteArray(allocator, self.label),
            pkcs.CKA_COPYABLE => encodeBool(allocator, self.copyable),
            pkcs.CKA_DESTROYABLE => encodeBool(allocator, self.destroyable),
            pkcs.CKA_CERTIFICATE_TYPE => encodeLong(allocator, self.certificate_type),
            pkcs.CKA_TRUSTED => encodeBool(allocator, self.trusted),
            pkcs.CKA_CERTIFICATE_CATEGORY => encodeLong(allocator, self.certificate_category),
            pkcs.CKA_CHECK_VALUE => encodeByteArray(allocator, self.check_value),
            pkcs.CKA_START_DATE => encodeDate(allocator, self.start_date),
            pkcs.CKA_END_DATE => encodeDate(allocator, self.end_date),
            pkcs.CKA_PUBLIC_KEY_INFO => encodeByteArray(allocator, self.public_key_info),
            pkcs.CKA_SUBJECT => encodeByteArray(allocator, self.subject),
            pkcs.CKA_ID => encodeByteArray(allocator, self.id),
            pkcs.CKA_ISSUER => encodeByteArray(allocator, self.issuer),
            pkcs.CKA_SERIAL_NUMBER => encodeByteArray(allocator, self.serial_number),
            pkcs.CKA_VALUE => encodeByteArray(allocator, self.value),
            pkcs.CKA_URL => encodeByteArray(allocator, self.url),
            pkcs.CKA_HASH_OF_SUBJECT_PUBLIC_KEY => encodeByteArray(allocator, self.hash_of_subject_public_key),
            pkcs.CKA_NAME_HASH_ALGORITHM => encodeLong(allocator, self.name_hash_algorithm),
            else => PkcsError.AttributeTypeInvalid,
        };
    }
};

pub const PrivateKeyObject = struct {
    handle: pkcs.CK_OBJECT_HANDLE,
    class: pkcs.CK_OBJECT_CLASS,
    token: pkcs.CK_BBOOL,
    private: pkcs.CK_BBOOL,
    modifiable: pkcs.CK_BBOOL,
    label: []const u8,
    copyable: pkcs.CK_BBOOL,
    destroyable: pkcs.CK_BBOOL,
    key_type: pkcs.CK_KEY_TYPE,
    id: []const u8,
    start_date: pkcs.CK_DATE,
    end_date: pkcs.CK_DATE,
    derive: pkcs.CK_BBOOL,
    local: pkcs.CK_BBOOL,
    key_gen_mechanism: pkcs.CK_MECHANISM_TYPE,
    allowed_mechanisms: []const pkcs.CK_MECHANISM_TYPE,
    subject: []const u8,
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
    always_authenticate: []pkcs.CK_ATTRIBUTE,
    public_key_info: []const u8,

    pub fn deinit(self: *Attribute, allocator: std.mem.Allocator) void {
        allocator.free(self.label);
        allocator.free(self.id);
        allocator.free(self.allowed_mechanisms);
        allocator.free(self.subject);
        allocator.free(self.unwrap_template);
        allocator.free(self.always_authenticate);
        allocator.free(self.public_key_info);
    }

    pub fn getAttributeValue(self: *const PrivateKeyObject, allocator: std.mem.Allocator, attribute_type: pkcs.CK_ATTRIBUTE_TYPE) PkcsError![]u8 {
        return switch (attribute_type) {
            pkcs.CKA_CLASS => encodeLong(allocator, self.class),
            pkcs.CKA_TOKEN => encodeBool(allocator, self.token),
            pkcs.CKA_PRIVATE => encodeBool(allocator, self.private),
            pkcs.CKA_MODIFIABLE => encodeBool(allocator, self.modifiable),
            pkcs.CKA_LABEL => encodeByteArray(allocator, self.label),
            pkcs.CKA_COPYABLE => encodeBool(allocator, self.copyable),
            pkcs.CKA_DESTROYABLE => encodeBool(allocator, self.destroyable),
            pkcs.CKA_KEY_TYPE => encodeLong(allocator, self.key_type),
            pkcs.CKA_ID => encodeByteArray(allocator, self.id),
            pkcs.CKA_START_DATE => encodeDate(allocator, self.start_date),
            pkcs.CKA_END_DATE => encodeDate(allocator, self.end_date),
            pkcs.CKA_DERIVE => encodeBool(allocator, self.derive),
            pkcs.CKA_LOCAL => encodeBool(allocator, self.local),
            pkcs.CKA_KEY_GEN_MECHANISM => encodeLong(allocator, self.key_gen_mechanism),
            pkcs.CKA_ALLOWED_MECHANISMS => unreachable,
            pkcs.CKA_SUBJECT => encodeByteArray(allocator, self.subject),
            pkcs.CKA_SENSITIVE => encodeBool(allocator, self.sensitive),
            pkcs.CKA_DECRYPT => encodeBool(allocator, self.decrypt),
            pkcs.CKA_SIGN => encodeBool(allocator, self.sign),
            pkcs.CKA_SIGN_RECOVER => encodeBool(allocator, self.sign_recover),
            pkcs.CKA_UNWRAP => encodeBool(allocator, self.unwrap),
            pkcs.CKA_EXTRACTABLE => encodeBool(allocator, self.extractable),
            pkcs.CKA_ALWAYS_SENSITIVE => encodeBool(allocator, self.always_sensitive),
            pkcs.CKA_NEVER_EXTRACTABLE => encodeBool(allocator, self.never_extractable),
            pkcs.CKA_WRAP_WITH_TRUSTED => encodeBool(allocator, self.wrap_with_trusted),
            pkcs.CKA_UNWRAP_TEMPLATE => unreachable,
            pkcs.CKA_ALWAYS_AUTHENTICATE => unreachable,
            pkcs.CKA_PUBLIC_KEY_INFO => encodeByteArray(allocator, self.public_key_info),
            else => PkcsError.AttributeTypeInvalid,
        };
    }
};

pub const PublicKeyObject = struct {
    handle: pkcs.CK_OBJECT_HANDLE,
    class: pkcs.CK_OBJECT_CLASS,
    token: pkcs.CK_BBOOL,
    private: pkcs.CK_BBOOL,
    modifiable: pkcs.CK_BBOOL,
    label: []const u8,
    copyable: pkcs.CK_BBOOL,
    destroyable: pkcs.CK_BBOOL,
    key_type: pkcs.CK_KEY_TYPE,
    id: []const u8,
    start_date: pkcs.CK_DATE,
    end_date: pkcs.CK_DATE,
    derive: pkcs.CK_BBOOL,
    local: pkcs.CK_BBOOL,
    key_gen_mechanism: pkcs.CK_MECHANISM_TYPE,
    allowed_mechanisms: []const pkcs.CK_MECHANISM_TYPE,
    subject: []const u8,
    encrypt: pkcs.CK_BBOOL,
    verify: pkcs.CK_BBOOL,
    verify_recover: pkcs.CK_BBOOL,
    wrap: pkcs.CK_BBOOL,
    trusted: pkcs.CK_BBOOL,
    wrap_template: []pkcs.CK_ATTRIBUTE,
    public_key_info: []const u8,

    pub fn deinit(self: *Attribute, allocator: std.mem.Allocator) void {
        allocator.free(self.label);
        allocator.free(self.id);
        allocator.free(self.allowed_mechanisms);
        allocator.free(self.subject);
        allocator.free(self.public_key_info);
    }

    pub fn getAttributeValue(self: *const PublicKeyObject, allocator: std.mem.Allocator, attribute_type: pkcs.CK_ATTRIBUTE_TYPE) PkcsError![]u8 {
        return switch (attribute_type) {
            pkcs.CKA_CLASS => encodeLong(allocator, self.class),
            pkcs.CKA_TOKEN => encodeBool(allocator, self.token),
            pkcs.CKA_PRIVATE => encodeBool(allocator, self.private),
            pkcs.CKA_MODIFIABLE => encodeBool(allocator, self.modifiable),
            pkcs.CKA_LABEL => encodeByteArray(allocator, self.label),
            pkcs.CKA_COPYABLE => encodeBool(allocator, self.copyable),
            pkcs.CKA_DESTROYABLE => encodeBool(allocator, self.destroyable),
            pkcs.CKA_KEY_TYPE => encodeLong(allocator, self.key_type),
            pkcs.CKA_ID => encodeByteArray(allocator, self.id),
            pkcs.CKA_START_DATE => encodeDate(allocator, self.start_date),
            pkcs.CKA_END_DATE => encodeDate(allocator, self.end_date),
            pkcs.CKA_DERIVE => encodeBool(allocator, self.derive),
            pkcs.CKA_LOCAL => encodeBool(allocator, self.local),
            pkcs.CKA_KEY_GEN_MECHANISM => encodeLong(allocator, self.key_gen_mechanism),
            pkcs.CKA_ALLOWED_MECHANISMS => unreachable,
            pkcs.CKA_SUBJECT => encodeByteArray(allocator, self.subject),
            pkcs.CKA_ENCRYPT => encodeBool(allocator, self.encrypt),
            pkcs.CKA_VERIFY => encodeBool(allocator, self.verify),
            pkcs.CKA_VERIFY_RECOVER => encodeBool(allocator, self.verify_recover),
            pkcs.CKA_WRAP => encodeBool(allocator, self.wrap),
            pkcs.CKA_TRUSTED => encodeBool(allocator, self.trusted),
            pkcs.CKA_WRAP_TEMPLATE => unreachable,
            pkcs.CKA_PUBLIC_KEY_INFO => encodeByteArray(allocator, self.public_key_info),
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
    errdefer search_template.deinit();

    for (template) |attribute| {
        const parsed_attribute = try parseAttribute(allocator, attribute);
        errdefer parsed_attribute.deinit(allocator);

        search_template.append(parsed_attribute) catch
            return PkcsError.HostMemory;
    }

    const slice = search_template.toOwnedSlice() catch
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

pub fn encodeBool(allocator: std.mem.Allocator, value: pkcs.CK_BBOOL) PkcsError![]u8 {
    const buff = allocator.alloc(u8, @sizeOf(pkcs.CK_BBOOL)) catch
        return PkcsError.HostMemory;

    const src: *const [@sizeOf(pkcs.CK_BBOOL)]u8 = @ptrCast(&value);
    std.mem.copyForwards(u8, buff, src);

    return buff;
}

pub fn encodeLong(allocator: std.mem.Allocator, value: pkcs.CK_ULONG) PkcsError![]u8 {
    const buff = allocator.alloc(u8, @sizeOf(pkcs.CK_ULONG)) catch
        return PkcsError.HostMemory;

    const src: *const [@sizeOf(pkcs.CK_ULONG)]u8 = @ptrCast(&value);
    std.mem.copyForwards(u8, buff, src);

    return buff;
}

pub fn encodeByteArray(allocator: std.mem.Allocator, value: []const u8) PkcsError![]u8 {
    const buff = allocator.alloc(u8, value.len) catch
        return PkcsError.HostMemory;

    std.mem.copyForwards(u8, buff, value);

    return buff;
}

pub fn encodeDate(allocator: std.mem.Allocator, value: pkcs.CK_DATE) PkcsError![]u8 {
    const buff = allocator.alloc(u8, @sizeOf(pkcs.CK_DATE)) catch
        return PkcsError.HostMemory;

    const src: *const [@sizeOf(pkcs.CK_DATE)]u8 = @ptrCast(&value);
    std.mem.copyForwards(u8, buff, src);

    return buff;
}

pub fn encodeMechanismTypeList(allocator: std.mem.Allocator, value: []const pkcs.CK_MECHANISM_TYPE) PkcsError![]u8 {
    const buff = allocator.alloc(u8, value.len * @sizeOf(pkcs.CK_MECHANISM_TYPE)) catch
        return PkcsError.HostMemory;

    return buff;
}
