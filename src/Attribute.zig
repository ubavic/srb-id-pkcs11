const std = @import("std");

const pkcs = @import("pkcs.zig");

pub const Attribute = @This();

attribute_type: pkcs.CK_ATTRIBUTE_TYPE,
value: []const u8,

pub fn deinit(self: *const Attribute, allocator: std.mem.Allocator) void {
    allocator.free(self.value);
}

pub fn parseAttributes(
    allocator: std.mem.Allocator,
    template: []pkcs.CK_ATTRIBUTE,
) ![]Attribute {
    var search_template = std.ArrayList(Attribute).initCapacity(allocator, template.len) catch
        return error.HostMemory;
    errdefer search_template.deinit(allocator);

    for (template) |attribute| {
        const parsed_attribute = try parseAttribute(allocator, attribute);
        errdefer parsed_attribute.deinit(allocator);

        search_template.append(allocator, parsed_attribute) catch
            return error.HostMemory;
    }

    const slice = search_template.toOwnedSlice(allocator) catch
        return error.HostMemory;

    return slice;
}

pub fn parseAttribute(
    allocator: std.mem.Allocator,
    attribute: pkcs.CK_ATTRIBUTE,
) !Attribute {
    if (attribute.pValue == null and attribute.ulValueLen != 0)
        return error.ArgumentsBad;

    const value = allocator.alloc(u8, attribute.ulValueLen) catch
        return error.HostMemory;

    if (attribute.ulValueLen > 0) {
        const src: [*c]u8 = @ptrCast(attribute.pValue.?);
        std.mem.copyForwards(u8, value, src[0..attribute.ulValueLen]);
    }

    return Attribute{
        .attribute_type = attribute.type,
        .value = value,
    };
}
