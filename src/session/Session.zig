const std = @import("std");

const Index = @import("../smart-card/Index.zig");
const MetaFile = @import("../smart-card/MetaFile.zig");
const object = @import("object.zig");
const operations = @import("operation.zig");
const PaddedPin = @import("../smart-card/PaddedPin.zig");
const pkcs = @import("../pkcs.zig");
const PublicKeyFile = @import("../smart-card/PublicKeyFile.zig");
const reader = @import("../smart-card/reader.zig");

pub fn Session(comptime Card: type) type {
    return struct {
        const Self = @This();

        allocator: std.mem.Allocator,
        id: pkcs.CK_SESSION_HANDLE,
        card: Card,
        reader_id: pkcs.CK_SLOT_ID,
        closed: bool = false,
        write_enabled: bool,
        operation: operations.Operation,
        objects: []object.Object,

        pub fn setPin(self: *Self, allocator: std.mem.Allocator, io: std.Io, old_pin: *const PaddedPin, new_pin: *const PaddedPin) !void {
            try self.login(io, old_pin);
            try self.card.setPin(allocator, old_pin, new_pin);
        }

        pub fn login(self: *Self, io: std.Io, pin: *const PaddedPin) !void {
            errdefer reader.setUserType(io, self.reader_id, reader.UserType.None);
            try self.card.verifyPin(self.allocator, pin);
            reader.setUserType(io, self.reader_id, reader.UserType.User);
        }

        pub fn logout(self: *Self, io: std.Io) void {
            reader.setUserType(io, self.reader_id, reader.UserType.None);
        }

        pub fn loggedIn(self: *Self, io: std.Io) bool {
            return reader.getUserType(io, self.reader_id) != reader.UserType.None;
        }

        pub fn assertNoOperation(self: *Self) !void {
            if (self.operation != .none)
                return error.OperationActive;
        }

        pub fn assertOperation(
            self: *Self,
            comptime kind: std.meta.Tag(operations.Operation),
        ) !*@FieldType(operations.Operation, @tagName(kind)) {
            if (std.meta.activeTag(self.operation) != kind)
                return error.OperationNotInitialized;

            return &@field(self.operation, @tagName(kind));
        }

        pub fn resetOperation(self: *Self) void {
            self.operation.deinit(self.allocator);
            self.operation = .none;
        }

        pub fn getObject(self: *Self, io: std.Io, object_handle: pkcs.CK_OBJECT_HANDLE) !*object.Object {
            for (self.objects) |*current_object| {
                if (current_object.private() and !self.loggedIn(io))
                    continue;

                if (current_object.handle() == object_handle)
                    return current_object;
            }

            return error.ObjectHandleInvalid;
        }

        pub fn loadObjects(
            self: *Self,
            allocator: std.mem.Allocator,
        ) !void {
            const tx = try self.card.startTransaction();
            defer self.card.endTransaction(tx);

            const index_content = try self.card.readFile(allocator, &.{ 0x8F, 0xFF });
            defer allocator.free(index_content.data);

            var index = try Index.init(index_content.data);

            var object_list = std.ArrayList(object.Object).initCapacity(allocator, index.length) catch
                return error.HostMemory;
            errdefer {
                for (object_list.items) |*current_object|
                    current_object.deinit(allocator);
                object_list.deinit(allocator);
            }

            var handle: pkcs.CK_OBJECT_HANDLE = 0x80000000;
            while (index.next()) |meta_file_name| {
                const meta_file_content = try self.card.readFile(allocator, &meta_file_name);
                defer allocator.free(meta_file_content.data);

                const meta_file = try MetaFile.parse(meta_file_content.data);

                switch (meta_file.class) {
                    0x01 => {
                        const compressed_certificate_content = try self.card.readFile(allocator, &meta_file.file_name);
                        defer allocator.free(compressed_certificate_content.data);

                        const certificate_data = try object.CertificateObject.decompressCertificate(allocator, compressed_certificate_content.data);
                        defer allocator.free(certificate_data);

                        const cert_object = object.CertificateObject.parse(
                            allocator,
                            handle,
                            certificate_data,
                            meta_file.id,
                            meta_file.file_name,
                            compressed_certificate_content.size,
                        ) catch
                            continue;

                        object_list.append(allocator, .{ .certificate = cert_object }) catch
                            return error.HostMemory;

                        handle += 8;
                    },
                    0x02 => {
                        const pub_key_file_content = try self.card.readFile(allocator, &meta_file.file_name);
                        defer allocator.free(pub_key_file_content.data);

                        var pub_key_file = PublicKeyFile{
                            .id = meta_file.id,
                            .pub_key_file_name = meta_file.file_name,
                        };
                        pub_key_file.parse(pub_key_file_content.data) catch
                            continue;

                        // The private key is fully described by the public key file.
                        // Select its file for the size, and do not read it.
                        const private_key_size = try self.card.getSize(allocator, &pub_key_file.priv_key_file_name);

                        const public_key_object = try object.PublicKeyObject.createPublicKeyObject(allocator, pub_key_file, handle, pub_key_file_content.size);
                        object_list.append(allocator, .{ .public_key = public_key_object }) catch
                            return error.HostMemory;

                        handle += 8;

                        const private_key_object = try object.PrivateKeyObject.createPrivateKeyObject(allocator, pub_key_file, handle, private_key_size);
                        object_list.append(allocator, .{ .private_key = private_key_object }) catch
                            return error.HostMemory;

                        handle += 8;
                    },
                    0x03 => {
                        // private key - we know all things needed from the pub key
                    },
                    else => unreachable,
                }
            }

            self.objects = object_list.toOwnedSlice(allocator) catch
                return error.HostMemory;
        }

        pub fn closeSession(self: *Self, allocator: std.mem.Allocator) !void {
            if (self.closed)
                return error.SessionClosed;

            self.closed = true;
            self.resetOperation();

            for (self.objects) |*o|
                o.deinit(allocator);

            allocator.free(self.objects);
            self.objects = &.{};

            self.card.disconnect() catch {};
        }
    };
}
