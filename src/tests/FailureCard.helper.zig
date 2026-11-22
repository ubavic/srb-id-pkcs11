const std = @import("std");

const HealthyCard = @import("HealthyCard.helper.zig");
const PaddedPin = @import("../smart-card/PaddedPin.zig");

/// Card that fails after N successful calls, useful for making sure
/// smart card errors are handled correctly.
pub fn FailureCard(comptime Parent: type) type {
    return struct {
        const Self = @This();

        parent: Parent,
        call_index: usize,
        fail_index: usize,
        err: Error,
        has_induced_failure: bool,

        pub const Error = error{
            DeviceError,
            DeviceRemoved,
            GeneralError,
            HostMemory,
        };

        pub const Config = struct {
            fail_index: usize = std.math.maxInt(usize),
            err: Error = error.DeviceError,
        };

        pub fn init(parent: Parent, config: Config) Self {
            return .{
                .parent = parent,
                .call_index = 0,
                .fail_index = config.fail_index,
                .err = config.err,
                .has_induced_failure = false,
            };
        }

        fn shouldFail(self: *Self) bool {
            if (self.call_index == self.fail_index) {
                self.has_induced_failure = true;
                return true;
            }

            self.call_index += 1;
            return false;
        }

        pub fn readFile(self: *Self, allocator: std.mem.Allocator, file_name: []const u8) ![]u8 {
            if (self.shouldFail()) return self.err;
            return self.parent.readFile(allocator, file_name);
        }

        pub fn readTokenInfo(self: *Self, allocator: std.mem.Allocator) !@TypeOf(self.parent.readTokenInfo(allocator) catch unreachable) {
            if (self.shouldFail()) return self.err;
            return self.parent.readTokenInfo(allocator);
        }

        pub fn disconnect(self: *Self) !void {
            if (self.shouldFail()) return self.err;
            return self.parent.disconnect();
        }

        pub fn initCrypto(self: *Self, allocator: std.mem.Allocator) !void {
            if (self.shouldFail()) return self.err;
            return self.parent.initCrypto(allocator);
        }

        pub fn startTransaction(self: *Self) !@TypeOf(self.parent.startTransaction() catch unreachable) {
            if (self.shouldFail()) return self.err;
            return self.parent.startTransaction();
        }

        pub fn endTransaction(self: *Self, tx: anytype) void {
            self.parent.endTransaction(tx);
        }

        pub fn readRandom(self: *Self, allocator: std.mem.Allocator, length: u8, out_buffer: []u8) ![]const u8 {
            if (self.shouldFail()) return self.err;
            return self.parent.readRandom(allocator, length, out_buffer);
        }

        pub fn verifyPin(self: *Self, allocator: std.mem.Allocator, pin: *const PaddedPin) !void {
            if (self.shouldFail()) return self.err;
            return self.parent.verifyPin(allocator, pin);
        }

        pub fn setPin(self: *Self, allocator: std.mem.Allocator, old_pin: *const PaddedPin, new_pin: *const PaddedPin) !void {
            if (self.shouldFail()) return self.err;
            return self.parent.setPin(allocator, old_pin, new_pin);
        }

        pub fn sign(self: *Self, allocator: std.mem.Allocator, key_file_name: [2]u8, plain_sign: bool, sign_request: []u8) ![]u8 {
            if (self.shouldFail()) return self.err;
            return self.parent.sign(allocator, key_file_name, plain_sign, sign_request);
        }

        pub fn decrypt(self: *Self, allocator: std.mem.Allocator, key_file_name: [2]u8, decrypt_request: []u8) ![]u8 {
            if (self.shouldFail()) return self.err;
            return self.parent.decrypt(allocator, key_file_name, decrypt_request);
        }
    };
}
