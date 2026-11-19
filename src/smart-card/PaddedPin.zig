const std = @import("std");

const PaddedPin = @This();

buffer: [8]u8,

pub fn construct(pin_slice: []const u8) !PaddedPin {
    if (pin_slice.len < 4 or pin_slice.len > 8)
        return error.PinLenRange;

    for (pin_slice) |p| {
        if (p < '0' or p > '9')
            return error.PinInvalid;
    }

    var new_pin = PaddedPin{
        .buffer = @splat(0x00),
    };

    @memcpy(new_pin.buffer[0..pin_slice.len], pin_slice);

    return new_pin;
}

pub fn slice(self: *const PaddedPin) []const u8 {
    return &self.buffer;
}
