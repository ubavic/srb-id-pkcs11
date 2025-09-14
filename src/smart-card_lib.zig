const builtin = @import("builtin");

pub const sc = switch (builtin.target.os.tag) {
    .windows => @cImport({
        @cInclude("winscard.h");
    }),
    .macos => @cImport({
        @cInclude("winscard.h");
        @cInclude("wintypes.h");
    }),
    .linux => @cImport({
        @cInclude("pcsclite.h");
        @cInclude("winscard.h");
        @cInclude("wintypes.h");
    }),
    else => unreachable,
};
