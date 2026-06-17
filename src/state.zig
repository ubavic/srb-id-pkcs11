const std = @import("std");
const pcsc = @import("pcsc");

pub var lock = std.Io.RwLock.init;

pub var initialized: bool = false;
pub var smart_card_client: pcsc.Client = undefined;

pub const allocator: std.mem.Allocator = std.heap.page_allocator;

pub var threaded: std.Io.Threaded = std.Io.Threaded.init_single_threaded;
pub var io = threaded.io();
