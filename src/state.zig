const std = @import("std");
const pcsc = @import("pcsc");

pub var lock = std.Thread.RwLock{};

pub var initialized: bool = false;
pub var smart_card_client: pcsc.Client = undefined;

pub var allocator = std.heap.page_allocator;
