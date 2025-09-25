const std = @import("std");

const sc = @import("smart-card_lib.zig").sc;
pub var lock = std.Thread.RwLock{};

pub var initialized: bool = false;
pub var smart_card_context_handle: sc.SCARDHANDLE = 0;

pub var allocator = std.heap.page_allocator;
