const std = @import("std");

const pkcs = @cImport({
    @cInclude("pkcs.h");
});

const pcsc = @cImport({
    @cInclude("pcsclite.h");
    @cInclude("winscard.h");
    @cInclude("wintypes.h");
});

pub var lock = std.Thread.RwLock{};

pub var initialized: bool = false;
pub var smart_card_context_handle: pcsc.SCARDHANDLE = 0;

pub var allocator = std.heap.page_allocator;
