const std = @import("std");

pub const max_id_len: usize = 32;

pub const Credential = struct {
    id_buf: [max_id_len]u8 = undefined,
    id_len: usize = 0,
    cert_file: [2]u8 = undefined,
    card_id: u8 = 0,
    has_cert: bool = false,
    has_key: bool = false,

    pub fn id(self: *const Credential) []const u8 {
        return self.id_buf[0..self.id_len];
    }

    pub fn fromDescriptor(data: []const u8) ?Credential {
        if (data.len < 4)
            return null;

        const tag = data[0];
        if (tag != 0x01 and tag != 0x02 and tag != 0x03)
            return null;

        const label_len: usize = data[3];
        const id_len_pos = 4 + label_len;
        if (id_len_pos >= data.len)
            return null;

        const id_len: usize = data[id_len_pos];
        const id_pos = id_len_pos + 1;
        if (id_len == 0 or id_len > max_id_len or id_pos + id_len > data.len)
            return null;

        var cred = Credential{};
        @memcpy(cred.id_buf[0..id_len], data[id_pos .. id_pos + id_len]);
        cred.id_len = id_len;

        switch (tag) {
            0x01 => {
                cred.cert_file = [_]u8{ data[1], data[2] };
                cred.has_cert = true;
            },
            0x03 => {
                cred.card_id = data[2];
                cred.has_key = true;
            },
            else => {},
        }

        return cred;
    }

    pub fn merge(self: *Credential, other: Credential) void {
        if (other.has_cert) {
            self.cert_file = other.cert_file;
            self.has_cert = true;
        }

        if (other.has_key) {
            self.card_id = other.card_id;
            self.has_key = true;
        }
    }
};

test "fromDescriptor parses a certificate descriptor" {
    // tag 0x01, ref 7102, label "ABC", id_len 4, id AABBCCDD, trailing subject.
    const data = [_]u8{ 0x01, 0x71, 0x02, 0x03, 'A', 'B', 'C', 0x04, 0xAA, 0xBB, 0xCC, 0xDD, 0xA9, 0x00 };

    const cred = Credential.fromDescriptor(&data).?;

    try std.testing.expect(cred.has_cert);
    try std.testing.expect(!cred.has_key);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x71, 0x02 }, &cred.cert_file);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xAA, 0xBB, 0xCC, 0xDD }, cred.id());
}

test "fromDescriptor parses a private key descriptor" {
    // tag 0x03, ref 6019 (card id 0x19), empty label, id_len 4, id 11223344.
    const data = [_]u8{ 0x03, 0x60, 0x19, 0x00, 0x04, 0x11, 0x22, 0x33, 0x44, 0x00, 0x01 };

    const cred = Credential.fromDescriptor(&data).?;

    try std.testing.expect(cred.has_key);
    try std.testing.expect(!cred.has_cert);
    try std.testing.expectEqual(@as(u8, 0x19), cred.card_id);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x11, 0x22, 0x33, 0x44 }, cred.id());
}

test "fromDescriptor parses a public key descriptor as id only" {
    // tag 0x02 (public key): id is recorded but neither cert nor key flag is set.
    const data = [_]u8{ 0x02, 0x60, 0x18, 0x00, 0x03, 0xDE, 0xAD, 0xBE, 0x00, 0x01 };

    const cred = Credential.fromDescriptor(&data).?;

    try std.testing.expect(!cred.has_cert);
    try std.testing.expect(!cred.has_key);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xDE, 0xAD, 0xBE }, cred.id());
}

test "fromDescriptor rejects malformed records" {
    // Shorter than the fixed header.
    try std.testing.expect(Credential.fromDescriptor(&[_]u8{ 0x01, 0x71, 0x02 }) == null);
    // Unknown tag.
    try std.testing.expect(Credential.fromDescriptor(&[_]u8{ 0x09, 0x00, 0x00, 0x00, 0x01, 0xAA }) == null);
    // id_len == 0.
    try std.testing.expect(Credential.fromDescriptor(&[_]u8{ 0x03, 0x60, 0x05, 0x00, 0x00 }) == null);
    // label_len points past the end of the record.
    try std.testing.expect(Credential.fromDescriptor(&[_]u8{ 0x03, 0x60, 0x05, 0x40, 0x14 }) == null);
    // id is truncated (declares 4 bytes, only 2 present).
    try std.testing.expect(Credential.fromDescriptor(&[_]u8{ 0x03, 0x60, 0x05, 0x00, 0x04, 0xAA, 0xBB }) == null);
    // id_len exceeds max_id_len.
    try std.testing.expect(Credential.fromDescriptor(&[_]u8{ 0x03, 0x60, 0x05, 0x00, 0x21, 0x00 }) == null);
}

test "merge combines cert and key descriptors" {
    const cert = Credential.fromDescriptor(&[_]u8{ 0x01, 0x71, 0x02, 0x00, 0x03, 0xAA, 0xBB, 0xCC }).?;
    var key = Credential.fromDescriptor(&[_]u8{ 0x03, 0x60, 0x05, 0x00, 0x03, 0xAA, 0xBB, 0xCC }).?;

    key.merge(cert);

    try std.testing.expect(key.has_cert and key.has_key);
    try std.testing.expectEqual(@as(u8, 0x05), key.card_id);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x71, 0x02 }, &key.cert_file);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xAA, 0xBB, 0xCC }, key.id());
}
