const pkcs = @import("pkcs.zig").pkcs;
const PkcsError = @import("pkcs_error.zig").PkcsError;

pub const ObjectConstants = struct {
    certificate_handle: pkcs.CK_OBJECT_HANDLE,
    private_key_handle: pkcs.CK_OBJECT_HANDLE,
    private_key_card_id: u8,
    public_key_handle: pkcs.CK_OBJECT_HANDLE,
    id: [20]u8,
};

// ID seems the same on every token.
// Maybe it depends on token generation or CA certificate
// Length suggest it is a sha1 or ripemd160 hash

pub const AuthCert = ObjectConstants{
    .certificate_handle = 0x80000028,
    .private_key_handle = 0x80000010,
    .private_key_card_id = 0x5,
    .public_key_handle = 0x80000008,
    .id = [_]u8{ 0x53, 0x6a, 0x49, 0x02, 0x16, 0x4c, 0xa7, 0xfe, 0xee, 0x30, 0x54, 0xaf, 0xb5, 0x70, 0xae, 0x61, 0x65, 0x1d, 0xc6, 0xc7 },
};

pub const SignCert = ObjectConstants{
    .certificate_handle = 0x80000030,
    .private_key_handle = 0x80000020,
    .private_key_card_id = 0x19,
    .public_key_handle = 0x80000018,
    .id = [_]u8{ 0xea, 0xb9, 0x59, 0x49, 0x75, 0x76, 0xe3, 0x0f, 0xfd, 0xcd, 0x81, 0xb2, 0xaf, 0x0b, 0xd6, 0x6e, 0xad, 0x29, 0xb1, 0xa3 },
};

pub fn getPrivateKeyFormPublicKey(public_key_handle: pkcs.CK_OBJECT_HANDLE) PkcsError!pkcs.CK_OBJECT_HANDLE {
    if (public_key_handle == AuthCert.public_key_handle)
        return AuthCert.private_key_handle;

    if (public_key_handle == SignCert.public_key_handle)
        return SignCert.private_key_handle;

    return PkcsError.KeyHandleInvalid;
}

pub fn getCardIdFormPrivateKey(private_key_handle: pkcs.CK_OBJECT_HANDLE) PkcsError!u8 {
    if (private_key_handle == AuthCert.private_key_handle)
        return AuthCert.private_key_card_id;

    if (private_key_handle == SignCert.private_key_handle)
        return SignCert.private_key_card_id;

    return PkcsError.KeyHandleInvalid;
}
