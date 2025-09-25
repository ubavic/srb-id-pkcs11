const pkcs = @import("pkcs.zig").pkcs;
const PkcsError = @import("pkcs_error.zig").PkcsError;

pub const ObjectConstants = struct {
    certificate_handle: pkcs.CK_OBJECT_HANDLE,
    private_key_handle: pkcs.CK_OBJECT_HANDLE,
    private_key_card_id: u8,
    public_key_handle: pkcs.CK_OBJECT_HANDLE,
};

pub const AuthCert = ObjectConstants{
    .certificate_handle = 0x80000028,
    .private_key_handle = 0x80000010,
    .private_key_card_id = 0x5,
    .public_key_handle = 0x80000008,
};

pub const SignCert = ObjectConstants{
    .certificate_handle = 0x80000030,
    .private_key_handle = 0x80000020,
    .private_key_card_id = 0x19,
    .public_key_handle = 0x80000018,
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
