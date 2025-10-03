# PKCS11 module for Serbian ID

This is open source [PKCS11 v2.40](https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html) module for Serbian ID smart cards. It is designed for smart cards produced by Gemalto and aims to support the functionality required for authenticating and signing into official state portals (like [eUprava](https://euprava.gov.rs/) or [ePorezi](https://eporezi.purs.gov.rs/user/login.html)).

## Status

The module supports the `CKM_MD5`, `CKM_SHA_1`, `CKM_SHA256`, `CKM_SHA384`, and `CKM_SHA512` digest algorithms (implemented in software, as it is in the original module). A random number generator is implemented on the token. Signing and verification are supported for the `CKM_RSA_PKCS`, `CKM_MD5_RSA_PKCS`, `CKM_SHA1_RSA_PKCS`, `CKM_SHA256_RSA_PKCS`, `CKM_SHA384_RSA_PKCS`, and `CKM_SHA512_RSA_PKCS` mechanisms. General session and token management functions are also implemented.

Encryption and decryption are not implemented, since the original module (most likely) does not support these operations.

Functions intended for security officers (`CKU_SO`) are not planned for implementation at this stage. They are not required for end users, and omitting them reduces code complexity.

## Usage on Linux

To use this module, you need to have the `pcscd` service enabled.

Download the latest `.so` file form [Releases](https://github.com/ubavic/srb-id-pkcs11/releases) and copy it to a permanent location (for example: `/usr/lib/` or `~/lib/`).

If you use Firefox, add a new PKCS#11 module using **Privacy & Security** settings in the browser ([documentation](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/pkcs11)). For the *module filename*, set the path to the `.so` file you just downloaded. After restarting Firefox, you can use the module for signing in on websites.

Chrome does not allow loading a PKCS#11 module through the browser settings. Instead, you must use `modutil` to add module do NSS database. This database is most likely located at `~/.pki/nssdb/`. Make sure you don't use `~` in paths, and make sure you close all browsers you have opened. For example:

```bash
modutil -dbdir sql:.pki/nssdb/ -add "Srb Id PKCS11" -libfile PATH_TO_SO
```

After staring Chrome you will be able to use the module.

## Compilation

First, download PKCS11 headers:

```bash
OASIS_URL="https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/include/pkcs11-v2.40"
curl --output include/pkcs11.h $OASIS_URL/pkcs11.h
curl --output include/pkcs11f.h $OASIS_URL/pkcs11f.h
curl --output include/pkcs11t.h $OASIS_URL/pkcs11t.h
```

Then, build the project with:

```
zig build
```

You will maybe need to configure [PCSC lite](https://pcsclite.apdu.fr/) path in `build.zig`.

## Warranty Disclaimer

This software is provided *as is*, without any warranty of any kind. Use of this module is at your own risk, and it may potentially damage your token.

## License

The code is released under the [unlicense](LICENSE). You are free to do whatever you want with code.
