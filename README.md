# PKCS#11 module for Serbian ID

This is an open source [PKCS#11 v2.40](https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html) module (middleware) for Serbian ID smart cards. It is designed for smart cards produced by Gemalto and aims to support the functionality required for authenticating and signing in to official state portals (like [eUprava](https://euprava.gov.rs/) or [ePorezi](https://eporezi.purs.gov.rs/user/login.html)).

For reading document data from Serbian ID cards, check the [Baš Čelik](https://github.com/ubavic/bas-celik) software and it's [wiki](https://github.com/ubavic/bas-celik/wiki) (on Serbian).

## Project status

The module supports the `CKM_MD5`, `CKM_SHA_1`, `CKM_SHA256`, `CKM_SHA384`, and `CKM_SHA512` digest algorithms (implemented in software, as it is in the original module). A random number generator is implemented on the token itself. Signing and verification are supported for the `CKM_RSA_PKCS`, `CKM_MD5_RSA_PKCS`, `CKM_SHA1_RSA_PKCS`, `CKM_SHA256_RSA_PKCS`, `CKM_SHA384_RSA_PKCS`, and `CKM_SHA512_RSA_PKCS` mechanisms. General session and token management functions are implemented.

Encryption and decryption are not implemented, since the original module (most likely) does not support these operations.

Functions intended for security officers (`CKU_SO`) are not planned for implementation at this stage. They are not required for end users, and omitting them reduces code complexity.

## Usage on Linux

To use this module, you need to have the `pcscd` service enabled, and the `ccid` driver installed.

Download the latest `.so` file from [Releases](https://github.com/ubavic/srb-id-pkcs11/releases) and copy it to a permanent location (for example: `/usr/lib/` or `~/lib/`).

If you use Firefox, add a new PKCS#11 module using the **Privacy & Security** settings in the browser ([documentation](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/pkcs11)). For the *module filename*, set the path to the `.so` file you just downloaded. After restarting Firefox, you can use the module for signing in on websites.

Chrome does not allow loading a PKCS#11 module through the browser settings. Instead, you must use `modutil` to add a module to the NSS database. This database is most likely located at `~/.pki/nssdb/`. Make sure you don't use `~` in paths, and make sure you close all browsers you have opened. For example:

```bash
modutil -dbdir sql:.pki/nssdb/ -add "Srb Id PKCS11" -libfile PATH_TO_SO
```

After starting Chrome, you will be able to use the module.

## Usage on macOS

Download the latest `.dylib` file from [Releases](https://github.com/ubavic/srb-id-pkcs11/releases) and copy it to a permanent location. There are separate `dylib` files for Intel (x64) and ARM Macs.

In Firefox, add a new PKCS#11 module using the **Privacy & Security** settings in the browser ([documentation](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/pkcs11)). For the *module filename*, set the path to the `.dylib` file you just downloaded. After restarting Firefox, you can use the module for signing in.

If your system’s security settings prevent downloaded `.dylib` files from executing, refer to Apple’s official documentation for instructions on enabling the use of unsigned libraries. Alternatively, you may install Zig and build the project locally.

## Compilation

Build the project with:

```
zig build
```

## Warranty Disclaimer

This software is provided *as is*, without any warranty of any kind. Use of this module is at your own risk, and it may potentially damage your token.

## License

The code is released under the [Unlicense](LICENSE). You are free to do whatever you want with the code.
