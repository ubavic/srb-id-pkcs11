# PKCS#11 module for Serbian ID

This is an open source [PKCS#11 v2.40](https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html) module for Serbian eID smart cards and Privredna Komora Srbije smart cards. This software supports the functionality required for authenticating and signing in to official state portals (like [eUprava](https://euprava.gov.rs/) or [ePorezi](https://eporezi.purs.gov.rs/user/login.html)). PKCS#11 modules, like this one, are called *middleware* in some documentation.

For reading document data from Serbian ID cards, check the [Baš Čelik](https://github.com/ubavic/bas-celik) software.

## Project status

The module should support all use cases of MUP certificates for end users.

The module supports the `CKM_MD5`, `CKM_SHA_1`, `CKM_SHA256`, `CKM_SHA384`, `CKM_SHA512` and `CKM_RIPEMD160` digest algorithms (implemented in software, as it is in the original module).
A random number generator is implemented on the token itself.
Signing and verification are supported for the `CKM_RSA_PKCS`, `CKM_MD5_RSA_PKCS`, `CKM_SHA1_RSA_PKCS`, `CKM_SHA256_RSA_PKCS`, `CKM_SHA384_RSA_PKCS`, `CKM_SHA512_RSA_PKCS` and `CKM_RIPEMD160_RSA_PKCS` mechanisms.
Encryption and decryption are implemented via `CKM_RSA_X_509` and `CKM_RSA_PKCS`.
General session and token management functions are implemented.

Functions intended for security officers (`CKU_SO`) are not planned for implementation at this stage. They are not required for end users, and omitting them reduces code complexity.

## Usage

This module is used like any other PKCS#11 module. Read your software’s documentation to learn how to configure the module. In most cases, you need to add an entry to the *module database* or set module's path in some config. Sometimes there is a GUI for that; other times, you must do it via the CLI. 

Refer to [e-documents howto](https://e-documents.ubavic.rs) (on serbian) for step by step instructions for different use-cases. Below are given general instructions.

### On Linux

To use this module, you need to have the `pcscd` service enabled, and the `ccid` driver installed.

Download the latest `.so` file from [Releases](https://github.com/ubavic/srb-id-pkcs11/releases) and copy it to a permanent location (for example: `/usr/lib/` or `~/lib/`).

On some distros, `p11-kit` is a recommended way of managing modules. This higher-level utility removes the need to configure modules separately for each program. Refer to the distribution documentation for more information.

### On macOS

Download the latest `.dylib` file from [Releases](https://github.com/ubavic/srb-id-pkcs11/releases) and copy it to a permanent location. Only builds for ARM macs are provided, for Intel macs you will have to compile the project yourself (see below).

If your system’s security settings prevent downloaded `.dylib` files from executing, refer to Apple’s [official documentation](https://support.apple.com/guide/mac-help/open-a-mac-app-from-an-unknown-developer-mh40616/mac) for instructions on enabling the use of unsigned libraries. Alternatively, you may install Zig and build the project locally.

## Compilation

Build the project with:

```bash
zig build
```

### Building on Linux

Ensure that the [PCSC Lite](https://pcsclite.apdu.fr/) (development) library (`libpcsclite.so`) is installed on your system. Most Linux package managers provide this package. Also install `ccid` driver, and enable `pcscd` service.

## Architecture

Code is organized in four layers:

1. `src/module.zig` contains all exported Cryptoki functions. Each exported function is a thin wrapper that passes `*ModuleState` and maps the error union to `CK_RV`.
2. `src/p11_*.zig` files contain the functions called from those wrappers. Functions at this level implement the Cryptoki logic.
3. `src/session/*.zig` contains the implementation of Cryptoki concepts (session, operation, object).
4. `src/smart-card/*.zig` contains the logic for communication with the tokens via PC/SC.

## Warranty Disclaimer

This software is provided *as is*, without any warranty of any kind. Use of this module is at your own risk, and it may potentially damage your token.

## License

The code is released under the [Unlicense](LICENSE). You are free to do whatever you want with the code.
