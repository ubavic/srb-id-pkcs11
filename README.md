# PKCS11 module for Serbian ID

This is open source [PKCS11 v2.40](https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html) module for Serbian ID smart cards. It is designed for smart cards produced by Gemalto and aims to support the functionality required for authenticating and signing into official state portals (like [eUprava](https://euprava.gov.rs/) or [ePorezi](https://eporezi.purs.gov.rs/user/login.html)).

## Status

Тhe module is currently in an early development phase. Digest functions are implemented (except RIPEMD160), session and token management functions are generally implemented. Signing and verification are next goals.

Functions intended for security officers (`CKU_SO`) are not planned for implementation at this stage. They are not required for end users, and omitting them reduces the code complexity.

## Compilation

First, download PKCS11 headers:

```bash
OASIS_URL="https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/include/pkcs11-v2.40"
curl --output include/pkcs11.h $(OASIS_URL)/pkcs11.h
curl --output include/pkcs11f.h $(OASIS_URL)/pkcs11f.h
curl --output include/pkcs11t.h $(OASIS_URL)/pkcs11t.h
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
