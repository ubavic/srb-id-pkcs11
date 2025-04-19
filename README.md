# PKCS11 module for Serbian ID

This is an attempt to provide open source [PKCS11 v2.40](https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html) module for Serbian ID smart cards produced by Gemalto. Module should provide at least functionalities that would enable user to log into state portals (like [eUprava](https://euprava.gov.rs/) ili [ePorezi](https://eporezi.purs.gov.rs/user/login.html)).

## Compilation

First, download PKCS11 headers:

```bash
OASIS_URL="https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/include/pkcs11-v2.40"
curl --output include/pkcs11.h $(OASIS_URL)/pkcs11.h; \
curl --output include/pkcs11f.h $(OASIS_URL)/pkcs11f.h; \
curl --output include/pkcs11t.h $(OASIS_URL)/pkcs11t.h; \
```

Then run `zig build` and you are good to go.

You will maybe need to configure [PCSC lite](https://pcsclite.apdu.fr/) path in `build.zig`.

## Warranty

There is absolutely no warranty of any kind.

## License

The code is released under the [unlicense](LICENSE). You are free to do whatever you want with code.
