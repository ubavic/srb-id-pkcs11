const pkcs = @cImport({
    @cInclude("pkcs.h");
});

pub export fn C_GetFunctionStatus(_: pkcs.CK_SESSION_HANDLE) pkcs.CK_RV {
    return pkcs.CKR_FUNCTION_NOT_PARALLEL;
}

pub export fn C_CancelFunction(_: pkcs.CK_SESSION_HANDLE) pkcs.CK_RV {
    return pkcs.CKR_FUNCTION_NOT_PARALLEL;
}
