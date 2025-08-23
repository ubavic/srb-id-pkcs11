const std = @import("std");

const pkcs = @cImport({
    @cInclude("pkcs.h");
});

const pcsc = @cImport({
    @cInclude("pcsclite.h");
    @cInclude("winscard.h");
    @cInclude("wintypes.h");
});

const version = @import("version.zig");
const state = @import("state.zig");
const reader = @import("reader.zig");
const session = @import("session.zig");
const openssl = @import("openssl.zig");

const p11_decryption = @import("p11_decryption.zig");
const p11_digest = @import("p11_digest.zig");
const p11_dual_functions = @import("p11_dual_functions.zig");
const p11_encryption = @import("p11_encryption.zig");
const p11_key_management = @import("p11_key_management.zig");
const p11_object_management = @import("p11_object_management.zig");
const p11_parallel = @import("p11_parallel.zig");
const p11_random = @import("p11_random.zig");
const p11_session = @import("p11_session.zig");
const p11_sign = @import("p11_sign.zig");
const p11_slot_and_token = @import("p11_slot_and_token.zig");

export fn C_Initialize(_: pkcs.CK_VOID_PTR) pkcs.CK_RV {
    if (state.initialized)
        return pkcs.CKR_CRYPTOKI_ALREADY_INITIALIZED;

    const rv = pcsc.SCardEstablishContext(pcsc.SCARD_SCOPE_SYSTEM, null, null, &state.smart_card_context_handle);
    if (rv != pcsc.SCARD_S_SUCCESS)
        return pkcs.CKR_FUNCTION_FAILED;

    reader.reader_states = std.AutoHashMap(pkcs.CK_SLOT_ID, reader.ReaderState).init(state.allocator);
    session.initSessions(state.allocator);

    openssl.init();

    state.initialized = true;
    return pkcs.CKR_OK;
}

export fn C_Finalize(reserved: pkcs.CK_VOID_PTR) pkcs.CK_RV {
    if (reserved != null)
        return pkcs.CKR_ARGUMENTS_BAD;

    if (!state.initialized)
        return pkcs.CKR_CRYPTOKI_NOT_INITIALIZED;

    const rv = pcsc.SCardReleaseContext(state.smart_card_context_handle);
    if (rv != pcsc.SCARD_S_SUCCESS)
        return pkcs.CKR_FUNCTION_FAILED;

    return pkcs.CKR_OK;
}

export fn C_GetInfo(info: ?*pkcs.CK_INFO) pkcs.CK_RV {
    if (!state.initialized)
        return pkcs.CKR_CRYPTOKI_NOT_INITIALIZED;

    if (info == null)
        return pkcs.CKR_ARGUMENTS_BAD;

    info.?.cryptokiVersion.major = pkcs.CRYPTOKI_VERSION_MAJOR;
    info.?.cryptokiVersion.minor = pkcs.CRYPTOKI_VERSION_MINOR;
    info.?.flags = 0;
    info.?.libraryVersion.major = version.major;
    info.?.libraryVersion.minor = version.minor;

    @memset(&info.?.libraryDescription, 0);
    std.mem.copyForwards(u8, &info.?.libraryDescription, "Module for Serbian personal ID");

    @memset(&info.?.manufacturerID, 0);
    std.mem.copyForwards(u8, &info.?.manufacturerID, "Nikola Ubavic");

    return pkcs.CKR_OK;
}

var functionList = pkcs.CK_FUNCTION_LIST{
    .version = pkcs.CK_VERSION{ .major = 0x02, .minor = 0x40 },
    .C_Initialize = C_Initialize,
    .C_Finalize = C_Finalize,
    .C_GetInfo = C_GetInfo,
    .C_GetFunctionList = C_GetFunctionList,
    .C_GetSlotList = p11_slot_and_token.C_GetSlotList,
    .C_GetSlotInfo = p11_slot_and_token.C_GetSlotInfo,
    .C_GetTokenInfo = p11_slot_and_token.C_GetTokenInfo,
    .C_GetMechanismList = p11_slot_and_token.C_GetMechanismList,
    .C_GetMechanismInfo = p11_slot_and_token.C_GetMechanismInfo,
    .C_InitToken = p11_slot_and_token.C_InitToken,
    .C_InitPIN = p11_slot_and_token.C_InitPIN,
    .C_SetPIN = p11_slot_and_token.C_SetPIN,
    .C_OpenSession = p11_session.C_OpenSession,
    .C_CloseSession = p11_session.C_CloseSession,
    .C_CloseAllSessions = p11_session.C_CloseAllSessions,
    .C_GetSessionInfo = p11_session.C_GetSessionInfo,
    .C_GetOperationState = p11_session.C_GetOperationState,
    .C_SetOperationState = p11_session.C_SetOperationState,
    .C_Login = p11_session.C_Login,
    .C_Logout = p11_session.C_Logout,
    .C_CreateObject = p11_object_management.C_CreateObject,
    .C_CopyObject = p11_object_management.C_CopyObject,
    .C_DestroyObject = p11_object_management.C_DestroyObject,
    .C_GetObjectSize = p11_object_management.C_GetObjectSize,
    .C_GetAttributeValue = p11_object_management.C_GetAttributeValue,
    .C_SetAttributeValue = p11_object_management.C_SetAttributeValue,
    .C_FindObjectsInit = p11_object_management.C_FindObjectsInit,
    .C_FindObjects = p11_object_management.C_FindObjects,
    .C_FindObjectsFinal = p11_object_management.C_FindObjectsFinal,
    .C_EncryptInit = p11_encryption.C_EncryptInit,
    .C_Encrypt = p11_encryption.C_Encrypt,
    .C_EncryptUpdate = p11_encryption.C_Encrypt,
    .C_EncryptFinal = p11_encryption.C_EncryptFinal,
    .C_DecryptInit = p11_decryption.C_DecryptInit,
    .C_Decrypt = p11_decryption.C_Decrypt,
    .C_DecryptUpdate = p11_decryption.C_DecryptUpdate,
    .C_DecryptFinal = p11_decryption.C_DecryptFinal,
    .C_DigestInit = p11_digest.C_DigestInit,
    .C_Digest = p11_digest.C_Digest,
    .C_DigestUpdate = p11_digest.C_DigestUpdate,
    .C_DigestKey = p11_digest.C_DigestKey,
    .C_DigestFinal = p11_digest.C_DigestFinal,
    .C_SignInit = p11_sign.C_SignInit,
    .C_Sign = p11_sign.C_Sign,
    .C_SignUpdate = p11_sign.C_SignUpdate,
    .C_SignFinal = p11_sign.C_SignFinal,
    .C_SignRecoverInit = p11_sign.C_SignRecoverInit,
    .C_SignRecover = p11_sign.C_SignRecover,
    .C_VerifyInit = p11_sign.C_VerifyInit,
    .C_Verify = p11_sign.C_Verify,
    .C_VerifyUpdate = p11_sign.C_VerifyUpdate,
    .C_VerifyFinal = p11_sign.C_VerifyFinal,
    .C_VerifyRecoverInit = p11_sign.C_VerifyRecoverInit,
    .C_VerifyRecover = p11_sign.C_VerifyRecover,
    .C_DigestEncryptUpdate = p11_dual_functions.C_DigestEncryptUpdate,
    .C_DecryptDigestUpdate = p11_dual_functions.C_DecryptDigestUpdate,
    .C_SignEncryptUpdate = p11_dual_functions.C_SignEncryptUpdate,
    .C_DecryptVerifyUpdate = p11_dual_functions.C_DecryptVerifyUpdate,
    .C_GenerateKey = p11_key_management.C_GenerateKey,
    .C_GenerateKeyPair = p11_key_management.C_GenerateKeyPair,
    .C_WrapKey = p11_key_management.C_WrapKey,
    .C_UnwrapKey = p11_key_management.C_UnwrapKey,
    .C_DeriveKey = p11_key_management.C_DeriveKey,
    .C_SeedRandom = p11_random.C_SeedRandom,
    .C_GenerateRandom = p11_random.C_GenerateRandom,
    .C_GetFunctionStatus = p11_parallel.C_GetFunctionStatus,
    .C_CancelFunction = p11_parallel.C_CancelFunction,
    .C_WaitForSlotEvent = p11_slot_and_token.C_WaitForSlotEvent,
};

export fn C_GetFunctionList(function_list: ?*?*pkcs.CK_FUNCTION_LIST) pkcs.CK_RV {
    if (function_list == null)
        return pkcs.CKR_ARGUMENTS_BAD;

    function_list.?.* = &functionList;
    return pkcs.CKR_OK;
}
