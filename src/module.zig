const pkcs = @import("pkcs.zig");
const pkcs_error = @import("pkcs_error.zig");
const PkcsError = pkcs_error.PkcsError;

const p11_decryption = @import("p11_decryption.zig");
const p11_digest = @import("p11_digest.zig");
const p11_dual_functions = @import("p11_dual_functions.zig");
const p11_encryption = @import("p11_encryption.zig");
const p11_general = @import("p11_general.zig");
const p11_key_management = @import("p11_key_management.zig");
const p11_object_management = @import("p11_object_management.zig");
const p11_parallel = @import("p11_parallel.zig");
const p11_random = @import("p11_random.zig");
const p11_session = @import("p11_session.zig");
const p11_sign = @import("p11_sign.zig");
const p11_slot_and_token = @import("p11_slot_and_token.zig");
const p11_verify = @import("p11_verify.zig");
const State = @import("ModuleState.zig");

var state: State = undefined;

export fn C_GetFunctionList(function_list: ?*?*pkcs.CK_FUNCTION_LIST) pkcs.CK_RV {
    if (function_list == null)
        return pkcs.CKR_ARGUMENTS_BAD;

    function_list.?.* = @constCast(&functionList);

    return pkcs.CKR_OK;
}

const functionList = pkcs.CK_FUNCTION_LIST{
    .version = pkcs.CK_VERSION{ .major = 2, .minor = 40 },
    .C_Initialize = C_Initialize,
    .C_Finalize = C_Finalize,
    .C_GetInfo = C_GetInfo,
    .C_GetFunctionList = @ptrCast(@constCast(&C_GetFunctionList)),
    .C_GetSlotList = C_GetSlotList,
    .C_GetSlotInfo = C_GetSlotInfo,
    .C_GetTokenInfo = C_GetTokenInfo,
    .C_GetMechanismList = C_GetMechanismList,
    .C_GetMechanismInfo = C_GetMechanismInfo,
    .C_InitToken = C_InitToken,
    .C_InitPIN = C_InitPIN,
    .C_SetPIN = C_SetPIN,
    .C_OpenSession = C_OpenSession,
    .C_CloseSession = C_CloseSession,
    .C_CloseAllSessions = C_CloseAllSessions,
    .C_GetSessionInfo = C_GetSessionInfo,
    .C_GetOperationState = C_GetOperationState,
    .C_SetOperationState = C_SetOperationState,
    .C_Login = C_Login,
    .C_Logout = C_Logout,
    .C_CreateObject = C_CreateObject,
    .C_CopyObject = C_CopyObject,
    .C_DestroyObject = C_DestroyObject,
    .C_GetObjectSize = C_GetObjectSize,
    .C_GetAttributeValue = C_GetAttributeValue,
    .C_SetAttributeValue = C_SetAttributeValue,
    .C_FindObjectsInit = C_FindObjectsInit,
    .C_FindObjects = C_FindObjects,
    .C_FindObjectsFinal = C_FindObjectsFinal,
    .C_EncryptInit = C_EncryptInit,
    .C_Encrypt = C_Encrypt,
    .C_EncryptUpdate = C_EncryptUpdate,
    .C_EncryptFinal = C_EncryptFinal,
    .C_DecryptInit = C_DecryptInit,
    .C_Decrypt = C_Decrypt,
    .C_DecryptUpdate = C_DecryptUpdate,
    .C_DecryptFinal = C_DecryptFinal,
    .C_DigestInit = C_DigestInit,
    .C_Digest = C_Digest,
    .C_DigestUpdate = C_DigestUpdate,
    .C_DigestKey = C_DigestKey,
    .C_DigestFinal = C_DigestFinal,
    .C_SignInit = C_SignInit,
    .C_Sign = C_Sign,
    .C_SignUpdate = C_SignUpdate,
    .C_SignFinal = C_SignFinal,
    .C_SignRecoverInit = C_SignRecoverInit,
    .C_SignRecover = C_SignRecover,
    .C_VerifyInit = C_VerifyInit,
    .C_Verify = C_Verify,
    .C_VerifyUpdate = C_VerifyUpdate,
    .C_VerifyFinal = C_VerifyFinal,
    .C_VerifyRecoverInit = C_VerifyRecoverInit,
    .C_VerifyRecover = C_VerifyRecover,
    .C_DigestEncryptUpdate = C_DigestEncryptUpdate,
    .C_DecryptDigestUpdate = C_DecryptDigestUpdate,
    .C_SignEncryptUpdate = C_SignEncryptUpdate,
    .C_DecryptVerifyUpdate = C_DecryptVerifyUpdate,
    .C_GenerateKey = C_GenerateKey,
    .C_GenerateKeyPair = C_GenerateKeyPair,
    .C_WrapKey = C_WrapKey,
    .C_UnwrapKey = C_UnwrapKey,
    .C_DeriveKey = C_DeriveKey,
    .C_SeedRandom = C_SeedRandom,
    .C_GenerateRandom = C_GenerateRandom,
    .C_GetFunctionStatus = C_GetFunctionStatus,
    .C_CancelFunction = C_CancelFunction,
    .C_WaitForSlotEvent = C_WaitForSlotEvent,
};

export fn C_Initialize(
    init_args: pkcs.CK_VOID_PTR,
) pkcs.CK_RV {
    return rv(p11_general.initialize(&state, init_args));
}

export fn C_Finalize(
    reserved: pkcs.CK_VOID_PTR,
) pkcs.CK_RV {
    return rv(p11_general.finalize(&state, reserved));
}

export fn C_GetInfo(
    info: ?*pkcs.CK_INFO,
) pkcs.CK_RV {
    return rv(p11_general.getInfo(&state, info));
}

export fn C_GetSlotList(
    token_present: pkcs.CK_BBOOL,
    slot_list: ?[*]pkcs.CK_SLOT_ID,
    slot_count: ?*pkcs.CK_ULONG,
) pkcs.CK_RV {
    return rv(p11_slot_and_token.getSlotList(&state, token_present, slot_list, slot_count));
}

export fn C_GetSlotInfo(
    slot_ID: pkcs.CK_SLOT_ID,
    slot_info: ?*pkcs.CK_SLOT_INFO,
) pkcs.CK_RV {
    return rv(p11_slot_and_token.getSlotInfo(&state, slot_ID, slot_info));
}

export fn C_GetTokenInfo(
    slot_id: pkcs.CK_SLOT_ID,
    token_info: ?*pkcs.CK_TOKEN_INFO,
) pkcs.CK_RV {
    return rv(p11_slot_and_token.getTokenInfo(&state, slot_id, token_info));
}

export fn C_GetMechanismList(
    slot_id: pkcs.CK_SLOT_ID,
    mechanism_list: ?[*]pkcs.CK_MECHANISM_TYPE,
    count: ?*pkcs.CK_ULONG,
) pkcs.CK_RV {
    return rv(p11_slot_and_token.getMechanismList(&state, slot_id, mechanism_list, count));
}

export fn C_GetMechanismInfo(
    slot_id: pkcs.CK_SLOT_ID,
    mechanism_type: pkcs.CK_MECHANISM_TYPE,
    mechanism_info: ?*pkcs.CK_MECHANISM_INFO,
) pkcs.CK_RV {
    return rv(p11_slot_and_token.getMechanismInfo(&state, slot_id, mechanism_type, mechanism_info));
}

export fn C_InitToken(
    slot_id: pkcs.CK_SLOT_ID,
    pin: ?*pkcs.CK_UTF8CHAR,
    pin_len: pkcs.CK_ULONG,
    label: ?*pkcs.CK_UTF8CHAR,
) pkcs.CK_RV {
    return rv(p11_slot_and_token.initToken(&state, slot_id, pin, pin_len, label));
}

export fn C_InitPIN(
    session_handle: pkcs.CK_SESSION_HANDLE,
    pin: ?[*]pkcs.CK_UTF8CHAR,
    pin_len: pkcs.CK_ULONG,
) pkcs.CK_RV {
    return rv(p11_slot_and_token.initPIN(&state, session_handle, pin, pin_len));
}

export fn C_SetPIN(
    session_handle: pkcs.CK_SESSION_HANDLE,
    old_pin: ?[*]pkcs.CK_UTF8CHAR,
    old_pin_len: pkcs.CK_ULONG,
    new_pin: ?[*]pkcs.CK_UTF8CHAR,
    new_pin_len: pkcs.CK_ULONG,
) pkcs.CK_RV {
    return rv(p11_slot_and_token.setPIN(&state, session_handle, old_pin, old_pin_len, new_pin, new_pin_len));
}

export fn C_OpenSession(
    slot_id: pkcs.CK_SLOT_ID,
    flags: pkcs.CK_FLAGS,
    application: ?*anyopaque,
    notify: pkcs.CK_NOTIFY,
    session_handle: ?*pkcs.CK_SESSION_HANDLE,
) pkcs.CK_RV {
    return rv(p11_session.openSession(&state, slot_id, flags, application, notify, session_handle));
}

export fn C_CloseSession(
    session_handle: pkcs.CK_SESSION_HANDLE,
) pkcs.CK_RV {
    return rv(p11_session.closeSession(&state, session_handle));
}

export fn C_CloseAllSessions(
    slot_id: pkcs.CK_SLOT_ID,
) pkcs.CK_RV {
    return rv(p11_session.closeAllSessions(&state, slot_id));
}

export fn C_GetSessionInfo(
    session_handle: pkcs.CK_SESSION_HANDLE,
    session_info: ?*pkcs.CK_SESSION_INFO,
) pkcs.CK_RV {
    return rv(p11_session.getSessionInfo(&state, session_handle, session_info));
}

export fn C_GetOperationState(
    session_handle: pkcs.CK_SESSION_HANDLE,
    operation_state: ?[*]pkcs.CK_BYTE,
    operation_state_len: ?*pkcs.CK_ULONG,
) pkcs.CK_RV {
    return rv(p11_session.getOperationState(&state, session_handle, operation_state, operation_state_len));
}

export fn C_SetOperationState(
    session_handle: pkcs.CK_SESSION_HANDLE,
    operation_state: ?[*]const pkcs.CK_BYTE,
    operation_state_len: pkcs.CK_ULONG,
    encryption_key: pkcs.CK_OBJECT_HANDLE,
    authentication_key: pkcs.CK_OBJECT_HANDLE,
) pkcs.CK_RV {
    return rv(p11_session.setOperationState(&state, session_handle, operation_state, operation_state_len, encryption_key, authentication_key));
}

export fn C_Login(
    session_handle: pkcs.CK_SESSION_HANDLE,
    user_type: pkcs.CK_USER_TYPE,
    pin: ?[*]const pkcs.CK_UTF8CHAR,
    pin_length: pkcs.CK_ULONG,
) pkcs.CK_RV {
    return rv(p11_session.login(&state, session_handle, user_type, pin, pin_length));
}

export fn C_Logout(
    session_handle: pkcs.CK_SESSION_HANDLE,
) pkcs.CK_RV {
    return rv(p11_session.logout(&state, session_handle));
}

export fn C_CreateObject(
    session_handle: pkcs.CK_SESSION_HANDLE,
    template: ?[*]pkcs.CK_ATTRIBUTE,
    count: pkcs.CK_ULONG,
    object_handle: ?*pkcs.CK_OBJECT_HANDLE,
) pkcs.CK_RV {
    return rv(p11_object_management.createObject(&state, session_handle, template, count, object_handle));
}

export fn C_CopyObject(
    session_handle: pkcs.CK_SESSION_HANDLE,
    object_handle: pkcs.CK_OBJECT_HANDLE,
    template: ?[*]pkcs.CK_ATTRIBUTE,
    count: pkcs.CK_ULONG,
    new_object_handle: ?*pkcs.CK_OBJECT_HANDLE,
) pkcs.CK_RV {
    return rv(p11_object_management.copyObject(&state, session_handle, object_handle, template, count, new_object_handle));
}

export fn C_DestroyObject(
    session_handle: pkcs.CK_SESSION_HANDLE,
    object_handle: pkcs.CK_OBJECT_HANDLE,
) pkcs.CK_RV {
    return rv(p11_object_management.destroyObject(&state, session_handle, object_handle));
}

export fn C_GetObjectSize(
    session_handle: pkcs.CK_SESSION_HANDLE,
    object_handle: pkcs.CK_OBJECT_HANDLE,
    size: ?*pkcs.CK_ULONG,
) pkcs.CK_RV {
    return rv(p11_object_management.getObjectSize(&state, session_handle, object_handle, size));
}

export fn C_GetAttributeValue(
    session_handle: pkcs.CK_SESSION_HANDLE,
    object_handle: pkcs.CK_OBJECT_HANDLE,
    template: ?[*]pkcs.CK_ATTRIBUTE,
    count: pkcs.CK_ULONG,
) pkcs.CK_RV {
    return rv(p11_object_management.getAttributeValue(&state, session_handle, object_handle, template, count));
}

export fn C_SetAttributeValue(
    session_handle: pkcs.CK_SESSION_HANDLE,
    object_handle: pkcs.CK_OBJECT_HANDLE,
    template: ?[*]pkcs.CK_ATTRIBUTE,
    count: pkcs.CK_ULONG,
) pkcs.CK_RV {
    return rv(p11_object_management.setAttributeValue(&state, session_handle, object_handle, template, count));
}

export fn C_FindObjectsInit(
    session_handle: pkcs.CK_SESSION_HANDLE,
    template: ?[*]pkcs.CK_ATTRIBUTE,
    count: pkcs.CK_ULONG,
) pkcs.CK_RV {
    return rv(p11_object_management.findObjectsInit(&state, session_handle, template, count));
}

export fn C_FindObjects(
    session_handle: pkcs.CK_SESSION_HANDLE,
    object_handles: ?[*]pkcs.CK_OBJECT_HANDLE,
    max_object_count: pkcs.CK_ULONG,
    object_count: ?*pkcs.CK_ULONG,
) pkcs.CK_RV {
    return rv(p11_object_management.findObjects(&state, session_handle, object_handles, max_object_count, object_count));
}

export fn C_FindObjectsFinal(
    session_handle: pkcs.CK_SESSION_HANDLE,
) pkcs.CK_RV {
    return rv(p11_object_management.findObjectsFinal(&state, session_handle));
}

export fn C_EncryptInit(
    session_handle: pkcs.CK_SESSION_HANDLE,
    mechanism: ?*pkcs.CK_MECHANISM,
    key: pkcs.CK_OBJECT_HANDLE,
) pkcs.CK_RV {
    return rv(p11_encryption.encryptInit(&state, session_handle, mechanism, key));
}

export fn C_Encrypt(
    session_handle: pkcs.CK_SESSION_HANDLE,
    data: ?[*]const pkcs.CK_BYTE,
    data_len: pkcs.CK_ULONG,
    encrypted_data: ?[*]pkcs.CK_BYTE,
    encrypted_data_len: ?*pkcs.CK_ULONG,
) pkcs.CK_RV {
    return rv(p11_encryption.encrypt(&state, session_handle, data, data_len, encrypted_data, encrypted_data_len));
}

export fn C_EncryptUpdate(
    session_handle: pkcs.CK_SESSION_HANDLE,
    part: ?[*]const pkcs.CK_BYTE,
    part_len: pkcs.CK_ULONG,
    encrypted_part: ?[*]pkcs.CK_BYTE,
    encrypted_part_len: ?*pkcs.CK_ULONG,
) pkcs.CK_RV {
    return rv(p11_encryption.encryptUpdate(&state, session_handle, part, part_len, encrypted_part, encrypted_part_len));
}

export fn C_EncryptFinal(
    session_handle: pkcs.CK_SESSION_HANDLE,
    last_encrypted_part: ?[*]pkcs.CK_BYTE,
    last_encrypted_part_len: ?*pkcs.CK_ULONG,
) pkcs.CK_RV {
    return rv(p11_encryption.encryptFinal(&state, session_handle, last_encrypted_part, last_encrypted_part_len));
}

export fn C_DecryptInit(
    session_handle: pkcs.CK_SESSION_HANDLE,
    mechanism: ?*pkcs.CK_MECHANISM,
    key: pkcs.CK_OBJECT_HANDLE,
) pkcs.CK_RV {
    return rv(p11_decryption.decryptInit(&state, session_handle, mechanism, key));
}

export fn C_Decrypt(
    session_handle: pkcs.CK_SESSION_HANDLE,
    encrypted_data: ?[*]const pkcs.CK_BYTE,
    encrypted_data_len: pkcs.CK_ULONG,
    data: ?[*]pkcs.CK_BYTE,
    data_len: ?*pkcs.CK_ULONG,
) pkcs.CK_RV {
    return rv(p11_decryption.decrypt(&state, session_handle, encrypted_data, encrypted_data_len, data, data_len));
}

export fn C_DecryptUpdate(
    session_handle: pkcs.CK_SESSION_HANDLE,
    encrypted_part: ?[*]const pkcs.CK_BYTE,
    encrypted_part_len: pkcs.CK_ULONG,
    part: ?[*]pkcs.CK_BYTE,
    part_len: ?*pkcs.CK_ULONG,
) pkcs.CK_RV {
    return rv(p11_decryption.decryptUpdate(&state, session_handle, encrypted_part, encrypted_part_len, part, part_len));
}

export fn C_DecryptFinal(
    session_handle: pkcs.CK_SESSION_HANDLE,
    last_part: ?[*]pkcs.CK_BYTE,
    last_part_len: ?*pkcs.CK_ULONG,
) pkcs.CK_RV {
    return rv(p11_decryption.decryptFinal(&state, session_handle, last_part, last_part_len));
}

export fn C_DigestInit(
    session_handle: pkcs.CK_SESSION_HANDLE,
    mechanism: ?*pkcs.CK_MECHANISM,
) pkcs.CK_RV {
    return rv(p11_digest.digestInit(&state, session_handle, mechanism));
}

export fn C_Digest(
    session_handle: pkcs.CK_SESSION_HANDLE,
    data: ?[*]pkcs.CK_BYTE,
    data_len: pkcs.CK_ULONG,
    data_digest: ?[*]pkcs.CK_BYTE,
    data_digest_len: ?*pkcs.CK_ULONG,
) pkcs.CK_RV {
    return rv(p11_digest.digest(&state, session_handle, data, data_len, data_digest, data_digest_len));
}

export fn C_DigestUpdate(
    session_handle: pkcs.CK_SESSION_HANDLE,
    part: ?[*]pkcs.CK_BYTE,
    part_len: pkcs.CK_ULONG,
) pkcs.CK_RV {
    return rv(p11_digest.digestUpdate(&state, session_handle, part, part_len));
}

export fn C_DigestKey(
    session_handle: pkcs.CK_SESSION_HANDLE,
    key: pkcs.CK_OBJECT_HANDLE,
) pkcs.CK_RV {
    return rv(p11_digest.digestKey(&state, session_handle, key));
}

export fn C_DigestFinal(
    session_handle: pkcs.CK_SESSION_HANDLE,
    data_digest: ?[*]pkcs.CK_BYTE,
    data_digest_len: ?*pkcs.CK_ULONG,
) pkcs.CK_RV {
    return rv(p11_digest.digestFinal(&state, session_handle, data_digest, data_digest_len));
}

export fn C_SignInit(
    session_handle: pkcs.CK_SESSION_HANDLE,
    mechanism: ?*pkcs.CK_MECHANISM,
    key: pkcs.CK_OBJECT_HANDLE,
) pkcs.CK_RV {
    return rv(p11_sign.signInit(&state, session_handle, mechanism, key));
}

export fn C_Sign(
    session_handle: pkcs.CK_SESSION_HANDLE,
    data: ?[*]pkcs.CK_BYTE,
    data_len: pkcs.CK_ULONG,
    signature: ?[*]pkcs.CK_BYTE,
    signature_len: ?*pkcs.CK_ULONG,
) pkcs.CK_RV {
    return rv(p11_sign.sign(&state, session_handle, data, data_len, signature, signature_len));
}

export fn C_SignUpdate(
    session_handle: pkcs.CK_SESSION_HANDLE,
    part: ?[*]pkcs.CK_BYTE,
    part_len: pkcs.CK_ULONG,
) pkcs.CK_RV {
    return rv(p11_sign.signUpdate(&state, session_handle, part, part_len));
}

export fn C_SignFinal(
    session_handle: pkcs.CK_SESSION_HANDLE,
    signature: ?[*]pkcs.CK_BYTE,
    signature_len: ?*pkcs.CK_ULONG,
) pkcs.CK_RV {
    return rv(p11_sign.signFinal(&state, session_handle, signature, signature_len));
}

export fn C_SignRecoverInit(
    session_handle: pkcs.CK_SESSION_HANDLE,
    mechanism: ?*pkcs.CK_MECHANISM,
    key: pkcs.CK_OBJECT_HANDLE,
) pkcs.CK_RV {
    return rv(p11_sign.signRecoverInit(&state, session_handle, mechanism, key));
}

export fn C_SignRecover(
    session_handle: pkcs.CK_SESSION_HANDLE,
    data: ?[*]const pkcs.CK_BYTE,
    data_len: pkcs.CK_ULONG,
    signature: ?[*]pkcs.CK_BYTE,
    signature_len: ?*pkcs.CK_ULONG,
) pkcs.CK_RV {
    return rv(p11_sign.signRecover(&state, session_handle, data, data_len, signature, signature_len));
}

export fn C_VerifyInit(
    session_handle: pkcs.CK_SESSION_HANDLE,
    mechanism: ?*pkcs.CK_MECHANISM,
    key: pkcs.CK_OBJECT_HANDLE,
) pkcs.CK_RV {
    return rv(p11_verify.verifyInit(&state, session_handle, mechanism, key));
}

export fn C_Verify(
    session_handle: pkcs.CK_SESSION_HANDLE,
    data: ?[*]const pkcs.CK_BYTE,
    data_len: pkcs.CK_ULONG,
    signature: ?[*]const pkcs.CK_BYTE,
    signature_len: pkcs.CK_ULONG,
) pkcs.CK_RV {
    return rv(p11_verify.verify(&state, session_handle, data, data_len, signature, signature_len));
}

export fn C_VerifyUpdate(
    session_handle: pkcs.CK_SESSION_HANDLE,
    part: ?[*]const pkcs.CK_BYTE,
    part_len: pkcs.CK_ULONG,
) pkcs.CK_RV {
    return rv(p11_verify.verifyUpdate(&state, session_handle, part, part_len));
}

export fn C_VerifyFinal(
    session_handle: pkcs.CK_SESSION_HANDLE,
    signature: ?[*]const pkcs.CK_BYTE,
    signature_len: pkcs.CK_ULONG,
) pkcs.CK_RV {
    return rv(p11_verify.verifyFinal(&state, session_handle, signature, signature_len));
}

export fn C_VerifyRecoverInit(
    session_handle: pkcs.CK_SESSION_HANDLE,
    mechanism: ?*pkcs.CK_MECHANISM,
    key: pkcs.CK_OBJECT_HANDLE,
) pkcs.CK_RV {
    return rv(p11_verify.verifyRecoverInit(&state, session_handle, mechanism, key));
}

export fn C_VerifyRecover(
    session_handle: pkcs.CK_SESSION_HANDLE,
    signature: ?[*]const pkcs.CK_BYTE,
    signature_len: pkcs.CK_ULONG,
    data: ?[*]pkcs.CK_BYTE,
    data_len: ?*pkcs.CK_ULONG,
) pkcs.CK_RV {
    return rv(p11_verify.verifyRecover(&state, session_handle, signature, signature_len, data, data_len));
}

export fn C_DigestEncryptUpdate(
    session_handle: pkcs.CK_SESSION_HANDLE,
    part: ?[*]const pkcs.CK_BYTE,
    part_len: pkcs.CK_ULONG,
    encrypted_part: ?[*]pkcs.CK_BYTE,
    encrypted_part_len: ?*pkcs.CK_ULONG,
) pkcs.CK_RV {
    return rv(p11_dual_functions.digestEncryptUpdate(&state, session_handle, part, part_len, encrypted_part, encrypted_part_len));
}

export fn C_DecryptDigestUpdate(
    session_handle: pkcs.CK_SESSION_HANDLE,
    encrypted_part: ?[*]const pkcs.CK_BYTE,
    encrypted_part_len: pkcs.CK_ULONG,
    part: ?[*]pkcs.CK_BYTE,
    part_len: ?*pkcs.CK_ULONG,
) pkcs.CK_RV {
    return rv(p11_dual_functions.decryptDigestUpdate(&state, session_handle, encrypted_part, encrypted_part_len, part, part_len));
}

export fn C_SignEncryptUpdate(
    session_handle: pkcs.CK_SESSION_HANDLE,
    part: ?[*]const pkcs.CK_BYTE,
    part_len: pkcs.CK_ULONG,
    encrypted_part: ?[*]pkcs.CK_BYTE,
    encrypted_part_len: ?*pkcs.CK_ULONG,
) pkcs.CK_RV {
    return rv(p11_dual_functions.signEncryptUpdate(&state, session_handle, part, part_len, encrypted_part, encrypted_part_len));
}

export fn C_DecryptVerifyUpdate(
    session_handle: pkcs.CK_SESSION_HANDLE,
    encrypted_part: ?[*]const pkcs.CK_BYTE,
    encrypted_part_len: pkcs.CK_ULONG,
    part: ?[*]pkcs.CK_BYTE,
    part_len: ?*pkcs.CK_ULONG,
) pkcs.CK_RV {
    return rv(p11_dual_functions.decryptVerifyUpdate(&state, session_handle, encrypted_part, encrypted_part_len, part, part_len));
}

export fn C_GenerateKey(
    session_handle: pkcs.CK_SESSION_HANDLE,
    mechanism: ?*pkcs.CK_MECHANISM,
    template: ?[*]pkcs.CK_ATTRIBUTE,
    count: pkcs.CK_ULONG,
    key_handle: ?*pkcs.CK_OBJECT_HANDLE,
) pkcs.CK_RV {
    return rv(p11_key_management.generateKey(&state, session_handle, mechanism, template, count, key_handle));
}

export fn C_GenerateKeyPair(
    session_handle: pkcs.CK_SESSION_HANDLE,
    mechanism: ?*pkcs.CK_MECHANISM,
    public_key_template: ?[*]pkcs.CK_ATTRIBUTE,
    public_key_attribute_count: pkcs.CK_ULONG,
    private_key_template: ?[*]pkcs.CK_ATTRIBUTE,
    private_key_attribute_count: pkcs.CK_ULONG,
    public_key_handle: ?*pkcs.CK_OBJECT_HANDLE,
    private_key_handle: ?*pkcs.CK_OBJECT_HANDLE,
) pkcs.CK_RV {
    return rv(p11_key_management.generateKeyPair(&state, session_handle, mechanism, public_key_template, public_key_attribute_count, private_key_template, private_key_attribute_count, public_key_handle, private_key_handle));
}

export fn C_WrapKey(
    session_handle: pkcs.CK_SESSION_HANDLE,
    mechanism: ?*pkcs.CK_MECHANISM,
    wrapping_key: pkcs.CK_OBJECT_HANDLE,
    key: pkcs.CK_OBJECT_HANDLE,
    wrapped_key: ?[*]pkcs.CK_BYTE,
    wrapped_key_len: ?*pkcs.CK_ULONG,
) pkcs.CK_RV {
    return rv(p11_key_management.wrapKey(&state, session_handle, mechanism, wrapping_key, key, wrapped_key, wrapped_key_len));
}

export fn C_UnwrapKey(
    session_handle: pkcs.CK_SESSION_HANDLE,
    mechanism: ?*pkcs.CK_MECHANISM,
    unwrapping_key: pkcs.CK_OBJECT_HANDLE,
    wrapped_key: ?[*]const pkcs.CK_BYTE,
    wrapped_key_len: pkcs.CK_ULONG,
    template: ?[*]pkcs.CK_ATTRIBUTE,
    attribute_count: pkcs.CK_ULONG,
    key_handle: ?*pkcs.CK_OBJECT_HANDLE,
) pkcs.CK_RV {
    return rv(p11_key_management.unwrapKey(&state, session_handle, mechanism, unwrapping_key, wrapped_key, wrapped_key_len, template, attribute_count, key_handle));
}

export fn C_DeriveKey(
    session_handle: pkcs.CK_SESSION_HANDLE,
    mechanism: ?*pkcs.CK_MECHANISM,
    base_key: pkcs.CK_OBJECT_HANDLE,
    template: ?[*]pkcs.CK_ATTRIBUTE,
    attribute_count: pkcs.CK_ULONG,
    key_handle: ?*pkcs.CK_OBJECT_HANDLE,
) pkcs.CK_RV {
    return rv(p11_key_management.deriveKey(&state, session_handle, mechanism, base_key, template, attribute_count, key_handle));
}

export fn C_SeedRandom(
    session_handle: pkcs.CK_SESSION_HANDLE,
    seed: ?[*]pkcs.CK_BYTE,
    seed_len: pkcs.CK_ULONG,
) pkcs.CK_RV {
    return rv(p11_random.seedRandom(&state, session_handle, seed, seed_len));
}

export fn C_GenerateRandom(
    session_handle: pkcs.CK_SESSION_HANDLE,
    random_data: ?[*]pkcs.CK_BYTE,
    random_size: pkcs.CK_ULONG,
) pkcs.CK_RV {
    return rv(p11_random.generateRandom(&state, session_handle, random_data, random_size));
}

export fn C_GetFunctionStatus(
    session_handle: pkcs.CK_SESSION_HANDLE,
) pkcs.CK_RV {
    return rv(p11_parallel.getFunctionStatus(&state, session_handle));
}

export fn C_CancelFunction(
    session_handle: pkcs.CK_SESSION_HANDLE,
) pkcs.CK_RV {
    return rv(p11_parallel.cancelFunction(&state, session_handle));
}

export fn C_WaitForSlotEvent(
    flags: pkcs.CK_FLAGS,
    slot: ?*pkcs.CK_SLOT_ID,
    reserved: ?*anyopaque,
) pkcs.CK_RV {
    return rv(p11_slot_and_token.waitForSlotEvent(&state, flags, slot, reserved));
}

fn rv(result: PkcsError!void) pkcs.CK_RV {
    result catch |err|
        return toRV(err);

    return pkcs.CKR_OK;
}

pub fn toRV(err: PkcsError) pkcs.CK_RV {
    return switch (err) {
        PkcsError.Cancel => pkcs.CKR_CANCEL,
        PkcsError.HostMemory => pkcs.CKR_HOST_MEMORY,
        PkcsError.SlotIdInvalid => pkcs.CKR_SLOT_ID_INVALID,
        PkcsError.GeneralError => pkcs.CKR_GENERAL_ERROR,
        PkcsError.FunctionFailed => pkcs.CKR_FUNCTION_FAILED,
        PkcsError.ArgumentsBad => pkcs.CKR_ARGUMENTS_BAD,
        PkcsError.NoEvent => pkcs.CKR_NO_EVENT,
        PkcsError.CantLock => pkcs.CKR_CANT_LOCK,
        PkcsError.AttributeSensitive => pkcs.CKR_ATTRIBUTE_SENSITIVE,
        PkcsError.AttributeTypeInvalid => pkcs.CKR_ATTRIBUTE_TYPE_INVALID,
        PkcsError.DeviceError => pkcs.CKR_DEVICE_ERROR,
        PkcsError.DeviceMemory => pkcs.CKR_DEVICE_MEMORY,
        PkcsError.DeviceRemoved => pkcs.CKR_DEVICE_REMOVED,
        PkcsError.FunctionCanceled => pkcs.CKR_FUNCTION_CANCELED,
        PkcsError.FunctionNotParallel => pkcs.CKR_FUNCTION_NOT_PARALLEL,
        PkcsError.FunctionNotSupported => pkcs.CKR_FUNCTION_NOT_SUPPORTED,
        PkcsError.KeyHandleInvalid => pkcs.CKR_KEY_HANDLE_INVALID,
        PkcsError.KeyTypeInconsistent => pkcs.CKR_KEY_TYPE_INCONSISTENT,
        PkcsError.KeyFunctionNotPermitted => pkcs.CKR_KEY_FUNCTION_NOT_PERMITTED,
        PkcsError.MechanismInvalid => pkcs.CKR_MECHANISM_INVALID,
        PkcsError.MechanismParamInvalid => pkcs.CKR_MECHANISM_PARAM_INVALID,
        PkcsError.ObjectHandleInvalid => pkcs.CKR_OBJECT_HANDLE_INVALID,
        PkcsError.OperationActive => pkcs.CKR_OPERATION_ACTIVE,
        PkcsError.OperationNotInitialized => pkcs.CKR_OPERATION_NOT_INITIALIZED,
        PkcsError.PinIncorrect => pkcs.CKR_PIN_INCORRECT,
        PkcsError.PinInvalid => pkcs.CKR_PIN_INVALID,
        PkcsError.PinLenRange => pkcs.CKR_PIN_LEN_RANGE,
        PkcsError.PinLocked => pkcs.CKR_PIN_LOCKED,
        PkcsError.SessionClosed => pkcs.CKR_SESSION_CLOSED,
        PkcsError.SessionHandleInvalid => pkcs.CKR_SESSION_HANDLE_INVALID,
        PkcsError.SessionParallelNotSupported => pkcs.CKR_SESSION_PARALLEL_NOT_SUPPORTED,
        PkcsError.SessionReadOnly => pkcs.CKR_SESSION_READ_ONLY,
        PkcsError.SignatureInvalid => pkcs.CKR_SIGNATURE_INVALID,
        PkcsError.SignatureLenRange => pkcs.CKR_SIGNATURE_LEN_RANGE,
        PkcsError.TokenNoPresent => pkcs.CKR_TOKEN_NOT_PRESENT,
        PkcsError.TokenNotRecognized => pkcs.CKR_TOKEN_NOT_RECOGNIZED,
        PkcsError.UserAlreadyLoggedIn => pkcs.CKR_USER_ALREADY_LOGGED_IN,
        PkcsError.UserNotLoggedIn => pkcs.CKR_USER_NOT_LOGGED_IN,
        PkcsError.UserTypeInvalid => pkcs.CKR_USER_TYPE_INVALID,
        PkcsError.RandomSeedNotSupported => pkcs.CKR_RANDOM_SEED_NOT_SUPPORTED,
        PkcsError.BufferTooSmall => pkcs.CKR_BUFFER_TOO_SMALL,
        PkcsError.CryptokiNotInitialized => pkcs.CKR_CRYPTOKI_NOT_INITIALIZED,
        PkcsError.CryptokiAlreadyInitialized => pkcs.CKR_CRYPTOKI_ALREADY_INITIALIZED,
        PkcsError.DataLenRange => pkcs.CKR_DATA_LEN_RANGE,
        PkcsError.EncryptedDataInvalid => pkcs.CKR_ENCRYPTED_DATA_INVALID,
        PkcsError.EncryptedDataLenRange => pkcs.CKR_ENCRYPTED_DATA_LEN_RANGE,
    };
}
