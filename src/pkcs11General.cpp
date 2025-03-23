#include "pkcs11General.h"

CK_FUNCTION_LIST pkcs11_2_40_functions = CK_FUNCTION_LIST{
	{0x02, 0x40},
	&C_Initialize,
	&C_Finalize,
	&C_GetInfo,
	&C_GetFunctionList,
	&C_GetSlotList,
	&C_GetSlotInfo,
	&C_GetTokenInfo,
	&C_GetMechanismList,
	&C_GetMechanismInfo,
	&C_InitToken,
	&C_InitPIN,
	&C_SetPIN,
	&C_OpenSession,
	&C_CloseSession,
	&C_CloseAllSessions,
	&C_GetSessionInfo,
	&C_GetOperationState,
	&C_SetOperationState,
	&C_Login,
	&C_Logout,
	&C_CreateObject,
	&C_CopyObject,
	&C_DestroyObject,
	&C_GetObjectSize,
	&C_GetAttributeValue,
	&C_SetAttributeValue,
	&C_FindObjectsInit,
	&C_FindObjects,
	&C_FindObjectsFinal,
	&C_EncryptInit,
	&C_Encrypt,
	&C_EncryptUpdate,
	&C_EncryptFinal,
	&C_DecryptInit,
	&C_Decrypt,
	&C_DecryptUpdate,
	&C_DecryptFinal,
	&C_DigestInit,
	&C_Digest,
	&C_DigestUpdate,
	&C_DigestKey,
	&C_DigestFinal,
	&C_SignInit,
	&C_Sign,
	&C_SignUpdate,
	&C_SignFinal,
	&C_SignRecoverInit,
	&C_SignRecover,
	&C_VerifyInit,
	&C_Verify,
	&C_VerifyUpdate,
	&C_VerifyFinal,
	&C_VerifyRecoverInit,
	&C_VerifyRecover,
	&C_DigestEncryptUpdate,
	&C_DecryptDigestUpdate,
	&C_SignEncryptUpdate,
	&C_DecryptVerifyUpdate,
	&C_GenerateKey,
	&C_GenerateKeyPair,
	&C_WrapKey,
	&C_UnwrapKey,
	&C_DeriveKey,
	&C_SeedRandom,
	&C_GenerateRandom,
	&C_GetFunctionStatus,
	&C_CancelFunction,
	&C_WaitForSlotEvent};

CK_DECLARE_FUNCTION(CK_RV, C_Initialize)(CK_VOID_PTR pInitArgs) {
	if(initialized) {
		return CKR_CRYPTOKI_ALREADY_INITIALIZED;
	}

	LONG rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &smartCardContextHandle);
	if(rv != SCARD_S_SUCCESS) {
		return CKR_FUNCTION_FAILED;
	}

	initialized = true;

	return CKR_OK;
}

CK_DECLARE_FUNCTION(CK_RV, C_Finalize)(CK_VOID_PTR pReserved) {
	if(pReserved != NULL_PTR) {
		return CKR_ARGUMENTS_BAD;
	}

	if(!initialized) {
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}

	LONG rv = SCardReleaseContext(smartCardContextHandle);
	if(rv != SCARD_S_SUCCESS) {
		return CKR_FUNCTION_FAILED;
	}

	initialized = false;

	return CKR_OK;
}

CK_DECLARE_FUNCTION(CK_RV, C_GetInfo)(CK_INFO_PTR pInfo) {
	if(!initialized) {
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}

	if(pInfo == NULL) {
		return CKR_ARGUMENTS_BAD;
	}

	pInfo->cryptokiVersion.major = CRYPTOKI_VERSION_MAJOR;
	pInfo->cryptokiVersion.minor = CRYPTOKI_VERSION_MINOR;
	pInfo->flags				 = 0;
	pInfo->libraryVersion.major	 = SRB_ID_PKCS11_VERSION_MAJOR;
	pInfo->libraryVersion.minor	 = SRB_ID_PKCS11_VERSION_MINOR;

	return CKR_OK;
}

CK_DECLARE_FUNCTION(CK_RV, C_GetFunctionList)(CK_FUNCTION_LIST_PTR_PTR ppFunctionList) {
	if(NULL == ppFunctionList)
		return CKR_ARGUMENTS_BAD;

	*ppFunctionList = &pkcs11_2_40_functions;

	return CKR_OK;
}
