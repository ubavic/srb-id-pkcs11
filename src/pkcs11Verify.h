#ifndef PKCS11_VERIFY_H
#define PKCS11_VERIFY_H

#include "pkcs11.h"

extern "C" {
CK_DECLARE_FUNCTION(CK_RV, C_VerifyInit)(
	CK_SESSION_HANDLE hSession,
	CK_MECHANISM_PTR pMechanism,
	CK_OBJECT_HANDLE hKey);

CK_DECLARE_FUNCTION(CK_RV, C_Verify)(
	CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR pData,
	CK_ULONG ulDataLen,
	CK_BYTE_PTR pSignature,
	CK_ULONG ulSignatureLen);

CK_DECLARE_FUNCTION(CK_RV, C_VerifyUpdate)(
	CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR pPart,
	CK_ULONG ulPartLen);

CK_DECLARE_FUNCTION(CK_RV, C_VerifyFinal)(
	CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR pSignature,
	CK_ULONG ulSignatureLen);

CK_DECLARE_FUNCTION(CK_RV, C_VerifyRecoverInit)(
	CK_SESSION_HANDLE hSession,
	CK_MECHANISM_PTR pMechanism,
	CK_OBJECT_HANDLE hKey);

CK_DECLARE_FUNCTION(CK_RV, C_VerifyRecover)(
	CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR pSignature,
	CK_ULONG ulSignatureLen,
	CK_BYTE_PTR pData,
	CK_ULONG_PTR pulDataLen);
}

#endif