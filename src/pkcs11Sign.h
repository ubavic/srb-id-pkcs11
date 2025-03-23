#ifndef PKCS11_SIGN_H
#define PKCS11_SIGN_H

#include "pkcs11.h"

extern "C" {
CK_DECLARE_FUNCTION(CK_RV, C_SignInit)(
	CK_SESSION_HANDLE hSession,
	CK_MECHANISM_PTR pMechanism,
	CK_OBJECT_HANDLE hKey);

CK_DECLARE_FUNCTION(CK_RV, C_Sign)(
	CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR pData,
	CK_ULONG ulDataLen,
	CK_BYTE_PTR pSignature,
	CK_ULONG_PTR pulSignatureLen);

CK_DECLARE_FUNCTION(CK_RV, C_SignUpdate)(
	CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR pPart,
	CK_ULONG ulPartLen);

CK_DECLARE_FUNCTION(CK_RV, C_SignFinal)(
	CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR pSignature,
	CK_ULONG_PTR pulSignatureLen);

CK_DECLARE_FUNCTION(CK_RV, C_SignRecoverInit)(
	CK_SESSION_HANDLE hSession,
	CK_MECHANISM_PTR pMechanism,
	CK_OBJECT_HANDLE hKey);

CK_DECLARE_FUNCTION(CK_RV, C_SignRecover)(
	CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR pData,
	CK_ULONG ulDataLen,
	CK_BYTE_PTR pSignature,
	CK_ULONG_PTR pulSignatureLen);
}

#endif
