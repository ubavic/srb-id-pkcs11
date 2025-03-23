#ifndef PKCS11_DIGEST_H
#define PKCS11_DIGEST_H

#include "pkcs11.h"

extern "C" {
CK_DECLARE_FUNCTION(CK_RV, C_DigestInit)(
	CK_SESSION_HANDLE hSession,
	CK_MECHANISM_PTR pMechanism);

CK_DECLARE_FUNCTION(CK_RV, C_Digest)(
	CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR pData,
	CK_ULONG ulDataLen,
	CK_BYTE_PTR pDigest,
	CK_ULONG_PTR pulDigestLen);

CK_DECLARE_FUNCTION(CK_RV, C_DigestUpdate)(
	CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR pPart,
	CK_ULONG ulPartLen);

CK_DECLARE_FUNCTION(CK_RV, C_DigestKey)(
	CK_SESSION_HANDLE hSession,
	CK_OBJECT_HANDLE hKey);

CK_DECLARE_FUNCTION(CK_RV, C_DigestFinal)(
	CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR pDigest,
	CK_ULONG_PTR pulDigestLen);
}

#endif