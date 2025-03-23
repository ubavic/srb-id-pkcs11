#ifndef PKCS11_DUAL_PURPOSE_H
#define PKCS11_DUAL_PURPOSE_H

#include "pkcs11.h"

extern "C" {
CK_DECLARE_FUNCTION(CK_RV, C_DigestEncryptUpdate)(
	CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR pPart,
	CK_ULONG ulPartLen,
	CK_BYTE_PTR pEncryptedPart,
	CK_ULONG_PTR pulEncryptedPartLen);

CK_DECLARE_FUNCTION(CK_RV, C_DecryptDigestUpdate)(
	CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR pEncryptedPart,
	CK_ULONG ulEncryptedPartLen,
	CK_BYTE_PTR pPart,
	CK_ULONG_PTR pulPartLen);

CK_DECLARE_FUNCTION(CK_RV, C_DecryptDigestUpdate)(
	CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR pEncryptedPart,
	CK_ULONG ulEncryptedPartLen,
	CK_BYTE_PTR pPart,
	CK_ULONG_PTR pulPartLen);
}

#endif