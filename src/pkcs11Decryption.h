#ifndef PKCS11_DECRYPTION_H
#define PKCS11_DECRYPTION_H

#include "pkcs11.h"

extern "C" {
CK_DECLARE_FUNCTION(CK_RV, C_DecryptInit)(
	CK_SESSION_HANDLE hSession,
	CK_MECHANISM_PTR pMechanism,
	CK_OBJECT_HANDLE hKey);

CK_DECLARE_FUNCTION(CK_RV, C_Decrypt)(
	CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR pEncryptedData,
	CK_ULONG ulEncryptedDataLen,
	CK_BYTE_PTR pData,
	CK_ULONG_PTR pulDataLen);

CK_DECLARE_FUNCTION(CK_RV, C_DecryptUpdate)(
	CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR pEncryptedPart,
	CK_ULONG ulEncryptedPartLen,
	CK_BYTE_PTR pPart,
	CK_ULONG_PTR pulPartLen);

CK_DECLARE_FUNCTION(CK_RV, C_DecryptFinal)(
	CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR pLastPart,
	CK_ULONG_PTR pulLastPartLen);
}

#endif