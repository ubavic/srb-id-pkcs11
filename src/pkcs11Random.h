#ifndef PKCS11_RANDOM_H
#define PKCS11_RANDOM_H

#include "pkcs11.h"

extern "C" {
CK_DECLARE_FUNCTION(CK_RV, C_SeedRandom)(
	CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR pSeed,
	CK_ULONG ulSeedLen);

CK_DECLARE_FUNCTION(CK_RV, C_GenerateRandom)(
	CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR RandomData,
	CK_ULONG ulRandomLen);
}

#endif