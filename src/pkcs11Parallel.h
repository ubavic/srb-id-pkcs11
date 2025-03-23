#ifndef PKCS11_PARALLEL_H
#define PKCS11_PARALLEL_H

#include "pkcs11.h"

extern "C" {
CK_DECLARE_FUNCTION(CK_RV, C_GetFunctionStatus)(CK_SESSION_HANDLE hSession);

CK_DECLARE_FUNCTION(CK_RV, C_CancelFunction)(CK_SESSION_HANDLE hSession);
}

#endif