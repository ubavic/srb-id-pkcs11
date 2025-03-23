#ifndef GENERAL_H
#define GENERAL_H

#include <PCSC/pcsclite.h>
#include <PCSC/winscard.h>
#include <PCSC/wintypes.h>

#include "pkcs11.h"
#include "state.h"

#define SRB_ID_PKCS11_VERSION_MAJOR 0
#define SRB_ID_PKCS11_VERSION_MINOR 1

extern "C" {
CK_DECLARE_FUNCTION(CK_RV, C_Initialize)(CK_VOID_PTR pInitArgs);

CK_DECLARE_FUNCTION(CK_RV, C_Finalize)(CK_VOID_PTR pReserved);

CK_DECLARE_FUNCTION(CK_RV, C_GetInfo)(CK_INFO_PTR pInfo);

CK_DECLARE_FUNCTION(CK_RV, C_GetFunctionList)(CK_FUNCTION_LIST_PTR_PTR ppFunctionList);
}

#endif