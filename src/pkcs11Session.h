#ifndef PKCS11_SESSION_H
#define PKCS11_SESSION_H

#include <memory>

#include "pkcs11.h"

#include "session.h"
#include "smartCard.h"
#include "smartCardException.h"
#include "state.h"

#include "state.h"

extern "C" {
CK_DECLARE_FUNCTION(CK_RV, C_OpenSession)(
	CK_SLOT_ID slotID,
	CK_FLAGS flags,
	CK_VOID_PTR pApplication,
	CK_NOTIFY Notify,
	CK_SESSION_HANDLE_PTR phSession);

CK_DECLARE_FUNCTION(CK_RV, C_CloseSession)(CK_SESSION_HANDLE hSession);

CK_DECLARE_FUNCTION(CK_RV, C_CloseAllSessions)(CK_SLOT_ID slotID);

CK_DECLARE_FUNCTION(CK_RV, C_GetSessionInfo)(
	CK_SESSION_HANDLE hSession,
	CK_SESSION_INFO_PTR pInfo);

CK_DECLARE_FUNCTION(CK_RV, C_GetOperationState)(
	CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR pOperationState,
	CK_ULONG_PTR pulOperationStateLen);

CK_DECLARE_FUNCTION(CK_RV, C_SetOperationState)(
	CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR pOperationState,
	CK_ULONG ulOperationStateLen,
	CK_OBJECT_HANDLE hEncryptionKey,
	CK_OBJECT_HANDLE hAuthenticationKey);

CK_DECLARE_FUNCTION(CK_RV, C_Login)(
	CK_SESSION_HANDLE hSession,
	CK_USER_TYPE userType,
	CK_UTF8CHAR_PTR pPin,
	CK_ULONG ulPinLen);

CK_DECLARE_FUNCTION(CK_RV, C_Logout)(CK_SESSION_HANDLE hSession);
}

#endif