#ifndef PKCS11_SLOTANDTOKEN_H
#define PKCS11_SLOTANDTOKEN_H

#include <algorithm>
#include <cassert>
#include <cstring>
#include <stdlib.h>
#include <string.h>
#include <string>

#include <PCSC/pcsclite.h>
#include <PCSC/winscard.h>
#include <PCSC/wintypes.h>

#include "pcsclite.h"
#include "state.h"
#include "winscard.h"

#include "pkcs11.h"
#include "state.h"

#include "oasis/pkcs11t.h"

extern "C" {
CK_DECLARE_FUNCTION(CK_RV, C_GetSlotList)(
	CK_BBOOL tokenPresent,
	CK_SLOT_ID_PTR pSlotList,
	CK_ULONG_PTR pulCount);

CK_DECLARE_FUNCTION(CK_RV, C_GetSlotInfo)(
	CK_SLOT_ID slotID,
	CK_SLOT_INFO_PTR pInfo);

CK_DECLARE_FUNCTION(CK_RV, C_GetTokenInfo)(
	CK_SLOT_ID slotID,
	CK_TOKEN_INFO_PTR pInfo);

CK_DECLARE_FUNCTION(CK_RV, C_WaitForSlotEvent)(
	CK_FLAGS flags,
	CK_SLOT_ID_PTR pSlot,
	CK_VOID_PTR pReserved);

CK_DECLARE_FUNCTION(CK_RV, C_GetMechanismList)(
	CK_SLOT_ID slotID,
	CK_MECHANISM_TYPE_PTR pMechanismList,
	CK_ULONG_PTR pulCount);

CK_DECLARE_FUNCTION(CK_RV, C_GetMechanismInfo)(
	CK_SLOT_ID slotID,
	CK_MECHANISM_TYPE type,
	CK_MECHANISM_INFO_PTR pInfo);

CK_DECLARE_FUNCTION(CK_RV, C_InitToken)(
	CK_SLOT_ID slotID,
	CK_UTF8CHAR_PTR pPin,
	CK_ULONG ulPinLen,
	CK_UTF8CHAR_PTR pLabel);

CK_DECLARE_FUNCTION(CK_RV, C_InitPIN)(
	CK_SESSION_HANDLE hSession,
	CK_UTF8CHAR_PTR pPin,
	CK_ULONG ulPinLen);

CK_DECLARE_FUNCTION(CK_RV, C_SetPIN)(
	CK_SESSION_HANDLE hSession,
	CK_UTF8CHAR_PTR pOldPin,
	CK_ULONG ulOldLen,
	CK_UTF8CHAR_PTR pNewPin,
	CK_ULONG ulNewLen);
}

#endif