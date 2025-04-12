#include "pkcs11Session.h"

unsigned int nextSessionId = 1;

CK_DECLARE_FUNCTION(CK_RV, C_OpenSession)(
	CK_SLOT_ID slotID,
	CK_FLAGS flags,
	CK_VOID_PTR pApplication,
	CK_NOTIFY Notify,
	CK_SESSION_HANDLE_PTR phSession) {
	if(!initialized) {
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}

	if(!readerStates.contains(slotID)) {
		return CKR_SLOT_ID_INVALID;
	}

	if((flags & CKF_SERIAL_SESSION) == 0) {
		return CKR_SESSION_PARALLEL_NOT_SUPPORTED;
	}

	try {
		SmartCard card			= SmartCard(smartCardContextHandle, slotID);
		sessions[nextSessionId] = std::make_unique<Session>(std::move(card));
		*phSession				= nextSessionId;

		nextSessionId += 1;
	} catch(SmartCardException& e) {
		return CKR_DEVICE_ERROR;
	} catch(...) {
		return CKR_GENERAL_ERROR;
	}

	return CKR_OK;
}

CK_DECLARE_FUNCTION(CK_RV, C_CloseSession)(CK_SESSION_HANDLE hSession) {
	if(!initialized) {
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}

	if(!sessions.contains(hSession)) {
		return CKR_ARGUMENTS_BAD;
	}

	auto session = &sessions[hSession];

	try {
		session->get()->Close();
	} catch(SmartCardException& e) {
		return CKR_DEVICE_ERROR;
	} catch(...) {
		return CKR_GENERAL_ERROR;
	}

	return CKR_OK;
}

CK_DECLARE_FUNCTION(CK_RV, C_CloseAllSessions)(CK_SLOT_ID slotID) {
	if(!initialized) {
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}

	if(!readerStates.contains(slotID)) {
		return CKR_SLOT_ID_INVALID;
	}

	CK_RV error = CKR_OK;

	for(auto& [sessionId, session] : sessions) {
		if(session.get()->SlotId() == slotID && !session.get()->Closed()) {
			error = C_CloseSession(sessionId);
		}
	}

	return error;
}

CK_DECLARE_FUNCTION(CK_RV, C_GetSessionInfo)(
	CK_SESSION_HANDLE hSession,
	CK_SESSION_INFO_PTR pInfo) {
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_GetOperationState)(
	CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR pOperationState,
	CK_ULONG_PTR pulOperationStateLen) {
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_SetOperationState)(
	CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR pOperationState,
	CK_ULONG ulOperationStateLen,
	CK_OBJECT_HANDLE hEncryptionKey,
	CK_OBJECT_HANDLE hAuthenticationKey) {
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_Login)(
	CK_SESSION_HANDLE hSession,
	CK_USER_TYPE userType,
	CK_UTF8CHAR_PTR pPin,
	CK_ULONG ulPinLen) {
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_Logout)(CK_SESSION_HANDLE hSession) {
	return CKR_FUNCTION_NOT_SUPPORTED;
}