#include "pkcs11SlotAndToken.h"

unsigned int nextReaderId = 1;

CK_DECLARE_FUNCTION(CK_RV, C_GetSlotList)(
	CK_BBOOL tokenPresent,
	CK_SLOT_ID_PTR pSlotList,
	CK_ULONG_PTR pulCount) {
	if(!initialized) {
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}

	if(pulCount == NULL) {
		return CKR_ARGUMENTS_BAD;
	}

	LONG rv;
	LPSTR mszReaders;
	DWORD dwReaders;

	dwReaders = SCARD_AUTOALLOCATE;

	rv = SCardListReaders(smartCardContextHandle, NULL, (LPSTR)&mszReaders, &dwReaders);
	if(rv == SCARD_E_NO_MEMORY) {
		return CKR_HOST_MEMORY;
	}
	if(rv != SCARD_S_SUCCESS && rv != SCARD_E_NO_READERS_AVAILABLE) {
		return CKR_GENERAL_ERROR;
	}

	for(auto& [_, readerState] : readerStates) {
		readerState.active		 = false;
		readerState.tokenPresent = false;
	}

	if(rv != SCARD_E_NO_READERS_AVAILABLE) {
		char* p = mszReaders;
		while(*p) {
			int readerNameLength = strlen(p);
			std::string readerName(p, readerNameLength);

			auto it = std::find_if(readerStates.begin(), readerStates.end(), [&readerName](const auto& pair) { return pair.second.name == readerName; });

			if(it != readerStates.end()) {
				it->second.active = true;
			} else {
				readerStates[nextReaderId] = ReaderState{readerName, true, false};
				nextReaderId++;
			}

			p += readerNameLength + 1;
		}
	}

	rv = SCardFreeMemory(smartCardContextHandle, mszReaders);
	if(rv != SCARD_S_SUCCESS) {
		return CKR_GENERAL_ERROR;
	}

	bool onlyWithTokenPresent = tokenPresent == CK_TRUE;

	if(onlyWithTokenPresent) {
		for(auto& [id, readerState] : readerStates) {
			if(readerState.active) {
				SCARDHANDLE cardHandle;
				DWORD activeProtocol;

				char* readerName = new char[readerState.name.length()];
				std::strcpy(readerName, readerState.name.c_str());

				rv = SCardConnect(smartCardContextHandle, readerName, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &cardHandle, &activeProtocol);

				delete[] readerName;

				if(rv == SCARD_S_SUCCESS) {
					readerState.tokenPresent = true;
					SCardDisconnect(cardHandle, SCARD_LEAVE_CARD);
				} else if(rv == SCARD_E_NO_SMARTCARD) {
					readerState.tokenPresent = false;
				} else if(rv == SCARD_W_UNPOWERED_CARD || rv == SCARD_W_UNRESPONSIVE_CARD || rv == SCARD_E_READER_UNAVAILABLE) {
					return CKR_DEVICE_ERROR;
				} else {
					return CKR_GENERAL_ERROR;
				}
			}
		}
	}

	auto forReturn = [&onlyWithTokenPresent](ReaderState s) { return s.active && (!onlyWithTokenPresent || s.tokenPresent); };

	unsigned long noOfSlots = (unsigned long)std::count_if(
		readerStates.begin(),
		readerStates.end(),
		[forReturn](const auto& pair) { return forReturn(pair.second); });

	if(pSlotList != NULL_PTR) {
		if(*pulCount < noOfSlots) {
			return CKR_BUFFER_TOO_SMALL;
		} else {
			unsigned int i = 0;
			for(auto& [id, readerState] : readerStates) {
				if(forReturn(readerState)) {
					pSlotList[i++] = id;
				}
			}
		}
	}

	*pulCount = noOfSlots;

	return CKR_OK;
}

CK_DECLARE_FUNCTION(CK_RV, C_GetSlotInfo)(
	CK_SLOT_ID slotID,
	CK_SLOT_INFO_PTR pInfo) {
	if(!initialized) {
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}

	if(pInfo == NULL) {
		return CKR_ARGUMENTS_BAD;
	}

	if(!readerStates.contains(slotID)) {
		return CKR_SLOT_ID_INVALID;
	}

	ReaderState readerState = readerStates[slotID];

	char* readerName = new char[readerState.name.length()];
	std::strcpy(readerName, readerState.name.c_str());

	bool cardPresent = false;
	SCARDHANDLE cardHandle;
	DWORD activeProtocol;

	LONG rv = SCardConnect(smartCardContextHandle, readerName, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &cardHandle, &activeProtocol);
	if(rv != SCARD_S_SUCCESS) {
		cardPresent = true;
		SCardDisconnect(cardHandle, SCARD_LEAVE_CARD);
	} else if(rv != SCARD_E_NO_SMARTCARD) {
		cardPresent = false;
	} else if(rv == SCARD_W_UNPOWERED_CARD || rv == SCARD_W_UNRESPONSIVE_CARD || rv == SCARD_E_READER_UNAVAILABLE) {
		return CKR_DEVICE_ERROR;
	} else {
		return CKR_GENERAL_ERROR;
	}

	std::memset(pInfo->slotDescription, ' ', sizeof(pInfo->slotDescription));
	std::strncpy((char*)pInfo->slotDescription, readerName, sizeof(pInfo->slotDescription));
	std::memset(pInfo->manufacturerID, ' ', sizeof(pInfo->manufacturerID));
	pInfo->flags				 = CKF_HW_SLOT | CKF_REMOVABLE_DEVICE | (cardPresent ? CKF_TOKEN_PRESENT : 0);
	pInfo->hardwareVersion.major = 0x01;
	pInfo->hardwareVersion.minor = 0x00;
	pInfo->firmwareVersion.major = 0x01;
	pInfo->firmwareVersion.minor = 0x00;

	delete[] readerName;

	return CKR_OK;
}

CK_DECLARE_FUNCTION(CK_RV, C_GetTokenInfo)(
	CK_SLOT_ID slotID,
	CK_TOKEN_INFO_PTR pInfo) {
	if(!initialized) {
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}

	if(pInfo == NULL) {
		return CKR_ARGUMENTS_BAD;
	}

	if(!readerStates.contains(slotID)) {
		return CKR_SLOT_ID_INVALID;
	}

	ReaderState readerState = readerStates[slotID];

	char* readerName = new char[readerState.name.length()];
	std::strcpy(readerName, readerState.name.c_str());

	SCARDHANDLE hCard;
	DWORD dwActiveProtocol;

	LONG rv = SCardConnect(smartCardContextHandle, readerName, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &hCard, &dwActiveProtocol);
	delete[] readerName;

	if(rv != SCARD_S_SUCCESS) {
		SCardDisconnect(smartCardContextHandle, SCARD_LEAVE_CARD);
	} else if(rv != SCARD_E_NO_SMARTCARD) {
		return CKR_TOKEN_NOT_PRESENT;
	} else if(rv == SCARD_W_UNPOWERED_CARD || rv == SCARD_W_UNRESPONSIVE_CARD || rv == SCARD_E_READER_UNAVAILABLE) {
		return CKR_DEVICE_ERROR;
	} else {
		return CKR_GENERAL_ERROR;
	}

	return CKR_OK;
}

CK_DECLARE_FUNCTION(CK_RV, C_WaitForSlotEvent)(
	CK_FLAGS flags,
	CK_SLOT_ID_PTR pSlot,
	CK_VOID_PTR pReserved) {
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_GetMechanismList)(
	CK_SLOT_ID slotID,
	CK_MECHANISM_TYPE_PTR pMechanismList,
	CK_ULONG_PTR pulCount) {
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_GetMechanismInfo)(
	CK_SLOT_ID slotID,
	CK_MECHANISM_TYPE type,
	CK_MECHANISM_INFO_PTR pInfo) {
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_InitToken)(
	CK_SLOT_ID slotID,
	CK_UTF8CHAR_PTR pPin,
	CK_ULONG ulPinLen,
	CK_UTF8CHAR_PTR pLabel) {
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_InitPIN)(
	CK_SESSION_HANDLE hSession,
	CK_UTF8CHAR_PTR pPin,
	CK_ULONG ulPinLen) {
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_SetPIN)(
	CK_SESSION_HANDLE hSession,
	CK_UTF8CHAR_PTR pOldPin,
	CK_ULONG ulOldLen,
	CK_UTF8CHAR_PTR pNewPin,
	CK_ULONG ulNewLen) {
	return CKR_FUNCTION_NOT_SUPPORTED;
}
