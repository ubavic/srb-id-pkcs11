#ifndef SMARTCARD_H
#define SMARTCARD_H

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <sys/types.h>
#include <vector>

#include <PCSC/pcsclite.h>
#include <PCSC/winscard.h>
#include <PCSC/wintypes.h>

#include "pkcs11.h"

#include "smartCardException.h"

#include "state.h"

class SmartCard {
  private:
	SCARDHANDLE hCard;
	DWORD dwActiveProtocol;
	CK_SLOT_ID slotID;

	std::vector<uint8_t> Transmit(std::vector<uint8_t> apdu);

	std::vector<uint8_t> ReadBinary(uint32_t offset, uint32_t length);

	std::vector<uint8_t> SelectFile(const std::vector<uint8_t>& name, uint32_t ne);

	std::vector<uint8_t> ReadFile(const std::vector<uint8_t>& name);

	std::vector<uint8_t> PadPin(const std::string& pin);

	int PinTriesLeft(const std::vector<uint8_t>& rsp);

  public:
	SmartCard(SCARDCONTEXT hContext, CK_SLOT_ID slotID);

	~SmartCard();

	std::vector<uint8_t> BuildAPDU(uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2, const std::vector<uint8_t>& data, uint32_t ne);

	void InitCrypto();

	int VerifyOldPin(const std::string& oldPin);

	int ChangePin(const std::string& newPin, const std::string& oldPin);

	bool ResponseOK(const std::vector<uint8_t>& response);

	bool ValidatePin(const std::string& pin);

	CK_SLOT_ID SlotId() const;
};

#endif