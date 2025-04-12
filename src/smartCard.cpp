#include "smartCard.h"

std::vector<uint8_t>
SmartCard::Transmit(std::vector<uint8_t> apdu) {
	BYTE pbRecvBuffer[0xFF];
	DWORD dwRecvLength = sizeof(pbRecvBuffer);
	DWORD dwSendLength = apdu.size();

	LONG rv = SCardTransmit(hCard, SCARD_PCI_T0, apdu.data(), apdu.size(), NULL, pbRecvBuffer, &dwRecvLength);
	if(rv != SCARD_S_SUCCESS) {
		throw SmartCardException(rv);
	}

	return std::vector<uint8_t>(pbRecvBuffer, pbRecvBuffer + dwRecvLength);
}

std::vector<uint8_t>
SmartCard::ReadBinary(uint32_t offset, uint32_t length) {
	uint8_t readSize		  = std::min(length, 0xFFu);
	std::vector<uint8_t> apdu = BuildAPDU(0x00, 0xB0, static_cast<uint8_t>((offset & 0xFF00) >> 8), static_cast<uint8_t>(offset & 0xFF), {}, readSize);

	auto response = Transmit(apdu);
	auto size	  = response.size();
	if(size < 2) {
		throw std::runtime_error("Reading binary: bad status code");
	}

	response.resize(size - 2);
	return response;
}

std::vector<uint8_t>
SmartCard::SelectFile(const std::vector<uint8_t>& name, uint32_t ne) {
	std::vector<uint8_t> apdu = SmartCard::BuildAPDU(0x00, 0xA4, 0x08, 0x00, name, ne);
	return Transmit(apdu);
}

std::vector<uint8_t>
SmartCard::ReadFile(const std::vector<uint8_t>& name) {
	std::vector<uint8_t> output;

	SelectFile(name, 4);

	std::vector<uint8_t> data = ReadBinary(0, 4);
	if(data.size() <= 3) {
		throw std::runtime_error("file too short");
	}

	uint16_t length = (data[2] << 8) | data[3];
	uint32_t offset = data.size();
	while(length > 0) {
		std::vector<uint8_t> chunk = ReadBinary(offset, length);
		output.insert(output.end(), chunk.begin(), chunk.end());
		offset += chunk.size();
		length -= chunk.size();
	}

	return output;
}

std::vector<uint8_t>
SmartCard::PadPin(const std::string& pin) {
	std::vector<uint8_t> data(8, 0);
	for(size_t i = 0; i < pin.size() && i < 8; ++i) {
		data[i] = static_cast<uint8_t>(pin[i]);
	}
	return data;
}

int
SmartCard::PinTriesLeft(const std::vector<uint8_t>& rsp) {
	if(rsp == std::vector<uint8_t>{0x63, 0xC0}) {
		return 0;
	}
	if(rsp == std::vector<uint8_t>{0x63, 0xC1}) {
		return 1;
	}
	if(rsp == std::vector<uint8_t>{0x63, 0xC2}) {
		return 2;
	}
	if(rsp == std::vector<uint8_t>{0x63, 0xC3}) {
		return 3;
	}
	return -1;
}

SmartCard::SmartCard(SCARDCONTEXT hContext, CK_SLOT_ID slotID) {
	this->slotID = slotID;

	auto readerNameString = readerStates[slotID].name;

	char* readerName = new char[readerNameString.length()];
	std::strcpy(readerName, readerNameString.c_str());

	LONG rv = SCardConnect(hContext, readerName, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &hCard, &dwActiveProtocol);
	delete[] readerName;

	if(rv != SCARD_S_SUCCESS) {
		throw SmartCardException(rv);
	}
}

SmartCard::~SmartCard() {
	SCardDisconnect(hCard, SCARD_LEAVE_CARD);
}

std::vector<uint8_t>
SmartCard::BuildAPDU(uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2, const std::vector<uint8_t>& data, uint32_t ne) {
	size_t length = data.size();

	if(length > 0xFFFF) {
		throw std::runtime_error("APDU command length too large");
	}

	std::vector<uint8_t> apdu = {cla, ins, p1, p2};

	if(length == 0) {
		if(ne != 0) {
			if(ne <= 256) {
				uint8_t l = (ne == 256) ? 0x00 : static_cast<uint8_t>(ne);
				apdu.push_back(l);
			} else {
				uint8_t l1 = (ne == 65536) ? 0x00 : static_cast<uint8_t>(ne >> 8);
				uint8_t l2 = (ne == 65536) ? 0x00 : static_cast<uint8_t>(ne);
				apdu.insert(apdu.end(), {l1, l2});
			}
		}
	} else {
		if(ne == 0) {
			if(length <= 255) {
				apdu.push_back(static_cast<uint8_t>(length));
				apdu.insert(apdu.end(), data.begin(), data.end());
			} else {
				apdu.insert(apdu.end(), {0x00, static_cast<uint8_t>(length >> 8), static_cast<uint8_t>(length)});
				apdu.insert(apdu.end(), data.begin(), data.end());
			}
		} else {
			if(length <= 255 && ne <= 256) {
				apdu.push_back(static_cast<uint8_t>(length));
				apdu.insert(apdu.end(), data.begin(), data.end());
				apdu.push_back((ne == 256) ? 0x00 : static_cast<uint8_t>(ne));
			} else {
				apdu.insert(apdu.end(), {0x00, static_cast<uint8_t>(length >> 8), static_cast<uint8_t>(length)});
				apdu.insert(apdu.end(), data.begin(), data.end());
				if(ne != 65536) {
					apdu.insert(apdu.end(), {static_cast<uint8_t>(ne >> 8), static_cast<uint8_t>(ne)});
				}
			}
		}
	}
	return apdu;
}

void
SmartCard::InitCrypto() {
	std::vector<uint8_t> data = {
		0xA0, 0x00, 0x00, 0x00,
		0x63, 0x50, 0x4B, 0x43,
		0x53, 0x2D, 0x31, 0x35};

	std::vector<uint8_t> apdu = SmartCard::BuildAPDU(0x00, 0xA4, 0x04, 0x00, data, 0);

	std::vector<uint8_t> rsp;
	rsp = Transmit(apdu);

	if(!ResponseOK(rsp)) {
		throw std::runtime_error("cryptography application not selected");
	}
}

int
SmartCard::VerifyOldPin(const std::string& oldPin) {
	std::vector<uint8_t> apdu = SmartCard::BuildAPDU(0x00, 0x20, 0x00, 0x80, PadPin(oldPin), 0);
	std::vector<uint8_t> rsp;
	try {
		rsp = Transmit(apdu);
	} catch(const SmartCardException& e) {
		return -1;
	}

	if(!ResponseOK(rsp)) {
		return PinTriesLeft(rsp);
	}

	// TODO
	return -1;
}

int
SmartCard::ChangePin(const std::string& newPin, const std::string& oldPin) {
	// TODO
	// BeginTransaction();

	InitCrypto();

	if(!ValidatePin(oldPin)) {
		throw std::runtime_error("old pin not valid");
	}

	if(!ValidatePin(newPin)) {
		throw std::runtime_error("new pin not valid");
	}

	std::vector<uint8_t> apdu = SmartCard::BuildAPDU(0x00, 0x20, 0x00, 0x80, PadPin(oldPin), 0);
	std::vector<uint8_t> rsp;
	try {
		rsp = Transmit(apdu);
	} catch(const SmartCardException& e) {
		throw std::runtime_error("verifying old pin: " + std::to_string(e.getErrorCode()));
	}

	if(!ResponseOK(rsp)) {
		return PinTriesLeft(rsp);
	}

	std::vector<uint8_t> data;
	data.insert(data.end(), PadPin(oldPin).begin(), PadPin(oldPin).end());
	data.insert(data.end(), PadPin(newPin).begin(), PadPin(newPin).end());

	apdu = SmartCard::BuildAPDU(0x00, 0x24, 0x00, 0x80, data, 0);
	try {
		rsp = Transmit(apdu);
	} catch(const SmartCardException& e) {
		throw std::runtime_error("changing pin: " + std::to_string(e.getErrorCode()));
	}

	if(!ResponseOK(rsp)) {
		return PinTriesLeft(rsp);
	}

	// EndTransaction(SCARD_LEAVE_CARD);

	return -1;
}

bool
ResponseOK(const std::vector<uint8_t>& response) {
	return response.size() >= 2 && response[response.size() - 2] == 0x90 && response[response.size() - 1] == 0x00;
}

bool
ValidatePin(const std::string& pin) {
	if(pin.length() < 4 || pin.length() > 8) {
		return false;
	}

	return std::all_of(pin.begin(), pin.end(), ::isdigit);
}

CK_SLOT_ID
SmartCard::SlotId() const {
	return this->slotID;
}