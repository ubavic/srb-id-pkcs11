#include "session.h"

void
Session::Close() {
	std::lock_guard<std::mutex> lock(this->mu);

	// TODO

	this->closed = true;
}

bool
Session::Closed() const {
	return this->closed;
}

CK_SLOT_ID
Session::SlotId() const {
	return this->card.SlotId();
}

extern std::map<CK_SLOT_ID, ReaderState> readerStates;
