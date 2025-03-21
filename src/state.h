#ifndef STATE_H
#define STATE_H

#include <map>

#include <PCSC/pcsclite.h>
#include <PCSC/winscard.h>
#include <PCSC/wintypes.h>
#include <string>

#include "pkcs11.h"

extern bool initialized;

extern SCARDCONTEXT smartCardContextHandle;

typedef struct ReaderState {
	std::string name;
	bool active;
	bool tokenPresent;
} ReaderState;

extern std::map<CK_SLOT_ID, ReaderState> readerStates;

#endif