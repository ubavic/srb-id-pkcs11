#ifndef STATE_H
#define STATE_H

#include <map>

#include <PCSC/pcsclite.h>
#include <PCSC/winscard.h>
#include <PCSC/wintypes.h>
#include <string>

extern bool initialized;

extern SCARDCONTEXT hContext;

typedef struct ReaderState {
	unsigned int id;
	bool active;
	bool tokenPresent;
} ReaderState;

#endif