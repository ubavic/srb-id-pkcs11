#include "state.h"

bool initialized = false;

SCARDCONTEXT smartCardContextHandle;

std::map<CK_SLOT_ID, ReaderState> readerStates;
