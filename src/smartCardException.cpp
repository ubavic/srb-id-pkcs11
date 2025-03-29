#include "smartCardException.h"

LONG
SmartCardException::getErrorCode() const {
	return errorCode;
}