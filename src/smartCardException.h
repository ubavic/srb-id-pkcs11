#ifndef SMART_CARD_EXCEPTION_H
#define SMART_CARD_EXCEPTION_H

#include <stdexcept>

#include <PCSC/wintypes.h>

class SmartCardException : public std::runtime_error {
  public:
	explicit SmartCardException(LONG errorCode)
		: std::runtime_error("smartcard error"), errorCode(errorCode) {
	}

	LONG getErrorCode() const;

  private:
	LONG errorCode;
};

class UnsupportedCardException : public std::runtime_error {
  public:
	explicit UnsupportedCardException()
		: std::runtime_error("unsupported card") {
	}
};

#endif