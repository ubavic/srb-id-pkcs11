#ifndef SESSION_H
#define SESSION_H

#include <memory>
#include <mutex>
#include <string>

#include "pkcs11.h"

#include "smartCard.h"

class Session {
  private:
	SmartCard card;
	bool loggedIn;
	bool closed;
	std::mutex mu;

  public:
	Session(SmartCard card);
	void LogIn(CK_USER_TYPE userType, std::string pin);
	void LogOut();
	void Close();
	bool Closed() const;
	CK_SLOT_ID SlotId() const;
};

std::map<CK_SESSION_HANDLE, std::unique_ptr<Session>> sessions;

#endif