CXX = g++
OASIS_URL = https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/include/pkcs11-v2.40
CXXFLAGS += -I/usr/local/include -I/usr/include/PCSC -fPIC -Wall -std=c++20
LDFLAGS = -shared

SRC = state.cpp \
    pkcs11Decryption.cpp \
	pkcs11Digest.cpp \
	pkcs11DualPurpose.cpp \
	pkcs11DualPurpose.cpp \
	pkcs11Encryption.cpp \
	pkcs11General.cpp \
	pkcs11KeyManagement.cpp \
	pkcs11ObjectManagement.cpp \
	pkcs11Parallel.cpp \
	pkcs11Random.cpp \
	pkcs11Session.cpp \
	pkcs11Sign.cpp \
	pkcs11SlotAndToken.cpp \
	pkcs11Verify.cpp
BUILD_DIR = build
OBJ = $(patsubst %.cpp, $(BUILD_DIR)/%.o, $(SRC))
TARGET = srb-id-pkcs11-x64.so

PKCS11_DIR = src/oasis
PKCS11_HEADERS = \
	$(PKCS11_DIR)/pkcs11.h \
	$(PKCS11_DIR)/pkcs11f.h \
	$(PKCS11_DIR)/pkcs11t.h

.PHONY: clean

all: $(TARGET)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(TARGET): $(OBJ)
	$(CXX) $(LDFLAGS) -o $@ $^ -lpcsclite

$(BUILD_DIR)/%.o: ./src/%.cpp | $(BUILD_DIR) $(PKCS11_HEADERS)
	$(CXX) $(CXXFLAGS) -c -o $@ $<

$(PKCS11_HEADERS):
	mkdir -p src/oasis
	@if [ ! -f "$(PKCS11_DIR)/pkcs11.h" ]; then \
		curl --output $(PKCS11_DIR)/pkcs11.h $(OASIS_URL)/pkcs11.h; \
		curl --output $(PKCS11_DIR)/pkcs11f.h $(OASIS_URL)/pkcs11f.h; \
		curl --output $(PKCS11_DIR)/pkcs11t.h $(OASIS_URL)/pkcs11t.h; \
	fi

clean:
	rm -rf $(BUILD_DIR) $(TARGET)
