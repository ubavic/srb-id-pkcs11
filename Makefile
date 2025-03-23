CXX = g++
CXXFLAGS += -I/usr/local/include -I/usr/include/PCSC -fPIC -Wall -std=c++20
LDFLAGS = -shared

SRC = general.cpp \
	state.cpp \
    pkcs11Decryption.cpp \
	pkcs11Digest.cpp \
	pkcs11DualPurpose.cpp \
	pkcs11DualPurpose.cpp \
	pkcs11Encryption.cpp \
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

all: $(TARGET)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(TARGET): $(OBJ)
	$(CXX) $(LDFLAGS) -o $@ $^ -lpcsclite

$(BUILD_DIR)/%.o: ./src/%.cpp | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -c -o $@ $<
	
clean:
	rm -rf $(BUILD_DIR) $(TARGET)
