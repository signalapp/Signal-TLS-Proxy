# =====================================
# Makefile for VPN User Project
# Supports: Linux & macOS
# Handles Multiple Main Functions and Tests
# =====================================

# Compiler and Flags
CC = gcc
CFLAGS = -Wall -Wextra -std=c11
LDFLAGS = -lssl -lcrypto

# Source Files
VPN_LIB_SRC = vpn_user_lib.c
VPN_MAIN_SRC = create_vpn_user.c
UNIT_TEST_SRC = unit_tests.c
FUNC_TEST_SRC = functional_tests.c

# Object Files
VPN_LIB_OBJ = vpn_user_lib.o
VPN_MAIN_OBJ = create_vpn_user.o
UNIT_TEST_OBJ = unit_tests.o
FUNC_TEST_OBJ = functional_tests.o

# Targets
VPN_TARGET = create_vpn_user
UNIT_TEST_TARGET = unit_tests
FUNC_TEST_TARGET = functional_tests

# OS Detection
UNAME_S := $(shell uname -s)

ifeq ($(UNAME_S), Darwin)
    # macOS-specific settings
    OPENSSL_PREFIX := $(shell brew --prefix openssl 2>/dev/null)
    ifeq ($(OPENSSL_PREFIX),)
        $(error OpenSSL not found. Install it with 'brew install openssl')
    endif
    CFLAGS += -I$(OPENSSL_PREFIX)/include
    LDFLAGS += -L$(OPENSSL_PREFIX)/lib
endif

ifeq ($(UNAME_S), Linux)
    # Linux-specific settings
    OPENSSL_INCLUDE = /usr/include/openssl
    OPENSSL_LIB = /usr/lib
    CFLAGS += -I$(OPENSSL_INCLUDE)
    LDFLAGS += -L$(OPENSSL_LIB)
endif

# =====================================
# Build Targets
# =====================================

# Default target
all: $(VPN_TARGET) $(UNIT_TEST_TARGET) $(FUNC_TEST_TARGET)

# Build VPN Library Object
$(VPN_LIB_OBJ): $(VPN_LIB_SRC) vpn_common.h
	@echo "🔧 Compiling VPN library into object file..."
	$(CC) $(CFLAGS) -c $(VPN_LIB_SRC) -o $(VPN_LIB_OBJ)

# Build Main Program
$(VPN_MAIN_OBJ): $(VPN_MAIN_SRC) vpn_common.h
	@echo "🔧 Compiling main application into object file..."
	$(CC) $(CFLAGS) -c $(VPN_MAIN_SRC) -o $(VPN_MAIN_OBJ)

# Link Main Program
$(VPN_TARGET): $(VPN_LIB_OBJ) $(VPN_MAIN_OBJ)
	@echo "🔧 Building main application (create_vpn_user)..."
	$(CC) $(CFLAGS) $(VPN_LIB_OBJ) $(VPN_MAIN_OBJ) -o $(VPN_TARGET) $(LDFLAGS)
	@echo "✅ Built $(VPN_TARGET)"

# Build Unit Tests
$(UNIT_TEST_TARGET): $(UNIT_TEST_SRC) $(VPN_LIB_OBJ)
	@echo "🧪 Building Unit Tests..."
	$(CC) $(CFLAGS) $(UNIT_TEST_SRC) $(VPN_LIB_OBJ) -o $(UNIT_TEST_TARGET) $(LDFLAGS)
	@echo "✅ Built $(UNIT_TEST_TARGET)"

# Build Functional Tests
$(FUNC_TEST_TARGET): $(FUNC_TEST_SRC) $(VPN_LIB_OBJ)
	@echo "🛠️ Building Functional Tests..."
	$(CC) $(CFLAGS) $(FUNC_TEST_SRC) $(VPN_LIB_OBJ) -o $(FUNC_TEST_TARGET) $(LDFLAGS)
	@echo "✅ Built $(FUNC_TEST_TARGET)"

# =====================================
# Run Targets
# =====================================

# Run Main Program
run: $(VPN_TARGET)
	@echo "🚀 Running $(VPN_TARGET)..."
	./$(VPN_TARGET)

# Run Unit Tests
run_unit_tests: $(UNIT_TEST_TARGET)
	@echo "🧪 Running Unit Tests..."
	./$(UNIT_TEST_TARGET)

# Run Functional Tests
run_func_tests: $(FUNC_TEST_TARGET)
	@echo "🛠️ Running Functional Tests..."
	./$(FUNC_TEST_TARGET)

# =====================================
# Utility Targets
# =====================================

# Show Build Information
info:
	@echo "📊 Build Information:"
	@echo "Detected OS: $(UNAME_S)"
	@echo "Compiler: $(CC)"
	@echo "OpenSSL Include Path: $(OPENSSL_INCLUDE) $(OPENSSL_PREFIX)/include"
	@echo "OpenSSL Library Path: $(OPENSSL_LIB) $(OPENSSL_PREFIX)/lib"

# Clean Build Files
clean:
	@echo "🧹 Cleaning build files..."
	rm -f $(VPN_TARGET) $(UNIT_TEST_TARGET) $(FUNC_TEST_TARGET) $(VPN_LIB_OBJ) $(VPN_MAIN_OBJ) *.o
	@echo "✅ Clean complete"

# Force Make to not treat these as file names
.PHONY: all clean run run_unit_tests run_func_tests info

