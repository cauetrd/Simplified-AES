# Project Settings
CXX := g++
CXXFLAGS := -std=c++17 -Wall -Wextra -O2
TARGET := saes
SRC_DIR := src
BUILD_DIR := build
LIB_DIR := lib

# Cryptopp settings
CRYPTOPP_VERSION := 8.7.0
CRYPTOPP_DIR := $(LIB_DIR)/cryptopp
CRYPTOPP_TAR := cryptopp$(subst .,,$(CRYPTOPP_VERSION)).zip
CRYPTOPP_URL := https://www.cryptopp.com/$(CRYPTOPP_TAR)
CRYPTOPP_LIB := $(CRYPTOPP_DIR)/libcryptopp.a

# Source files
SRCS := $(wildcard $(SRC_DIR)/*.cpp)
OBJS := $(patsubst $(SRC_DIR)/%.cpp,$(BUILD_DIR)/%.o,$(SRCS))

# Directories
DIRS := $(BUILD_DIR) $(LIB_DIR)

.PHONY: all clean cleanall help directories cryptopp debug


# Main targets
all: directories cryptopp $(TARGET)

$(TARGET): $(OBJS) $(CRYPTOPP_LIB)
	$(CXX) $(CXXFLAGS) -o $@ $^ -pthread

# Object files
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.cpp | cryptopp
	$(CXX) $(CXXFLAGS) -c $< -o $@ -I$(CRYPTOPP_DIR)

# Cryptopp Library
cryptopp: $(CRYPTOPP_LIB)

$(CRYPTOPP_LIB): | $(CRYPTOPP_DIR)
	@echo "Building Crypto++ library..."
	@cd $(CRYPTOPP_DIR) && $(MAKE) static
	@echo "Crypto++ library built successfully"

$(CRYPTOPP_DIR): | $(LIB_DIR)
	@echo "Downloading Crypto++ library..."
	@mkdir -p $(CRYPTOPP_DIR)
	@if command -v wget > /dev/null; then \
		wget -q -O $(LIB_DIR)/$(CRYPTOPP_TAR) $(CRYPTOPP_URL); \
	elif command -v curl > /dev/null; then \
		curl -s -o $(LIB_DIR)/$(CRYPTOPP_TAR) $(CRYPTOPP_URL); \
	else \
		echo "Error: Neither wget nor curl is installed"; \
		exit 1; \
	fi
	@unzip -q $(LIB_DIR)/$(CRYPTOPP_TAR) -d $(CRYPTOPP_DIR)
	@rm $(LIB_DIR)/$(CRYPTOPP_TAR)
	@echo "Crypto++ files extracted to $(CRYPTOPP_DIR)"
	@ls -la $(CRYPTOPP_DIR) | head -n 10

# Create necessary directories
directories: $(DIRS)
$(DIRS):
	@mkdir -p $@

# Debug target to show variables
debug:
	@echo "Source files: $(SRCS)"
	@echo "Object files: $(OBJS)"
	@echo "Cryptopp dir: $(CRYPTOPP_DIR)"
	@echo "Cryptopp lib: $(CRYPTOPP_LIB)"
	@ls -la $(CRYPTOPP_DIR) 2>/dev/null || echo "Cryptopp directory does not exist"

# Clean targets
clean:
	@rm -f $(TARGET) $(OBJS)
	@echo "Cleaned project build files"

cleanall: clean
	@rm -rf $(LIB_DIR)
	@echo "Cleaned all build files including libraries"

# Help target
help:
	@echo "Available targets:"
	@echo "  all      - Build everything (default)"
	@echo "  clean    - Remove built project files"
	@echo "  cleanall - Remove all built files including libraries"
	@echo "  debug    - Display debug information"
	@echo "  help     - Display this help message"
