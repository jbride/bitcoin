# libbitcoinpqc - Post-Quantum Cryptography for Bitcoin
# Main Makefile for building, testing, and installing the C library

# User-configurable variables
PREFIX ?= /usr/local
DEBUG ?= 0
VERBOSE ?= 0
NO_COLOR ?= 0

# Tool detection
CMAKE := $(shell command -v cmake 2> /dev/null)

# Build directories
BUILD_DIR := build

# Colors for terminal output
ifeq ($(NO_COLOR), 0)
  GREEN := \033[0;32m
  YELLOW := \033[0;33m
  RED := \033[0;31m
  BLUE := \033[0;34m
  NC := \033[0m # No Color
else
  GREEN :=
  YELLOW :=
  RED :=
  BLUE :=
  NC :=
endif

# Default target
.PHONY: all
all: info c-lib

.PHONY: everything
everything: all examples tests

# Print build information
.PHONY: info
info:
	@echo -e "${BLUE}Building libbitcoinpqc - Post-Quantum Cryptography for Bitcoin${NC}"
	@echo -e "${BLUE}------------------------------------------------------------${NC}"
	@if [ -n "$(CMAKE)" ]; then echo -e "  [${GREEN}✓${NC}] CMake: $(CMAKE)"; else echo -e "  [${RED}✗${NC}] CMake (required for C library)"; fi
	@echo -e "${BLUE}------------------------------------------------------------${NC}"
	@echo -e "${YELLOW}Available make targets:${NC}"
	@echo -e "  ${GREEN}make c-lib${NC}        - Build the C library"
	@echo -e "  ${GREEN}make examples${NC}     - Build example programs"
	@echo -e "  ${GREEN}make everything${NC}   - Build all components (library, examples, tests)"
	@echo -e "  ${GREEN}make help${NC}         - Show all available targets"
	@echo -e "${BLUE}------------------------------------------------------------${NC}"

# C library targets
.PHONY: c-lib
c-lib: cmake-configure cmake-build

.PHONY: cmake-configure
cmake-configure:
	@echo -e "${BLUE}Configuring C library with CMake...${NC}"
	@mkdir -p $(BUILD_DIR)
	@cd $(BUILD_DIR) && cmake .. -DCMAKE_BUILD_TYPE=$(if $(filter 1,$(DEBUG)),Debug,Release) -DBUILD_EXAMPLES=ON -DCMAKE_INSTALL_PREFIX=$(PREFIX)

.PHONY: cmake-build
cmake-build:
	@echo -e "${BLUE}Building C library...${NC}"
	@cmake --build $(BUILD_DIR) $(if $(filter 1,$(VERBOSE)),--verbose,)

# Example targets
.PHONY: examples
examples: c-lib
	@echo -e "${BLUE}Building C examples...${NC}"
	@cmake --build $(BUILD_DIR) --target examples

# Testing targets
.PHONY: tests
tests: test-c

.PHONY: test-c
test-c: c-lib
	@echo -e "${BLUE}Running C tests...${NC}"
	@cd $(BUILD_DIR) && ctest $(if $(filter 1,$(VERBOSE)),-V,)

# Installation targets
.PHONY: install
install: c-lib
	@echo -e "${BLUE}Installing C library to $(PREFIX)...${NC}"
	@cd $(BUILD_DIR) && cmake --install .

# Clean targets
.PHONY: clean
clean:
	@echo -e "${BLUE}Cleaning build files...${NC}"
	@rm -rf $(BUILD_DIR)

# Help target
.PHONY: help
help:
	@echo -e "${BLUE}libbitcoinpqc Makefile Help${NC}"
	@echo -e "${BLUE}-------------------------${NC}"
	@echo -e "Main targets:"
	@echo -e "  ${GREEN}all${NC}             - Build the C library (default)"
	@echo -e "  ${GREEN}everything${NC}      - Build all components including examples and tests"
	@echo -e "  ${GREEN}c-lib${NC}           - Build the C library"
	@echo -e "  ${GREEN}examples${NC}        - Build example programs"
	@echo -e "  ${GREEN}tests${NC}           - Run all tests"
	@echo -e "  ${GREEN}install${NC}         - Install the library"
	@echo -e "  ${GREEN}clean${NC}           - Clean all build files"
	@echo -e "  ${GREEN}help${NC}            - Display this help message"
	@echo -e "  ${GREEN}fix-warnings${NC}    - Fix common build warnings"
	@echo -e "  ${GREEN}troubleshoot${NC}    - Display troubleshooting information"
	@echo -e ""
	@echo -e "Developer targets:"
	@echo -e "  ${GREEN}dev${NC}             - Run format, lint, and analyze"
	@echo -e "  ${GREEN}format${NC}          - Format C code"
	@echo -e "  ${GREEN}lint${NC}            - Lint C code"
	@echo -e "  ${GREEN}analyze${NC}         - Run static analysis on C code"
	@echo -e "  ${GREEN}dev-deps${NC}        - Install development dependencies"
	@echo -e ""
	@echo -e "Configuration options:"
	@echo -e "  ${YELLOW}DEBUG=1${NC}          - Build in debug mode (default: 0)"
	@echo -e "  ${YELLOW}VERBOSE=1${NC}        - Show verbose build output (default: 0)"
	@echo -e "  ${YELLOW}PREFIX=/path${NC}     - Installation prefix (default: /usr/local)"
	@echo -e "  ${YELLOW}NO_COLOR=1${NC}       - Disable colored output (default: 0)"

# Fix warnings targets
.PHONY: fix-warnings
fix-warnings:
	@echo -e "${BLUE}Fixing CRYPTO_ALGNAME redefinition warnings...${NC}"
	@echo -e "${YELLOW}This functionality has been removed.${NC}"
	@echo -e "${GREEN}Please edit CMakeLists.txt manually if needed.${NC}"

# Troubleshooting information
.PHONY: troubleshoot
troubleshoot:
	@echo -e "${BLUE}libbitcoinpqc Troubleshooting${NC}"
	@echo -e "${BLUE}---------------------------${NC}"
	@echo -e "Common issues and solutions:"
	@echo -e ""
	@echo -e "  ${YELLOW}CRYPTO_ALGNAME redefinition warnings:${NC}"
	@echo -e "    These are harmless but can be fixed by editing CMakeLists.txt manually"
	@echo -e "    Change CRYPTO_ALGNAME to CRYPTO_ALGNAME_SPHINCS in the target_compile_definitions"
	@echo -e ""
	@echo -e "  ${YELLOW}Example compilation errors:${NC}"
	@echo -e "    If examples don't compile, ensure you're using the latest code."
	@echo -e "    Run: make clean && make"
	@echo -e ""
	@echo -e "  ${YELLOW}Missing tools:${NC}"
	@echo -e "    Make sure you have all required development tools installed."
	@echo -e ""
	@echo -e "  ${YELLOW}Terminal color issues:${NC}"
	@echo -e "    If you see raw escape sequences (like \\033[0;32m), run with NO_COLOR=1"
	@echo -e ""
	@echo -e "  ${YELLOW}For more detailed help:${NC}"
	@echo -e "    Check the README.md or open an issue on GitHub."

# Developer tools
.PHONY: dev
dev: format lint analyze

.PHONY: format
format:
	@echo -e "${BLUE}Formatting code...${NC}"
	@if command -v clang-format > /dev/null; then \
		find src include examples -name "*.c" -o -name "*.h" | xargs clang-format -i -style=file; \
		echo -e "${GREEN}C code formatted${NC}"; \
	else \
		echo -e "${YELLOW}clang-format not found, skipping C formatting${NC}"; \
	fi

.PHONY: lint
lint:
	@echo -e "${BLUE}Linting code...${NC}"
	@if command -v cppcheck > /dev/null; then \
		cppcheck --enable=all --suppressions-list=.cppcheck-suppressions --error-exitcode=0 src include examples; \
		echo -e "${GREEN}C code linted${NC}"; \
	else \
		echo -e "${YELLOW}cppcheck not found, skipping C linting${NC}"; \
	fi

.PHONY: analyze
analyze:
	@echo -e "${BLUE}Analyzing code...${NC}"
	@if command -v scan-build > /dev/null; then \
		scan-build -o analysis-reports cmake --build $(BUILD_DIR); \
		echo -e "${GREEN}Static analysis completed. See analysis-reports directory for results.${NC}"; \
	else \
		echo -e "${YELLOW}scan-build not found, skipping static analysis${NC}"; \
	fi

.PHONY: dev-deps
dev-deps:
	@echo -e "${BLUE}Installing development dependencies...${NC}"
	@if command -v apt-get > /dev/null; then \
		sudo apt-get update && sudo apt-get install -y clang-format cppcheck clang-tools llvm; \
	elif command -v dnf > /dev/null; then \
		sudo dnf install -y clang-tools-extra cppcheck; \
	elif command -v pacman > /dev/null; then \
		sudo pacman -S --needed clang cppcheck; \
	elif command -v brew > /dev/null; then \
		brew install llvm cppcheck; \
	else \
		echo -e "${YELLOW}Could not detect package manager, please install manually:${NC}"; \
		echo "- clang-format (for code formatting)"; \
		echo "- cppcheck (for static analysis)"; \
		echo "- clang tools (for static analysis)"; \
	fi
