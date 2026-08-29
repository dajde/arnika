# Define the name of the application and its version
NAME := arnika
VERSION := $(shell git describe --tags --always)

# Define the Go compiler and other tools
GO = go

# Build flags
GO_BUILD_VARS := CGO_ENABLED=0 GOEXPERIMENT=runtimesecret
BUILD_FLAGS = -trimpath -ldflags "-w -s -extldflags=-Wl,-Bsymbolic -X 'main.Version=$(VERSION)' -X 'main.APPName=$(NAME)'"
BINARY_NAME ?= arnika
BUILD_DIR ?= build

# Optional Go build tags selecting the key writer backend (see KEYCONTROL.md):
#   (empty)            -> netlink, local WireGuard via wgctrl [default]
#   wireguard_netlink  -> netlink (explicit)
#   wireguard_mikrotik -> MikroTik RouterOS REST API
# Usage: make build BUILD_TAGS=wireguard_mikrotik
BUILD_TAGS ?=
TAGS_FLAG := $(if $(BUILD_TAGS),-tags "$(BUILD_TAGS)",)

# Default target: build the binary
default: build

# Build rule: create a new executable
build:
	@echo "Building $(BINARY_NAME)$(if $(BUILD_TAGS), (tags: $(BUILD_TAGS)),)"
	$(GO_BUILD_VARS) $(GO) build $(BUILD_FLAGS) $(TAGS_FLAG) -o $(BUILD_DIR)/$(BINARY_NAME) .

# Convenience targets for each key writer backend
build-netlink:
	$(MAKE) build BUILD_TAGS=wireguard_netlink

build-mikrotik:
	$(MAKE) build BUILD_TAGS=wireguard_mikrotik

# Clean rule: remove build artifacts
clean:
	rm -rf $(BUILD_DIR)/*

.PHONY: default build build-netlink build-mikrotik clean
