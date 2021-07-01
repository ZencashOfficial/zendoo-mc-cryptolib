EXECUTABLES = g++ cargo
K := $(foreach exec,$(EXECUTABLES),\
        $(if $(shell PATH=$(PATH) command -v $(exec)),,$(error "No $(exec) in PATH")))
CXX ?= g++
CARGO_BIN ?= cargo
ifeq ($(shell env | grep RUSTFLAGS),)
	RUSTFLAGS := -C target-feature=+bmi2,+adx --emit=asm
endif
RUST_FILES := $(shell find ../src/ -type f -name '*.rs')
CARGO_FILES := $(shell find ../ -maxdepth 1 -type f -name '*.toml' -or -name '*.lock')
RUST_LIB := ../target/release/libzendoo_mc.a
CXX_FILE := ./sampleCalls.cpp
INCLUDE := ../include
INCLUDE_FILES := $(wildcard $(INCLUDE)/*.h)

.PHONY: all
all: clean example

.PHONY: clean-cargo
clean-cargo:
	RUSTFLAGS='$(RUSTFLAGS)' $(CARGO_BIN) $(CARGOARGS) clean

.PHONY: clean-test
clean-test:
	rm -f ./bin_SampleCalls

.PHONY: clean
clean: clean-cargo clean-test

.PHONY: libs
libs: $(RUST_LIB)

$(RUST_LIB): $(CARGO_FILES) $(RUST_FILES)
	RUSTFLAGS='$(RUSTFLAGS)' $(CARGO_BIN) $(CARGOARGS) build --release --all-features

.PHONY: build
build: libs ./bin_SampleCalls

./bin_SampleCalls: $(CXX_FILE) $(INCLUDE_FILES)
	$(CXX) -o $@ $(CXX_FILE) -I$(INCLUDE)  -L. -l:$(RUST_LIB) -lpthread -ldl

.PHONY: example
example: build
	./bin_SampleCalls --abort-after=1
