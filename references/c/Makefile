# YKDF C reference implementation. Requires libsodium and OpenSSL >= 3.5
# (for native ML-KEM / ML-DSA seed key generation), plus python3 to transcribe
# the canonical vectors into a compile-time table.

CC      ?= cc
PKGS    := libsodium libcrypto
CFLAGS  ?= -std=c11 -O2 -Wall -Wextra -Wpedantic
CFLAGS  += -I include -I src $(shell pkg-config --cflags $(PKGS))
LDLIBS  += $(shell pkg-config --libs $(PKGS))

VECTORS := ../../vectors/v1.json
SRC     := src/ykdf.c src/bech32.c src/pqc.c
BUILD   := build
BIN     := $(BUILD)/conformance
GEN     := $(BUILD)/vectors_data.h

.PHONY: test clean
test: $(BIN)
	$(BIN)

$(GEN): $(VECTORS) test/gen_vectors.py | $(BUILD)
	python3 test/gen_vectors.py $(VECTORS) > $@

$(BIN): test/conformance.c $(SRC) include/ykdf.h src/bech32.h $(GEN) | $(BUILD)
	# -Wno-overlength-strings: the generated vector table holds ML-DSA/ML-KEM key
	# literals longer than the C99 guaranteed minimum; the library code itself
	# stays -Wpedantic-clean.
	$(CC) $(CFLAGS) -Wno-overlength-strings -I $(BUILD) test/conformance.c $(SRC) -o $@ $(LDLIBS)

$(BUILD):
	mkdir -p $(BUILD)

clean:
	rm -rf $(BUILD)
