CC      ?= gcc
CFLAGS  ?= -O3 -march=native -std=gnu11 -Wall -Wextra -Wpedantic -Iinclude -Isrc
LDFLAGS ?=
PYTHON  ?= python3

BUILD   := build
GEN     := src/gen

LIB_SRC := src/variant.c src/keyschedule.c src/present_core.c \
           src/present_ref.c src/present_table.c src/present_bitslice.c \
           $(GEN)/variants_gen.c
LIB_OBJ := $(patsubst %.c,$(BUILD)/%.o,$(LIB_SRC))

GENERATED := $(GEN)/variants_gen.c $(GEN)/sbox_circuits.h
VARIANT_JSON := $(wildcard variants/*.json)

TESTS   := $(BUILD)/test_vectors $(BUILD)/test_impls $(BUILD)/test_variants
BINS    := $(BUILD)/present-cli $(BUILD)/bench $(TESTS)

.PHONY: all clean test bench generate variants analysis report distclean

all: $(BINS)

# --- code generation ---------------------------------------------------------------
$(BUILD)/sbox_synth: tools/sbox_synth.c | $(BUILD)
	$(CC) -O2 -std=gnu11 -Wall -o $@ $<

$(GENERATED): $(VARIANT_JSON) tools/gen_c.py $(BUILD)/sbox_synth
	$(PYTHON) tools/gen_c.py --synth $(BUILD)/sbox_synth

generate: $(GENERATED)

# Regenerate the variant JSON files themselves (searches for S-boxes; slow-ish).
variants:
	$(PYTHON) tools/make_variants.py

# --- library -----------------------------------------------------------------------
$(BUILD)/%.o: %.c $(GENERATED) | $(BUILD)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD)/present-cli: src/cli.c $(LIB_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(BUILD)/bench: bench/bench_main.c $(LIB_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(BUILD)/test_%: tests/test_%.c $(LIB_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(BUILD):
	@mkdir -p $(BUILD)

# --- targets ----------------------------------------------------------------------
test: $(TESTS)
	@set -e; for t in $(TESTS); do echo "== $$t"; $$t; done
	@$(PYTHON) -m unittest discover -s analysis/tests -t analysis -v

bench: $(BUILD)/bench
	@mkdir -p results
	$(BUILD)/bench --csv results/speed.csv

analysis:
	$(PYTHON) analysis/cli.py analyze --all

report:
	$(PYTHON) analysis/cli.py report

clean:
	rm -rf $(BUILD)

distclean: clean
	rm -f $(GENERATED)
