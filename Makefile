CC      ?= gcc
CFLAGS  ?= -O3 -march=native -std=gnu11 -Wall -Wextra -Wpedantic -Iinclude -Isrc
LDFLAGS ?=
NVCC    ?= nvcc
CUDA_ARCH ?= native
CUDAFLAGS ?= -O3 -std=c++17 -arch=$(CUDA_ARCH) -Xptxas=-warn-spills -Iinclude -Isrc
PYTHON  ?= python3
IVERILOG ?= iverilog
VVP     ?= vvp
GOWIN   ?= $(HOME)/gowin/Gowin_V1.9.12.02_linux
GW_SH   ?= $(GOWIN)/IDE/bin/gw_sh

BUILD   := build
GEN     := src/gen
FPGA_GEN := fpga/generated

LIB_SRC := src/variant.c src/keyschedule.c src/present_core.c \
           src/present_ref.c src/present_table.c src/present_table_x.c \
           src/present_bitslice.c src/present_avx2.c \
           $(GEN)/variants_gen.c
LIB_OBJ := $(patsubst %.c,$(BUILD)/%.o,$(LIB_SRC))

GENERATED := $(GEN)/variants_gen.c $(GEN)/sbox_circuits.h $(GEN)/lin_consts.h \
             $(GEN)/lin444_bodies.h
VARIANT_JSON := $(wildcard variants/*.json)

TESTS   := $(BUILD)/test_vectors $(BUILD)/test_impls $(BUILD)/test_variants
BINS    := $(BUILD)/present-cli $(BUILD)/bench $(BUILD)/shiftgen_present \
           $(BUILD)/wide_bench $(BUILD)/avalanche $(TESTS)

.PHONY: all clean test bench gpu-bench generate variants analysis report validate-artifact \
        fpga-generate fpga-kat fpga-gowin-check fpga-gowin-build fpga-gowin-report \
        fpga-capacity distclean

all: $(BINS)

# --- code generation ---------------------------------------------------------------
$(BUILD)/sbox_synth: tools/sbox_synth.c | $(BUILD)
	$(CC) -O2 -std=gnu11 -Wall -o $@ $<

# Rotation-constant search for the lin444 linear layer. Standalone: it depends on
# nothing in src/, and its output is pasted into a variant's "linear" block.
$(BUILD)/shiftgen_present: tools/shiftgen_present.c | $(BUILD)
	$(CC) -O2 -std=gnu11 -Wall -Wextra -o $@ $<

$(GENERATED): $(VARIANT_JSON) tools/gen_c.py $(BUILD)/sbox_synth
	$(PYTHON) tools/gen_c.py --synth $(BUILD)/sbox_synth

generate: $(GENERATED)

# Regenerate the variant JSON files themselves (searches for S-boxes; slow-ish).
variants:
	$(PYTHON) tools/make_variants.py

# --- library -----------------------------------------------------------------------
# -MMD -MP writes a .d file naming every header the object really used, so editing
# a header rebuilds what depends on it. Without this, a change to a header that is
# not in $(GENERATED) -- src/lin444_body.h, say -- leaves stale objects behind and
# the next benchmark silently measures the old code.
$(BUILD)/%.o: %.c $(GENERATED) | $(BUILD)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -MMD -MP -c -o $@ $<

-include $(shell find $(BUILD) -name '*.d' 2>/dev/null)

$(BUILD)/present-cli: src/cli.c $(LIB_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(BUILD)/bench: bench/bench_main.c $(LIB_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# The 128-bit block ciphers (real AES, AES-lin444) are self-contained: they share no
# code with src/, which is 64-bit throughout, only the measurement protocol -- and
# the generated S-box circuit header, so that the bitsliced AES S-box measured here
# is the same circuit the 64-bit variants use rather than a second copy of it.
$(BUILD)/wide_bench: bench/wide_bench.c $(GEN)/sbox_circuits.h | $(BUILD)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

$(BUILD)/gpu_bench: bench/gpu_bench.cu | $(BUILD)
	$(NVCC) $(CUDAFLAGS) -o $@ $<

$(BUILD)/avalanche: bench/avalanche.c $(LIB_OBJ)
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

gpu-bench: $(BUILD)/gpu_bench
	@mkdir -p results
	$(BUILD)/gpu_bench --csv results/gpu-speed.csv

fpga-generate:
	$(PYTHON) tools/gen_fpga.py generate

fpga-kat: fpga-generate | $(BUILD)
	@set -e; \
	for mod in $$(cat $(FPGA_GEN)/modules.txt); do \
		echo "== $$mod"; \
		$(IVERILOG) -g2012 -o $(BUILD)/$$mod.vvp $(FPGA_GEN)/$$mod.v $(FPGA_GEN)/tb/tb_$$mod.v; \
		$(VVP) $(BUILD)/$$mod.vvp; \
	done

fpga-gowin-check:
	$(PYTHON) tools/gen_fpga.py check-gowin --gw-sh $(GW_SH)

fpga-gowin-build: fpga-generate fpga-gowin-check
	GOWIN="$(GOWIN)" GW_SH="$(GW_SH)" fpga/build_all_gowin.sh

fpga-gowin-report:
	$(PYTHON) tools/gowin_collect.py

fpga-capacity:
	$(PYTHON) tools/fpga_capacity.py

analysis:
	$(PYTHON) analysis/cli.py analyze --all

report:
	$(PYTHON) analysis/cli.py report

validate-artifact:
	$(PYTHON) tools/validate_artifact.py

clean:
	rm -rf $(BUILD)

distclean: clean
	rm -f $(GENERATED)
