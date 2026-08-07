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
           src/present_bitslice.c src/present_bitslice32.c \
           src/present_avx2.c src/present_neon.c \
           $(GEN)/variants_gen.c
LIB_OBJ := $(patsubst %.c,$(BUILD)/%.o,$(LIB_SRC))

GENERATED := $(GEN)/variants_gen.c $(GEN)/sbox_circuits.h $(GEN)/lin_consts.h \
             $(GEN)/lin444_bodies.h

# Derived from $(GEN)/sbox_circuits.h by a pure retype (u64 -> 128-bit vector or
# u64 -> 32-bit word), so these have their own rule rather than being produced by
# the gen_c.py run above.
GENERATED_RETYPED := $(GEN)/sbox_circuits_neon.h $(GEN)/sbox_circuits_u32.h
VARIANT_JSON := $(wildcard variants/*.json)

TESTS   := $(BUILD)/test_vectors $(BUILD)/test_impls $(BUILD)/test_variants \
           $(BUILD)/test_wide_bitslice32
BINS    := $(BUILD)/present-cli $(BUILD)/bench $(BUILD)/shiftgen_present \
           $(BUILD)/wide_bench $(BUILD)/avalanche $(TESTS)

.PHONY: all clean test bench gpu-bench generate variants analysis report validate-artifact \
        fpga-generate fpga-kat fpga-gowin-check fpga-gowin-build fpga-gowin-report \
        fpga-capacity distclean m4-hello m4-clock-check m4-kat m4-kats m4-bench \
        m4-purecore

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

$(GEN)/sbox_circuits_neon.h: $(GEN)/sbox_circuits.h tools/gen_retyped_circuits.py
	$(PYTHON) tools/gen_retyped_circuits.py neon $(GEN)/sbox_circuits.h $@

$(GEN)/sbox_circuits_u32.h: $(GEN)/sbox_circuits.h tools/gen_retyped_circuits.py
	$(PYTHON) tools/gen_retyped_circuits.py u32 $(GEN)/sbox_circuits.h $@

generate: $(GENERATED) $(GENERATED_RETYPED)

# Regenerate the variant JSON files themselves (searches for S-boxes; slow-ish).
variants:
	$(PYTHON) tools/make_variants.py

# --- library -----------------------------------------------------------------------
# -MMD -MP writes a .d file naming every header the object really used, so editing
# a header rebuilds what depends on it. Without this, a change to a header that is
# not in $(GENERATED) -- src/lin444_body.h, say -- leaves stale objects behind and
# the next benchmark silently measures the old code.
$(BUILD)/%.o: %.c $(GENERATED) $(GENERATED_RETYPED) | $(BUILD)
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
$(BUILD)/wide_bench: bench/wide_bench.c bench/wide_ciphers.h $(GEN)/sbox_circuits.h | $(BUILD)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# The accessor the 128-bit ciphers lack: encrypt one named block under one named
# key, so tools/gen_m4_kats.py can ask the host build for a KAT the same way it
# asks present-cli for the 64-bit ciphers'. Self-contained like wide_bench above.
$(BUILD)/m4_kat_oracle: tools/m4_kat_oracle.c bench/wide_ciphers.h | $(BUILD)
	$(CC) $(CFLAGS) -Ibench -o $@ $< $(LDFLAGS)

$(BUILD)/gpu_bench: bench/gpu_bench.cu | $(BUILD)
	$(NVCC) $(CUDAFLAGS) -o $@ $<

$(BUILD)/avalanche: bench/avalanche.c $(LIB_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(BUILD)/test_%: tests/test_%.c $(LIB_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Self-contained like wide_bench above: no LIB_OBJ, just the two 128-bit-cipher
# headers, so its prerequisites are listed explicitly rather than relying on
# $(LIB_OBJ)'s -MMD (test_%'s generic rule above compiles and links in one step,
# which does not track the headers a test includes -- confirmed this bites by
# `touch`ing a header and finding `make` reports the stale binary up to date).
# -Ibench resolves the test's unqualified "wide_ciphers.h" / "wide_bitslice32.h"
# includes the same way wide_bench.c's same-directory quote-include does.
$(BUILD)/test_wide_bitslice32: tests/test_wide_bitslice32.c bench/wide_ciphers.h \
                                bench/wide_bitslice32.h $(GEN)/sbox_circuits_u32.h | $(BUILD)
	$(CC) $(CFLAGS) -Ibench -o $@ $< $(LDFLAGS)

$(BUILD):
	@mkdir -p $(BUILD)

# --- targets ----------------------------------------------------------------------
test: $(TESTS)
	@set -e; for t in $(TESTS); do echo "== $$t"; $$t; done
	@$(PYTHON) -m unittest discover -s analysis/tests -t analysis -v

bench: $(BUILD)/bench
	@mkdir -p results
	$(BUILD)/bench --csv results/speed.csv

# results/gpu-speed.csv is the frozen pre-optimization baseline that
# docs/gpu-optimizations.md compares against, so this target must not write it.
gpu-bench: $(BUILD)/gpu_bench
	@mkdir -p results
	$(BUILD)/gpu_bench --csv results/gpu-speed-optimized.csv

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

# --- STM32F407 firmware ------------------------------------------------------------
# Cross build; shares nothing with the host toolchain above. Note that the firmware
# links src/keyschedule_portable.c and never src/keyschedule.c -- the latter uses
# __int128, which does not exist on Cortex-M4.
M4_CC      := arm-none-eabi-gcc
M4_OBJCOPY := arm-none-eabi-objcopy
M4_FLAGS   := -mcpu=cortex-m4 -mthumb -mfpu=fpv4-sp-d16 -mfloat-abi=hard \
              -O3 -std=gnu11 -Wall -Wextra -ffreestanding -DPRESENT_ENC_ONLY \
              -Iinclude -Isrc -Ifw/m4 -Ibench
M4_LD      := -nostartfiles -Wl,--gc-sections

# Linker scripts. Every firmware ELF depends on all of them (they are tiny, and a
# spurious rebuild is cheaper than a stale one); which one is *used* comes from
# M4_LDS_<name>, defaulting to the product configuration.
M4_LD_SCRIPTS   := fw/m4/link/product.ld fw/m4/link/purecore.ld
M4_LDS_DEFAULT  := fw/m4/link/product.ld
M4_LDS_purecore := fw/m4/link/purecore.ld

# Per-binary extra preprocessor flags, again keyed on the binary name.
M4_DEFS_purecore := -DM4_PURECORE -DM4_CONFIG='"purecore"'

# Boot, clock and host I/O: every firmware binary needs exactly these.
M4_COMMON  := fw/m4/startup_stm32f407.s fw/m4/system_init.c fw/m4/semihost.c \
              fw/m4/libc_shim.c

# Headers a firmware binary may include, listed because the rule below compiles
# and links in one step and so cannot use -MMD (same reason as
# $(BUILD)/test_wide_bitslice32 above -- and confirmed the same way: before this
# line existed, `touch bench/wide_bitslice32.h && make m4-kat` reported "Nothing
# to be done", as did touching any fw/m4/*.h). On a benchmark that is the worst
# form of the bug: it does not fail, it silently times the previous build.
# $(GENERATED_RETYPED) already covers $(GEN)/sbox_circuits_u32.h, which
# bench/wide_bitslice32.h includes.
M4_HDRS    := $(wildcard fw/m4/*.h) bench/wide_ciphers.h bench/wide_bitslice32.h

# One rule for every firmware binary: build/m4/NAME.elf is built from
# fw/m4/NAME_main.c plus $(M4_COMMON) plus that binary's own $(M4_SRC_NAME).
# A later task adds a second binary by dropping in fw/m4/NAME_main.c and (if it
# needs library sources) setting M4_SRC_NAME -- no new recipe.
#
# Compile and link are two steps, not one. `gcc -o x.elf a.c b.c` names every
# intermediate object /tmp/ccXXXXXX.o, with a fresh random stem on every run --
# check any old .map file. A linker script cannot select an input file it cannot
# name, so `*present_bitslice32.o(.text*)` in purecore.ld would have matched
# nothing, silently, and left the code in flash while still linking and running.
# Objects therefore go to build/m4/obj/NAME/<basename>.o, one directory per
# binary because M4_DEFS_<name> can change how a shared source compiles.
M4_OBJDIR   = $(BUILD)/m4/obj/$*
M4_ELF_SRCS = $< $(M4_COMMON) $(M4_SRC_$*)
M4_ELF_OBJS = $(patsubst %,$(M4_OBJDIR)/%.o,$(notdir $(basename $(M4_ELF_SRCS))))
M4_ELF_LDS  = $(if $(M4_LDS_$*),$(M4_LDS_$*),$(M4_LDS_DEFAULT))

.SECONDEXPANSION:
$(BUILD)/m4/%.elf: fw/m4/%_main.c $(M4_COMMON) $(M4_HDRS) $(M4_LD_SCRIPTS) \
                   $(GENERATED) $(GENERATED_RETYPED) $$(M4_SRC_$$*)
	@test $(words $(M4_ELF_OBJS)) -eq $(words $(sort $(M4_ELF_OBJS))) || \
	    { echo "$*: two sources share an object basename; one would silently" \
	           "overwrite the other"; exit 1; }
	@mkdir -p $(dir $@) $(M4_OBJDIR)
	@rm -f $(M4_OBJDIR)/*.o
	$(foreach s,$(M4_ELF_SRCS),$(M4_CC) $(M4_FLAGS) $(M4_DEFS_$*) -c $(s) \
	    -o $(M4_OBJDIR)/$(notdir $(basename $(s))).o &&) :
	$(M4_CC) $(M4_FLAGS) $(M4_DEFS_$*) -T$(M4_ELF_LDS) $(M4_LD) \
	    -Wl,-Map=$(@:.elf=.map) -o $@ $(M4_ELF_OBJS)

$(BUILD)/m4/%.bin: $(BUILD)/m4/%.elf
	$(M4_OBJCOPY) -O binary $< $@

# The .elf is a chained pattern-rule prerequisite of the .bin, so make would treat
# it as intermediate and delete it. gdb needs it: keep it.
.PRECIOUS: $(BUILD)/m4/%.elf

m4-hello: $(BUILD)/m4/hello.elf $(BUILD)/m4/hello.bin

m4-clock-check: $(BUILD)/m4/clock_check.elf $(BUILD)/m4/clock_check.bin

# --- known-answer gate -------------------------------------------------------------
# The vectors are produced by the *host* build -- present-cli for the 64-bit
# ciphers, m4_kat_oracle for the 128-bit pair, with wide_bench's FIPS-197 and
# cross-kernel self-check as the latter's attestation -- so those three binaries
# are prerequisites of the header, not just of the firmware that includes it.
M4_KAT_VECTORS := fw/m4/gen/kat_vectors.h

$(M4_KAT_VECTORS): tools/gen_m4_kats.py tools/cipher_set.py \
                   $(VARIANT_JSON) $(wildcard variants/wide/*.json) \
                   $(BUILD)/present-cli $(BUILD)/m4_kat_oracle $(BUILD)/wide_bench
	@mkdir -p $(dir $@)
	$(PYTHON) tools/gen_m4_kats.py --out $@

m4-kats: $(M4_KAT_VECTORS)

# src/keyschedule.c is excluded on purpose -- it uses __int128, which does not
# exist on Cortex-M4 -- and src/keyschedule_portable.c stands in for it. Nothing
# else in src/ is excluded: present_avx2.c and present_neon.c compile to stubs
# here (__AVX2__ and __ARM_NEON are undefined for this target), so they cost
# nothing and their decryption entry points are never built. src/present_bitslice.c
# is needed for present_circuit_outcomp_mask, which present_core.c calls to build
# the bitsliced round keys.
M4_SRC_LIB := src/variant.c src/keyschedule_portable.c \
              src/present_core.c src/present_ref.c src/present_table.c \
              src/present_table_x.c src/present_bitslice.c src/present_bitslice32.c \
              src/present_avx2.c src/present_neon.c $(GEN)/variants_gen.c

M4_SRC_kat := fw/m4/kat.c $(M4_SRC_LIB)

$(BUILD)/m4/kat.elf: $(M4_KAT_VECTORS)

m4-kat: $(BUILD)/m4/kat.elf $(BUILD)/m4/kat.bin

# --- the speed benchmark ------------------------------------------------------------
# Same sources as the gate plus fw/m4/bench_m4_main.c: the harness runs
# kat_check_all() itself and asks kat_ok() before timing each row, so the gate is
# linked in rather than being a separate binary a human has to remember to run.
M4_SRC_bench_m4 := fw/m4/kat.c $(M4_SRC_LIB)

$(BUILD)/m4/bench_m4.elf: $(M4_KAT_VECTORS)

m4-bench: $(BUILD)/m4/bench_m4.elf $(BUILD)/m4/bench_m4.bin

# --- the purecore memory configuration ----------------------------------------------
# The same harness and the same sources as m4-bench, relinked against
# fw/m4/link/purecore.ld: cipher and harness code in SRAM, ART off (M4_PURECORE
# reaches system_init.c), 5 flash wait states unchanged. fw/m4/purecore_main.c is
# a one-line wrapper so the pattern rule can derive it from the binary name; the
# harness it includes is a prerequisite in its own right, or touching the harness
# would leave this binary stale -- the "silently times the previous build" bug
# the header list above exists to prevent.
M4_SRC_purecore := fw/m4/kat.c $(M4_SRC_LIB)

$(BUILD)/m4/purecore.elf: $(M4_KAT_VECTORS) fw/m4/bench_m4_main.c

m4-purecore: $(BUILD)/m4/purecore.elf $(BUILD)/m4/purecore.bin

analysis:
	$(PYTHON) analysis/cli.py analyze --all

report:
	$(PYTHON) analysis/cli.py report

validate-artifact:
	$(PYTHON) tools/validate_artifact.py

clean:
	rm -rf $(BUILD)

distclean: clean
	rm -f $(GENERATED) $(GENERATED_RETYPED)
