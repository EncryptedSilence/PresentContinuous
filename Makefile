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
        m4-bench-fw m4-flash-noart m4-sram-noart m4-configs

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
# tools/tests is a second discovery root and needs its own invocation: `discover`
# takes one -s, and the two suites have different top-level directories
# (analysis/tests is a package under analysis/, tools/tests one under the repo
# root). Listing only the first is how tools/tests/test_cipher_set.py -- the only
# automated guard on tools/cipher_set.py being the single source of truth -- ran
# nowhere at all for twelve tasks.
	@$(PYTHON) -m unittest discover -s tools/tests -t . -v

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
              -ffunction-sections -falign-functions=16 \
              -Iinclude -Isrc -Ifw/m4 -Ibench
M4_LD      := -nostartfiles -Wl,--gc-sections

# -ffunction-sections: added at the START of the optimization work, which is where
# the note this paragraph replaces said it had to go. What it fixes, in the words
# of that note: --gc-sections without it collects at *object* granularity, so an
# unreferenced function in a firmware-linked translation unit is not dropped -- it
# shifts every address after it. Measured, not inferred: adding one predicate the
# firmware never called moved all three ELF sha256 and _eramtext, and took the
# .ramtext relocation audit from 79 symbols to 80.
#
# What that costs, and it is not nothing: the audit's `removed by --gc-sections`
# count is now a per-function number rather than a per-object one, so it jumps,
# and .ramtext shrinks. Both are expected. What does NOT change is the audit's
# meaning -- every .text symbol still present in a relocated object must still be
# inside [_sramtext, _eramtext).
#
# -falign-functions=16 exists for the measurement, not for the code size. The
# resolution floor documented in results/m4-speed.csv is governed by a code
# address's offset mod 16 against this part's 128-bit flash word: a +4 B shift of
# the image moved all 39 rows by up to 7.5%. Aligning every function entry to 16
# forces the linker to re-pad rather than propagate such a shift, so the mechanism
# that produced that floor no longer has anything to act on. That is a claim about
# the mechanism and it is NOT yet a measurement -- the relink experiment (pad
# ahead of .text by +4 and +16, diff every row) has to be re-run on these objects
# before the floor in the republished header may be lowered. Until it is, the
# published 7.5% stands as written.
#
# The rule the replaced note ends with still holds and is unchanged by any of the
# above: after touching any firmware-linked source, rebuild and diff the three ELF
# sha256 against the ones in results/m4-speed.csv. Unchanged means the edit was
# genuinely comment-only. Changed means the published file must be regenerated and
# every figure in docs/m4-optimizations.md re-checked against it. -ffunction-sections
# narrows how often that fires; it does not make a recompile safe to leave
# unpublished.

# -Isrc and -Ifw/m4 each put a directory named `gen` on the include path --
# src/gen (host code generation) and fw/m4/gen (the KAT vectors). A header
# present in both would resolve to src/gen's copy for every firmware
# translation unit, silently, because -Isrc comes first: the firmware would be
# built against the host header while every reader of the #include assumed the
# firmware one. Nothing collides today. This makes a future collision a build
# failure instead of a wrong binary; the alternative fix, spelling the firmware
# include as "m4/gen/...", would mean renaming the directory the generator
# writes to and is not worth it for one file.
M4_GEN_CLASH = $(filter $(notdir $(wildcard $(GEN)/*)),$(notdir $(wildcard fw/m4/gen/*)))

# Linker scripts. Every firmware ELF depends on all of them (they are tiny, and a
# spurious rebuild is cheaper than a stale one); which one is *used* comes from
# M4_LDS_<name>, defaulting to the product configuration.
M4_LD_SCRIPTS     := fw/m4/link/product.ld fw/m4/link/sram_noart.ld
M4_LDS_DEFAULT    := fw/m4/link/product.ld
M4_LDS_sram_noart := fw/m4/link/sram_noart.ld

# Per-binary extra preprocessor flags, again keyed on the binary name. M4_NO_ART
# turns the flash accelerator off in system_init.c and says nothing about where
# the code lives -- that is the linker script's business, which is why the two
# no-ART configurations share it.
M4_DEFS_flash_noart := -DM4_NO_ART -DM4_CONFIG='"flash-noart"'
M4_DEFS_sram_noart  := -DM4_NO_ART -DM4_CONFIG='"sram-noart"'

# Boot, clock and host I/O: every firmware binary needs exactly these.
M4_COMMON  := fw/m4/startup_stm32f407.s fw/m4/system_init.c fw/m4/semihost.c \
              fw/m4/libc_shim.c

# Headers a firmware binary may include, listed because -MMD cannot help here.
# (It is not that compile and link are one step -- they are two, see the .elf rule
# below. The reason is that the objects are not make targets: they are produced
# inside the .elf recipe's own $(foreach) loop, so there is no per-object rule for
# a generated .d file to attach to, and the only target make can decide to rebuild
# is the .elf, whose prerequisites are this list. The recipe deletes and rebuilds
# every object each time it runs, so once make decides to run it, nothing is
# stale; the whole question is whether it runs at all.)
#
# Confirmed by experiment: before this line existed, `touch bench/wide_bitslice32.h
# && make m4-kat` reported "Nothing to be done", as did touching any fw/m4/*.h. On
# a benchmark that is the worst form of the bug: it does not fail, it silently
# times the previous build.
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
# name, so `*present_bitslice32.o(.text*)` in sram_noart.ld would have matched
# nothing, silently, and left the code in flash while still linking and running.
# Objects therefore go to build/m4/obj/NAME/<basename>.o, one directory per
# binary because M4_DEFS_<name> can change how a shared source compiles.
# Which source holds main(). By default fw/m4/NAME_main.c, as the paragraph above
# says; M4_MAIN_<name> overrides it so a family of binaries that differ only in
# their -D flags can share one. The per-cipher images do exactly that: 21 of them
# against one harness, where 21 identical one-line wrapper files would be 21 places
# for the harness to be included from and one place for a typo to build the wrong
# thing. It is spelled out in the rule's prerequisite list rather than held in a
# variable here, because only the rule can reach $* through .SECONDEXPANSION.
M4_OBJDIR   = $(BUILD)/m4/obj/$*
M4_ELF_SRCS = $< $(M4_COMMON) $(M4_SRC_$*)
M4_ELF_OBJS = $(patsubst %,$(M4_OBJDIR)/%.o,$(notdir $(basename $(M4_ELF_SRCS))))
M4_ELF_LDS  = $(if $(M4_LDS_$*),$(M4_LDS_$*),$(M4_LDS_DEFAULT))

# --- .ramtext relocation audit -------------------------------------------------------
# The one failure a relocating configuration cannot have is the linker script's
# object-name patterns matching nothing: the link succeeds, the CSV still says
# sram-noart, and the timed code is still in flash. sram_noart.ld's
# `ASSERT(_eramtext - _sramtext >= 64K)` catches only *total* wipeout. Dropping
# three small objects -- present_table_x.o, libc_shim.o, keyschedule_portable.o --
# leaves .ramtext at 94,888 B, links clean, fires no assert, and silently puts
# present_encrypt_table_x4 and memcpy back in flash. A run in that state is
# meaningless while looking entirely normal, so the build refuses to produce it.
#
# M4_RAMTEXT_OBJS_<name> is the relocated set, kept beside the linker script it
# mirrors; binaries without one (product, flash-noart) skip the audit. The rule:
# every .text symbol of every listed object must be linked inside
# [_sramtext, _eramtext). Names are compared per object because a `static` in a
# header included by both kat.c (flash) and the harness (SRAM) legitimately has
# two copies -- hence "at least as many copies inside .ramtext as there are
# relocated objects defining it" rather than "no copy outside".
M4_NM := arm-none-eabi-nm

M4_RAMTEXT_OBJS_sram_noart := present_core present_ref present_table \
    present_table_x present_bitslice present_bitslice32 present_avx2 \
    present_neon keyschedule_portable variant variants_gen sram_noart_main \
    libc_shim

# A liveness floor, not the correctness check. The per-symbol test below is what
# proves the relocation held; this is what proves the per-symbol test had
# anything to look at. Without it the audit's failure modes are all silent: an
# object name that no longer resolves makes nm write to stderr, and the exit
# status of a pipeline is awk's, so `relocation audit ok -- 0 symbols` is printed
# and the build succeeds -- and run_m4_bench.py then stamps that line into the
# published CSV as evidence the relocation held. That is the same silent-success
# bug this audit exists to close, one level up.
#
# The floor is derived from what it has to catch, not from what the build happens
# to produce -- a floor set just under the current count is a floor that fires on
# the next legitimate edit.
#
# Re-derived when -ffunction-sections was added, which took the real count from 79
# to 72 and the collected count from 12 to 19. Nothing was lost: the seven are
# present_avx2's 5 and present_neon's 7 (x86 and ARM-NEON kernels, never callable
# on this target, previously retained only because per-object collection could not
# see inside their objects) less the churn the finer granularity also freed
# elsewhere. Both objects stay named above deliberately -- they now contribute
# zero symbols, so the audit examines nothing for them, but the naming is what
# turns "this kernel became live again" into a relocation the audit checks rather
# than one it silently misses.
#
# What the floor must catch is a partial pattern match that leaves the timed code
# in flash. Live counts today: present_bitslice32 25, present_bitslice 24, the
# other eleven objects 23 between them. Dropping either big object on its own
# leaves 47 or 48, so any floor above 48 catches it; dropping a small one is
# caught by the per-symbol test instead, which is the real correctness check.
# 50 therefore preserves exactly the property the 70 was chosen for, while
# leaving 22 symbols of room for churn instead of 2.
M4_RAMTEXT_MIN_SYMS_sram_noart := 50

# $(1) = linked ELF, $(2) = object dir, $(3) = object basenames, $(4) = min syms.
#
# Every nm invocation is checked explicitly rather than relying on `set -e` or
# pipefail: the recipe wraps this in `|| { rm -f $@; exit 1; }`, which disables
# errexit for everything inside it, and pipefail is not in POSIX sh.
#
# The object-existence guard runs in a SUBSHELL joined by `&&`. `exit 1` in the
# recipe's own shell would terminate it immediately and skip the `rm -f $@` in
# that `||` handler, leaving a stale, unaudited ELF newer than its prerequisites
# -- so the failing build could be turned into a passing one by simply running
# make again. In a subshell the exit becomes the left operand's status, the
# right-hand side is skipped, and the handler runs.
define M4_RAMTEXT_AUDIT
( for o in $(3); do \
    $(M4_NM) --defined-only $(2)/$$o.o > /dev/null 2>&1 || \
      { echo "$(1): RELOCATION AUDIT FAILED -- cannot read $(2)/$$o.o"; \
        echo "  M4_RAMTEXT_OBJS names an object this build does not produce;" \
             "the audit would otherwise pass having examined nothing"; exit 1; }; \
  done ) && \
{ $(M4_NM) --defined-only $(1) | sed 's/^/L /' || echo "NM_FAILED"; \
  for o in $(3); do $(M4_NM) --defined-only $(2)/$$o.o | sed "s/^/O $$o /"; done; } | \
awk -v elf=$(1) -v minsyms=$(4) 'function h(s, i,v){v=0;for(i=1;i<=length(s);i++)v=v*16+index("0123456789abcdef",substr(tolower(s),i,1))-1;return v} \
  $$1=="NM_FAILED"{print elf": RELOCATION AUDIT FAILED -- nm could not read the linked ELF"; exit 1} \
  $$1=="L"&&$$4=="_sramtext"{lo=h($$2); haslo=1} $$1=="L"&&$$4=="_eramtext"{hi=h($$2); hashi=1} \
  $$1=="L"{seen[$$4]++; a[$$4]=a[$$4] " " $$2; next} \
  $$4=="T"||$$4=="t"{need[$$5]++; from[$$5]=from[$$5] " " $$2} \
  END{if(!haslo||!hashi){print elf": RELOCATION AUDIT FAILED -- no _sramtext/_eramtext in the ELF;" \
        " this linker script does not relocate anything"; exit 1} \
      for(n in need){if(!(n in seen)){gc++;continue} r=0; m=split(a[n],v," "); \
        for(i=1;i<=m;i++) if(h(v[i])>=lo && h(v[i])<hi) r++; \
        if(r<need[n]){printf "  %-44s in%s: %d of %d copies in .ramtext (at%s)\n",n,from[n],r,need[n],a[n]; bad++} else ok++} \
      if(bad){printf "%s: RELOCATION AUDIT FAILED -- %d symbol(s) above are in flash, not in .ramtext\n",elf,bad; \
              print "  the linker script'\''s object-name patterns did not match; a run in this state would time the flash path"; exit 1} \
      if(ok<minsyms){printf "%s: RELOCATION AUDIT FAILED -- only %d symbols in .ramtext, expected at least %d\n",elf,ok,minsyms; \
              print "  no symbol was found in flash, but far too few were examined for that to mean anything"; exit 1} \
      printf "%s: relocation audit ok -- %d symbols in .ramtext [%08x,%08x) (floor %d), %d removed by --gc-sections\n",elf,ok,lo,hi,minsyms,gc+0}'
endef

.SECONDEXPANSION:
$(BUILD)/m4/%.elf: $$(if $$(M4_MAIN_$$*),$$(M4_MAIN_$$*),fw/m4/$$*_main.c) \
                   $(M4_COMMON) $(M4_HDRS) $(M4_LD_SCRIPTS) \
                   $(GENERATED) $(GENERATED_RETYPED) $$(M4_SRC_$$*)
	@test $(words $(M4_ELF_OBJS)) -eq $(words $(sort $(M4_ELF_OBJS))) || \
	    { echo "$*: two sources share an object basename; one would silently" \
	           "overwrite the other"; exit 1; }
	@test -z "$(M4_GEN_CLASH)" || \
	    { echo "$*: $(GEN) and fw/m4/gen both contain: $(M4_GEN_CLASH)"; \
	      echo "  -Isrc precedes -Ifw/m4, so every \`gen/<name>\` include in the" \
	           "firmware would silently resolve to the host copy"; exit 1; }
	@mkdir -p $(dir $@) $(M4_OBJDIR)
	@rm -f $(M4_OBJDIR)/*.o
	$(foreach s,$(M4_ELF_SRCS),$(M4_CC) $(M4_FLAGS) $(M4_DEFS_$*) -c $(s) \
	    -o $(M4_OBJDIR)/$(notdir $(basename $(s))).o &&) :
	$(M4_CC) $(M4_FLAGS) $(M4_DEFS_$*) -T$(M4_ELF_LDS) $(M4_LD) $(M4_LDX_$*) \
	    -Wl,-Map=$(@:.elf=.map) -o $@ $(M4_ELF_OBJS)
	$(if $(M4_RAMTEXT_OBJS_$*),@$(call M4_RAMTEXT_AUDIT,$@,$(M4_OBJDIR),$(M4_RAMTEXT_OBJS_$*),$(M4_RAMTEXT_MIN_SYMS_$*)) \
	    || { rm -f $@; exit 1; })

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
M4_KAT_VECTORS := fw/m4/gen/kat_vectors.h fw/m4/gen/cipher_set.h

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

m4-bench-fw: $(BUILD)/m4/bench_m4.elf $(BUILD)/m4/bench_m4.bin

# --- the two comparison memory configurations ---------------------------------------
# Same harness, same sources, same flags as m4-bench above. Three configurations
# are published, and each answers a different question:
#
#   product      product.ld     (no defines)  code in flash, ART on
#   flash-noart  product.ld     -DM4_NO_ART   code in flash, ART off
#   sram-noart   sram_noart.ld  -DM4_NO_ART   code in SRAM,  ART off
#
# product minus flash-noart is the accelerator's own contribution -- the question
# the spec asked. sram-noart additionally moves instruction fetch off the ICode
# bus onto the system bus that carries every data access; it is a different
# instruction-supply path, not a lower bound (this part has no zero-wait-state
# executable memory: CCM is D-bus only). Measured over the 49 pairs published in
# results/m4-speed.csv, the ART is worth about 1.6x at the median (1.3x to 2.4x
# across rows); a third significant figure is not meaningful at the 7.5% per-row
# layout floor the CSV documents.
#
# Each needs a fw/m4/NAME_main.c so the pattern rule can derive a main from the
# binary name; both are one-line wrappers around the single copy of the harness.
# That harness is a prerequisite in its own right, or touching it would leave
# these binaries stale -- the "silently times the previous build" bug the header
# list above exists to prevent.
M4_SRC_flash_noart := fw/m4/kat.c $(M4_SRC_LIB)
M4_SRC_sram_noart  := fw/m4/kat.c $(M4_SRC_LIB)

$(BUILD)/m4/flash_noart.elf: $(M4_KAT_VECTORS) fw/m4/bench_m4_main.c
$(BUILD)/m4/sram_noart.elf:  $(M4_KAT_VECTORS) fw/m4/bench_m4_main.c

m4-flash-noart: $(BUILD)/m4/flash_noart.elf $(BUILD)/m4/flash_noart.bin

m4-sram-noart: $(BUILD)/m4/sram_noart.elf $(BUILD)/m4/sram_noart.bin

# All three firmware images, for the side-by-side. `make m4-bench` below builds
# these from a removed build/m4 and runs them; this target is the build half on
# its own, for when there is no board attached.
m4-configs: m4-bench-fw m4-flash-noart m4-sram-noart

# --- one binary per cipher -----------------------------------------------------------
# The same harness and the same three memory configurations, built seven more times
# over with -DM4_ONE_CIPHER=<slug> so each image contains exactly one cipher: 21
# ELFs, build/m4/one_<slug>_<config>.elf.
#
# What they are for, in one line each -- fw/m4/one_cipher.h has the long version:
#
#   footprint    an image whose .text IS the cipher's code, rather than a figure a
#                call-graph tool has to attribute out of seven ciphers' worth.
#                present-80-r16 goes from 179,104 B of .text to 35,432.
#   headroom     the sram-noart configuration relocates the timed code into SRAM,
#                and the combined image fills 102 KiB of the ~104 KiB there. Per
#                cipher that ceiling stops being the reason an optimisation cannot
#                land.
#   isolation    no other cipher's code sits between this cipher's kernels, so a row
#                cannot move because an unrelated one changed size.
#
# The combined image stays and stays authoritative for results/m4-speed.csv: it is
# the only one that measures all seven under a single layout in a single session,
# which is what makes its rows comparable columns.
#
# The cipher list comes from tools/cipher_set.py, the same seven the KAT vectors and
# the FPGA results are built from -- never restated here.
-include fw/m4/gen/ciphers.mk

fw/m4/gen/ciphers.mk: tools/cipher_set.py $(VARIANT_JSON) $(wildcard variants/wide/*.json)
	@mkdir -p $(dir $@)
	$(PYTHON) tools/cipher_set.py --make > $@

M4_ONE_CONFIGS := product flash_noart sram_noart

# .ramtext floors for the per-cipher sram-noart images. Per family, because the two
# relocate quite different sets: a 64-bit cipher's image relocates the src/ library
# and the harness (32 symbols, 18-36 KiB), while a 128-bit cipher's relocates the
# harness alone -- its kernels are static inline in bench/wide_ciphers.h, and
# --gc-sections then removes the whole src/ library, which nothing in such an image
# calls (16 symbols, 13-18 KiB).
#
# What a count floor can and cannot catch here, stated because it is weaker than the
# combined image's. There, one object is 25 of 84 symbols, so a floor at 50 catches
# that object going missing. Per cipher the largest relocated object is 7 of 32, so
# NO count floor can catch a single object dropping out -- that is the per-symbol
# audit's job, and it does it. These floors catch the failure the per-symbol audit
# cannot report on: the whole match collapsing, or nm failing, leaving the audit
# with nothing to examine and printing "ok -- 0 symbols". Set to roughly two thirds
# of the observed count and of the smallest observed .ramtext, which is loose enough
# for churn and tight enough that a collapse cannot pass.
M4_ONE_RAMTEXT_MIN_SYMS_narrow  := 24
M4_ONE_RAMTEXT_MIN_SYMS_aes     := 12
M4_ONE_RAMTEXT_MIN_SYMS_lin     := 12
M4_ONE_RAMTEXT_MIN_BYTES_narrow := 12288
M4_ONE_RAMTEXT_MIN_BYTES_aes    := 8192
M4_ONE_RAMTEXT_MIN_BYTES_lin    := 8192

# $(1) = cipher slug, $(2) = memory configuration.
#
# Every variable the pattern rule reads is set here, and nothing else is: no recipe,
# no new rule. M4_MAIN_<name> points all 21 at the one harness; M4_DEFS_<name> is
# this image's cipher and the configuration's own defines; PRESENT_ONE_CIPHER is
# added only for the 64-bit ciphers, since the 128-bit pair has no src/ kernel to
# fix (M4_ONE_VARIANT_<slug> is empty for them, and is the *variant* slug rather
# than the cipher slug because cipher_set.py reports two variants under other
# names).
define M4_ONE_BINARY
M4_MAIN_one_$(1)_$(2) := fw/m4/bench_m4_main.c
M4_SRC_one_$(1)_$(2)  := fw/m4/kat.c $$(M4_SRC_LIB)
M4_DEFS_one_$(1)_$(2) := -DM4_ONE_CIPHER=$(1) $$(M4_DEFS_$(2)) \
    $$(if $$(M4_ONE_VARIANT_$(1)),-DPRESENT_ONE_CIPHER=$$(M4_ONE_VARIANT_$(1)))
M4_LDS_one_$(1)_$(2)  := $$(M4_LDS_$(2))
ifneq ($$(M4_RAMTEXT_OBJS_$(2)),)
M4_RAMTEXT_OBJS_one_$(1)_$(2)     := $$(patsubst $(2)_main,bench_m4_main,$$(M4_RAMTEXT_OBJS_$(2)))
M4_RAMTEXT_MIN_SYMS_one_$(1)_$(2) := $$(M4_ONE_RAMTEXT_MIN_SYMS_$$(M4_ONE_FAM_$(1)))
M4_LDX_one_$(1)_$(2)              := \
    -Wl,--defsym=__ramtext_min=$$(M4_ONE_RAMTEXT_MIN_BYTES_$$(M4_ONE_FAM_$(1)))
endif
$$(BUILD)/m4/one_$(1)_$(2).elf: $$(M4_KAT_VECTORS)
M4_ONE_ELFS += $$(BUILD)/m4/one_$(1)_$(2).elf $$(BUILD)/m4/one_$(1)_$(2).bin
endef

$(foreach c,$(M4_ONE_SLUGS),$(foreach k,$(M4_ONE_CONFIGS), \
    $(eval $(call M4_ONE_BINARY,$(c),$(k)))))

# Refuses to build nothing. Without this, a ciphers.mk that failed to generate --
# `-include` says nothing when the file is absent -- would leave M4_ONE_SLUGS empty
# and `make m4-one` would report success having produced no images at all.
m4-one:
	@test -n "$(M4_ONE_SLUGS)" || \
	    { echo "m4-one: no ciphers -- fw/m4/gen/ciphers.mk is missing or empty;" \
	           "try: $(PYTHON) tools/cipher_set.py --make"; exit 1; }
	@$(MAKE) --no-print-directory $(M4_ONE_ELFS)

# Run one image and print what it says. `make m4-run BIN=one_cipher_D_product`.
# For looking at a board while working on a kernel; it publishes nothing, and
# results/m4-speed.csv still comes only from `make m4-bench`.
m4-run:
	@test -n "$(BIN)" || { echo "usage: make m4-run BIN=<binary>   e.g. BIN=one_cipher_D_product"; exit 1; }
	$(PYTHON) tools/run_m4_bench.py --run-only $(BIN)

# --- the published measurement -------------------------------------------------------
# The one command that produces results/m4-speed.csv, this project's authoritative
# Cortex-M4 result. It builds all three configurations from a removed build/m4 at
# one commit and measures them in one session, because on this part a per-row
# figure moves by up to 7.5% purely from where the code lands (offset mod 16, with
# the ART off and a 128-bit flash fetch) -- rows built at different commits are not
# comparable columns. tools/run_m4_bench.py enforces that; do not assemble the CSV
# by running the three firmware targets by hand.
m4-bench: $(GENERATED) $(GENERATED_RETYPED) $(M4_KAT_VECTORS)
	@mkdir -p results
	$(PYTHON) tools/run_m4_bench.py --out results/m4-speed.csv

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
