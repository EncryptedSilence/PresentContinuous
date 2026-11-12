# CUDA build of the ChaCha20 / Ascon GPU benchmark.
#
# The host implementations are the correctness oracle, so every build first runs
# `make -C .. test` (rebuilds changed host objects and runs the full KAT suite;
# a failure stops here), and ca_gpu additionally embeds oracle_gate.c, which
# re-checks the linked oracle objects against the KAT files at startup.
#
#   make            build (after the host KAT suite passes)
#   make run        build, then run with CSV into ../results/cuda/gpu.csv
#   make run-bc     build bc_gpu (AES-128 / Qalqan / PRESENT-80 CTR), CSV into ../results/cuda/gpu-bc.csv
NVCC ?= nvcc
CC   ?= gcc
ARCH ?= sm_120
B    := ../../build/ca
X    := $(B)/x86
HOST_OBJ := $(X)/chacha/chacha20_ref.o $(X)/chacha/chacha20_avx2.o $(X)/ascon/ascon_avx2.o \
            $(X)/ascon/ascon_common.o $(X)/ascon-c/opt64.o
.NOTPARALLEL:
# bc_gpu: the AES-128 / Qalqan CTR oracles (KAT-checked by test_bc) and the
# PRESENT library objects of the root Makefile (PRESENT-80 31-round reference).
BC_HOST_OBJ := $(X)/aes/aes128_ref.o $(X)/aes/aes128_ni.o $(X)/qalqan/qalqan.o $(X)/qalqan/qalqan_ctr.o
# Accelerated Qalqan (not distributed): GFNI host oracle if present, reference otherwise
ifneq ($(wildcard ../src/qalqan/qalqan_x86.c),)
BC_HOST_OBJ += $(X)/qalqan/qalqan_x86.o
BC_DEFS := -DHAVE_QALQAN_X86
endif
R    := ../..
PRESENT_OBJ := $(addprefix $(R)/build/src/,variant.o keyschedule.o present_core.o present_ref.o present_table.o \
               present_table_x.o present_bitslice.o present_bitslice32.o present_avx2.o present_neon.o gen/variants_gen.o)

all: host-verified $(B)/cuda/ca_gpu $(B)/cuda/bc_gpu

host-verified:
	$(MAKE) -C .. test

# Updated (or not) by the host-verified step above; make compares their mtimes.
$(HOST_OBJ) $(BC_HOST_OBJ) $(X)/kat_data.c: host-verified ;

present-lib:
	$(MAKE) -C $(R) $(patsubst $(R)/%,%,$(PRESENT_OBJ))
$(PRESENT_OBJ): present-lib ;

$(B)/cuda/oracle_gate.o: oracle_gate.c ../tests/kat_common.h ../include/*.h
	@mkdir -p $(B)/cuda
	$(CC) -O2 -I../include -c $< -o $@

$(B)/cuda/kat_data.o: $(X)/kat_data.c
	@mkdir -p $(B)/cuda
	$(CC) -O2 -c $< -o $@

$(B)/cuda/ca_gpu: ca_gpu.cu gpu_harness.cuh $(HOST_OBJ) $(B)/cuda/oracle_gate.o $(B)/cuda/kat_data.o
	@mkdir -p $(B)/cuda
	$(NVCC) -O3 -std=c++17 -arch=$(ARCH) -Xptxas -v -I../include $< $(HOST_OBJ) $(B)/cuda/oracle_gate.o $(B)/cuda/kat_data.o -o $@ 2> $(B)/cuda/ptxas.log || (cat $(B)/cuda/ptxas.log; exit 1)
	@grep -E "Compiling entry|registers|spill" $(B)/cuda/ptxas.log | sed 's/ptxas info *: //' | paste - - - | sed -E 's/Function properties for [^ ]+//' | head -20

$(B)/cuda/bc_gpu: bc_gpu.cu gpu_harness.cuh $(wildcard bc_gpu_qalqan.cuh) $(BC_HOST_OBJ) $(PRESENT_OBJ)
	@mkdir -p $(B)/cuda
	$(NVCC) -O3 -std=c++17 -arch=$(ARCH) -Xptxas -v $(BC_DEFS) -I../include -I../src/qalqan -I$(R)/include $< $(BC_HOST_OBJ) $(PRESENT_OBJ) -o $@ 2> $(B)/cuda/ptxas-bc.log || (cat $(B)/cuda/ptxas-bc.log; exit 1)
	@grep -E "Compiling entry|registers|spill" $(B)/cuda/ptxas-bc.log | sed 's/ptxas info *: //' | paste - - - | sed -E 's/Function properties for [^ ]+//' | grep -v 'Lb1EE' | head -20

run-bc: all
	$(B)/cuda/bc_gpu ../results/cuda/gpu-bc.csv

run: all
	$(B)/cuda/ca_gpu ../results/cuda/gpu.csv

.PHONY: all host-verified present-lib run run-bc
