// Testbench for the keystream engines (AES-128/256, Qalqan, ChaCha20, PRESENT-80 CTR).
// Reads <vec> written by fpga/tools/gen_vectors.c from the KAT-verified host reference and
// checks every keystream block of every case byte for byte. Also measures the latency
// (clocks from `load` to the first block, including Qalqan's key schedule) and the
// initiation interval (clocks between blocks), and checks the latter against II.
//
// Select the core with +define+CORE_<name>; the vector file is the plusarg +vec=<path>.
`timescale 1ns/1ps
module tb_ctr;
`ifdef CORE_AES128
  localparam KB = 128, BB = 128, CB = 32, II = 10; localparam NAME = "aes128_ctr";
`elsif CORE_AES256
  localparam KB = 256, BB = 128, CB = 32, II = 14; localparam NAME = "aes256_ctr";
`elsif CORE_QALQAN
  localparam KB = 256, BB = 128, CB = 32, II = 15; localparam NAME = "qalqan_ctr";
`elsif CORE_CHACHA
  localparam KB = 256, BB = 512, CB = 32, II = 20; localparam NAME = "chacha20";
`elsif CORE_PRESENT
  localparam KB = 80, BB = 64, CB = 64, II = 31; localparam NAME = "present80_ctr";
`endif
  reg clk = 0, rst = 1, load = 0, run = 0;
  reg [KB-1:0] key;
  reg [95:0] nonce;
  reg [CB-1:0] ctr0;
  wire [BB-1:0] ks;
  wire ks_valid;
  always #5 clk = ~clk;

`ifdef CORE_AES128
  aes_ctr #(.NK(4)) dut(.clk(clk), .rst(rst), .load(load), .key(key), .nonce(nonce), .ctr0(ctr0),
                        .run(run), .ks(ks), .ks_valid(ks_valid));
`elsif CORE_AES256
  aes_ctr #(.NK(8)) dut(.clk(clk), .rst(rst), .load(load), .key(key), .nonce(nonce), .ctr0(ctr0),
                        .run(run), .ks(ks), .ks_valid(ks_valid));
`elsif CORE_QALQAN
  qalqan_ctr dut(.clk(clk), .rst(rst), .load(load), .key(key), .nonce(nonce), .ctr0(ctr0),
                 .run(run), .ks(ks), .ks_valid(ks_valid));
`elsif CORE_CHACHA
  chacha20_ctr dut(.clk(clk), .rst(rst), .load(load), .key(key), .nonce(nonce), .ctr0(ctr0),
                   .run(run), .ks(ks), .ks_valid(ks_valid));
`elsif CORE_PRESENT
  present80_ctr dut(.clk(clk), .rst(rst), .load(load), .key(key), .ctr0(ctr0),
                    .run(run), .ks(ks), .ks_valid(ks_valid));
`endif

  integer fd, ncases, c, nblk, j, errors, cyc, t_load, t_prev, lat, ii_min, ii_max, blocks;
  reg [BB-1:0] exp_ks;
  reg [1023:0] vecpath;
  always @(posedge clk) cyc <= cyc + 1;

  task wait_block;
    integer guard;
    begin
      guard = 0;
      @(posedge clk);
      while (!ks_valid) begin
        guard = guard + 1;
        if (guard > 100000) begin $display("FAIL %0s: timeout", NAME); $finish; end
        @(posedge clk);
      end
    end
  endtask

  initial begin
    cyc = 0; errors = 0; blocks = 0; ii_min = 1 << 30; ii_max = 0; lat = 0;
    if (!$value$plusargs("vec=%s", vecpath)) begin $display("FAIL: +vec= missing"); $finish; end
    fd = $fopen(vecpath, "r");
    if (fd == 0) begin $display("FAIL: cannot open %0s", vecpath); $finish; end
    if ($fscanf(fd, "%h", ncases) != 1) begin $display("FAIL: bad vector file"); $finish; end
    repeat (3) @(posedge clk);
    rst <= 0;
    for (c = 0; c < ncases; c = c + 1) begin
      if ($fscanf(fd, "%h %h %h %h", key, nonce, ctr0, nblk) != 4) begin $display("FAIL: bad case"); $finish; end
      @(posedge clk);
      load <= 1; run <= 1;
      @(posedge clk);
      load <= 0;
      t_load = cyc;
      for (j = 0; j < nblk; j = j + 1) begin
        if ($fscanf(fd, "%h", exp_ks) != 1) begin $display("FAIL: short case"); $finish; end
        wait_block;
        if (j == 0) lat = cyc - t_load;
        else begin
          if (cyc - t_prev < ii_min) ii_min = cyc - t_prev;
          if (cyc - t_prev > ii_max) ii_max = cyc - t_prev;
        end
        t_prev = cyc;
        blocks = blocks + 1;
        if (ks !== exp_ks) begin
          errors = errors + 1;
          if (errors <= 5) $display("MISMATCH %0s case %0d block %0d\n  got %h\n  exp %h", NAME, c, j, ks, exp_ks);
        end
      end
      run <= 0;
    end
    $fclose(fd);
    if (errors == 0 && ii_min == II && ii_max == II)
      $display("PASS %0s: %0d cases, %0d blocks, II = %0d clocks/block (%0d bit), first block %0d clocks after load",
               NAME, ncases, blocks, II, BB, lat);
    else
      $display("FAIL %0s: %0d mismatches of %0d blocks, II min %0d max %0d (expected %0d)",
               NAME, errors, blocks, ii_min, ii_max, II);
    $finish;
  end
endmodule
