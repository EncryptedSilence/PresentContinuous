// Testbench for ascon128_aead.v against fpga/tools/gen_vectors.c (ascon-c ref, KAT-verified):
// every ciphertext block and the tag of every case, AD and plaintext lengths 0..1024 bytes
// across the 16-byte block boundaries. Measures the clocks per plaintext block on the
// longest message (expected 8: p^8, absorb in the clock of its first round) and the clocks
// of the initialization and finalization.
`timescale 1ns/1ps
module tb_ascon;
  reg clk = 0, rst = 1, load = 0;
  reg [127:0] key, nonce, in_data;
  reg in_valid = 0, in_ad = 0, in_last = 0;
  reg [4:0] in_bytes = 0;
  wire in_ready, ct_valid, tag_valid;
  wire [127:0] ct, tag;
  always #5 clk = ~clk;

  ascon128_aead dut(.clk(clk), .rst(rst), .load(load), .key(key), .nonce(nonce),
                    .in_ready(in_ready), .in_valid(in_valid), .in_ad(in_ad), .in_last(in_last),
                    .in_bytes(in_bytes), .in_data(in_data), .ct_valid(ct_valid), .ct(ct),
                    .tag_valid(tag_valid), .tag(tag));

  integer fd, ncases, c, adlen, mlen, nad, nm, j, errors, cyc, t_prev, ii_min, ii_max, t_load, t_init, t_fin, t_last;
  reg [127:0] ad_b [0:127];
  reg [127:0] m_b [0:127];
  reg [127:0] c_b [0:127];
  reg [127:0] exp_tag;
  reg [1023:0] vecpath;
  always @(posedge clk) cyc <= cyc + 1;

  // present one block and wait until the core takes it; returns the clock it was taken
  task send(input isad, input last, input [4:0] nbytes, input [127:0] data, output integer t);
    integer guard;
    begin
      in_valid <= 1; in_ad <= isad; in_last <= last; in_bytes <= nbytes; in_data <= data;
      guard = 0;
      @(posedge clk);
      while (!in_ready) begin
        guard = guard + 1;
        if (guard > 1000) begin $display("FAIL ascon: in_ready timeout"); $finish; end
        @(posedge clk);
      end
      t = cyc;
      in_valid <= 0;
    end
  endtask

  integer t, k, nct;
  initial begin
    cyc = 0; errors = 0; ii_min = 1 << 30; ii_max = 0; t_init = 0; t_fin = 0;
    if (!$value$plusargs("vec=%s", vecpath)) begin $display("FAIL: +vec= missing"); $finish; end
    fd = $fopen(vecpath, "r");
    if (fd == 0 || $fscanf(fd, "%h", ncases) != 1) begin $display("FAIL: cannot read %0s", vecpath); $finish; end
    repeat (3) @(posedge clk);
    rst <= 0;
    for (c = 0; c < ncases; c = c + 1) begin
      if ($fscanf(fd, "%h %h %h %h", key, nonce, adlen, mlen) != 4) begin $display("FAIL: bad case"); $finish; end
      nad = (adlen + 15) / 16; nm = (mlen + 15) / 16;
      for (j = 0; j < nad; j = j + 1) k = $fscanf(fd, "%h", ad_b[j]);
      for (j = 0; j < nm; j = j + 1) k = $fscanf(fd, "%h", m_b[j]);
      for (j = 0; j < nm; j = j + 1) k = $fscanf(fd, "%h", c_b[j]);
      k = $fscanf(fd, "%h", exp_tag);
      @(posedge clk);
      load <= 1;
      @(posedge clk);
      load <= 0;
      t_load = cyc;
      // associated data: full blocks, then a last block of adlen % 16 bytes (only if adlen > 0)
      if (adlen > 0) begin
        for (j = 0; j < adlen / 16; j = j + 1) send(1, 0, 16, ad_b[j], t);
        send(1, 1, adlen % 16, (adlen % 16) ? ad_b[adlen / 16] : 128'h0, t);
      end
      // plaintext, the ciphertext block checked in the clock after it was taken
      nct = 0;
      for (j = 0; j <= mlen / 16; j = j + 1) begin
        if (j < mlen / 16) send(0, 0, 16, m_b[j], t);
        else send(0, 1, mlen % 16, (mlen % 16) ? m_b[j] : 128'h0, t);
        if (j == 0 && adlen == 0 && t - t_load > t_init) t_init = t - t_load;
        if (j > 0 && mlen == 1024) begin
          if (t - t_prev < ii_min) ii_min = t - t_prev;
          if (t - t_prev > ii_max) ii_max = t - t_prev;
        end
        t_prev = t;
        @(negedge clk);
        if (!ct_valid) begin errors = errors + 1; $display("FAIL ascon case %0d: no ct_valid", c); end
        else if (j < nm && ct !== c_b[j]) begin
          errors = errors + 1;
          if (errors <= 5) $display("MISMATCH ascon case %0d ct block %0d\n  got %h\n  exp %h", c, j, ct, c_b[j]);
        end
      end
      t_last = t;
      k = 0;
      while (!tag_valid) begin
        @(posedge clk); #1;
        k = k + 1;
        if (k > 100) begin $display("FAIL ascon: tag timeout"); $finish; end
      end
      if (cyc - t_last > t_fin) t_fin = cyc - t_last;
      if (tag !== exp_tag) begin
        errors = errors + 1;
        if (errors <= 5) $display("MISMATCH ascon case %0d (ad %0d, m %0d) tag\n  got %h\n  exp %h", c, adlen, mlen, tag, exp_tag);
      end
      @(posedge clk);
    end
    $fclose(fd);
    if (errors == 0 && ii_min == 8 && ii_max == 8)
      $display("PASS ascon128_aead: %0d cases, ct and tag match; plaintext II = 8 clocks/16-byte block, init %0d clocks, final block to tag %0d clocks",
               ncases, t_init, t_fin);
    else
      $display("FAIL ascon128_aead: %0d errors, II min %0d max %0d (expected 8)", errors, ii_min, ii_max);
    $finish;
  end
endmodule
