// PRESENT-80 (31 rounds, Bogdanov et al., CHES 2007) keystream generator in CTR mode,
// round-iterative: one round per clock, 80-bit key schedule on the fly, a new 8-byte
// keystream block every 31 clocks.
//
// CTR contract (the project's ctr_bench, bench/ctr_backend.h): block j = BE64(ctr0 + j),
// 64-bit counter wrapping mod 2^64; keystream byte 0 = ks[63:56]. key[79:72] is key byte 0
// (the most significant byte, as present_init() takes it).
//
// Protocol as aes_ctr.v: pulse `load`; while `run` is high a block appears on `ks` with a
// one-clock `ks_valid` every 31 clocks (the first 32 clocks after the `load` pulse, as
// tb_ctr.v counts it). The final whitening key K32 is applied in the clock
// of round 31, which also loads the next counter, so the engine never idles.
`timescale 1ns/1ps
module present80_ctr (
  input  wire        clk,
  input  wire        rst,
  input  wire        load,
  input  wire [79:0] key,
  input  wire [63:0] ctr0,
  input  wire        run,
  output reg  [63:0] ks,
  output reg         ks_valid
);
  function [3:0] sb(input [3:0] x);
    case (x)
      4'h0: sb = 4'hc; 4'h1: sb = 4'h5; 4'h2: sb = 4'h6; 4'h3: sb = 4'hb;
      4'h4: sb = 4'h9; 4'h5: sb = 4'h0; 4'h6: sb = 4'ha; 4'h7: sb = 4'hd;
      4'h8: sb = 4'h3; 4'h9: sb = 4'he; 4'ha: sb = 4'hf; 4'hb: sb = 4'h8;
      4'hc: sb = 4'h4; 4'hd: sb = 4'h7; 4'he: sb = 4'h1; default: sb = 4'h2;
    endcase
  endfunction
  function [63:0] s_layer(input [63:0] s);
    integer i;
    for (i = 0; i < 16; i = i + 1) s_layer[4 * i +: 4] = sb(s[4 * i +: 4]);
  endfunction
  // pLayer: bit i -> bit 16i mod 63, bit 63 stays
  function [63:0] p_layer(input [63:0] s);
    integer i;
    for (i = 0; i < 64; i = i + 1) p_layer[(i == 63) ? 63 : (16 * i) % 63] = s[i];
  endfunction
  // key register update after round i (i = 1..31)
  function [79:0] key_update(input [79:0] k, input [4:0] i);
    reg [79:0] t;
    begin
      t = {k[18:0], k[79:19]};          // rotate left by 61
      t[79:76] = sb(t[79:76]);
      t[19:15] = t[19:15] ^ i;
      key_update = t;
    end
  endfunction

  reg [79:0] kmaster, kreg;
  reg [63:0] state, ctr;
  reg [4:0]  r;                          // round being computed, 1..31
  reg        active;

  wire [63:0] round_out = p_layer(s_layer(state ^ kreg[79:16]));
  wire [79:0] key_next  = key_update(kreg, r);

  always @(posedge clk) begin
    if (rst) begin
      active <= 1'b0; ks_valid <= 1'b0; ks <= 64'h0; r <= 5'd1;
      state <= 64'h0; ctr <= 64'h0; kmaster <= 80'h0; kreg <= 80'h0;
    end else begin
      ks_valid <= 1'b0;
      if (load) begin
        kmaster <= key; kreg <= key; ctr <= ctr0; state <= ctr0; r <= 5'd1; active <= 1'b1;
      end else if (active && run) begin
        if (r == 5'd31) begin
          ks <= round_out ^ key_next[79:16]; ks_valid <= 1'b1;
          ctr <= ctr + 64'd1; state <= ctr + 64'd1; kreg <= kmaster; r <= 5'd1;
        end else begin
          state <= round_out; kreg <= key_next; r <= r + 5'd1;
        end
      end
    end
  end
endmodule
