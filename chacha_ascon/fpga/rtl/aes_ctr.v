// AES-128 / AES-256 keystream generator in CTR mode (FIPS-197, SP 800-38A), round-iterative:
// one full round per clock, round keys expanded on the fly (encryption-only schedule,
// 4 S-boxes), so a new 16-byte keystream block every NR clocks (NR = 10 / 14).
//
// CTR contract (chacha_ascon/include/blockctr.h): block j = nonce[0..11] || BE32(ctr0 + j),
// the 32-bit counter wraps mod 2^32. All byte strings are in memory order with byte 0 in the
// most significant bits (key[8*KB-1 -: 8] is key byte 0, ks[127:120] keystream byte 0).
//
// Protocol: pulse `load` with key/nonce/ctr0; while `run` is high a block is finished every
// NR clocks and presented on `ks` with a one-clock `ks_valid`. The first block appears NR
// clocks after the load. Holding `run` low freezes the engine.
//
// Timing: the round of the next block starts in the clock after the last round of the
// previous one (the next counter block XOR round key 0 is loaded in the same clock as the
// final round), so the engine never idles: throughput = 128 bit / NR clocks.
`timescale 1ns/1ps
module aes_ctr #(parameter NK = 4) (    // NK = key length in 32-bit words: 4 or 8
  input  wire              clk,
  input  wire              rst,
  input  wire              load,
  input  wire [32*NK-1:0]  key,
  input  wire [95:0]       nonce,
  input  wire [31:0]       ctr0,
  input  wire              run,
  output reg  [127:0]      ks,
  output reg               ks_valid
);
  localparam NR = NK + 6;

`include "aes_sbox.vh"

  function [31:0] sub_word(input [31:0] w);
    sub_word = {aes_sbox(w[31:24]), aes_sbox(w[23:16]), aes_sbox(w[15:8]), aes_sbox(w[7:0])};
  endfunction
  function [127:0] sub_bytes(input [127:0] s);
    sub_bytes = {sub_word(s[127:96]), sub_word(s[95:64]), sub_word(s[63:32]), sub_word(s[31:0])};
  endfunction
  // byte (row i, column c) is state byte 4c+i, at bits [127-8(4c+i) -: 8]
  function [127:0] shift_rows(input [127:0] s);
    integer c, i;
    begin
      for (c = 0; c < 4; c = c + 1)
        for (i = 0; i < 4; i = i + 1)
          shift_rows[127 - 8 * (4 * c + i) -: 8] = s[127 - 8 * (4 * ((c + i) % 4) + i) -: 8];
    end
  endfunction
  function [7:0] xt(input [7:0] b);
    xt = {b[6:0], 1'b0} ^ (b[7] ? 8'h1b : 8'h00);
  endfunction
  function [31:0] mix_col(input [31:0] a);
    reg [7:0] a0, a1, a2, a3;
    begin
      a0 = a[31:24]; a1 = a[23:16]; a2 = a[15:8]; a3 = a[7:0];
      mix_col = {xt(a0) ^ xt(a1) ^ a1 ^ a2 ^ a3,
                 a0 ^ xt(a1) ^ xt(a2) ^ a2 ^ a3,
                 a0 ^ a1 ^ xt(a2) ^ xt(a3) ^ a3,
                 xt(a0) ^ a0 ^ a1 ^ a2 ^ xt(a3)};
    end
  endfunction
  function [127:0] mix_columns(input [127:0] s);
    mix_columns = {mix_col(s[127:96]), mix_col(s[95:64]), mix_col(s[63:32]), mix_col(s[31:0])};
  endfunction
  function [7:0] rcon(input [3:0] i);   // Rcon[i], i = 1..10
    case (i)
      4'd1: rcon = 8'h01; 4'd2: rcon = 8'h02; 4'd3: rcon = 8'h04; 4'd4: rcon = 8'h08;
      4'd5: rcon = 8'h10; 4'd6: rcon = 8'h20; 4'd7: rcon = 8'h40; 4'd8: rcon = 8'h80;
      4'd9: rcon = 8'h1b; 4'd10: rcon = 8'h36; default: rcon = 8'h00;
    endcase
  endfunction

  reg [32*NK-1:0] kreg;          // master key
  reg [95:0]      nreg;
  reg [31:0]      ctr;           // counter of the block in flight
  reg [127:0]     state;
  reg [127:0]     rk1, rk2;      // round keys r-1 and r-2
  reg [3:0]       r;             // round being computed, 1..NR
  reg             active;

  wire [127:0] k0 = kreg[32*NK-1 -: 128];
  wire [127:0] k1 = (NK == 8) ? kreg[127:0] : kreg[32*NK-1 -: 128];

  // round key r from rk_{r-NK/4} (P) and the last word of rk_{r-1}
  wire        use_rot = (NK == 4) ? 1'b1 : ~r[0];
  wire [3:0]  ri      = (NK == 4) ? r : {1'b0, r[3:1]};
  wire [31:0] last    = rk1[31:0];
  // SubWord commutes with RotWord: one set of four S-boxes for both AES-256 kinds of step
  wire [31:0] sl      = sub_word(last);
  wire [31:0] g       = use_rot ? ({sl[23:0], sl[31:24]} ^ {rcon(ri), 24'h0}) : sl;
  wire [127:0] p      = (NK == 4) ? rk1 : rk2;
  wire [31:0] w0 = p[127:96] ^ g;
  wire [31:0] w1 = p[95:64] ^ w0;
  wire [31:0] w2 = p[63:32] ^ w1;
  wire [31:0] w3 = p[31:0] ^ w2;
  wire [127:0] rk_new = {w0, w1, w2, w3};
  // AES-256 round 1 uses the second key half as is; expansion starts at round 2
  wire first256 = (NK == 8) && (r == 4'd1);
  wire [127:0] rk = first256 ? rk1 : rk_new;

  wire [127:0] sr = shift_rows(sub_bytes(state));
  wire [127:0] round_out = ((r == NR) ? sr : mix_columns(sr)) ^ rk;

  always @(posedge clk) begin
    if (rst) begin
      active <= 1'b0; ks_valid <= 1'b0; ks <= 128'h0; r <= 4'd1;
      state <= 128'h0; rk1 <= 128'h0; rk2 <= 128'h0; ctr <= 32'h0; kreg <= 0; nreg <= 96'h0;
    end else begin
      ks_valid <= 1'b0;
      if (load) begin
        kreg <= key; nreg <= nonce; ctr <= ctr0; active <= 1'b1; r <= 4'd1;
        state <= {nonce, ctr0} ^ key[32*NK-1 -: 128];
        rk2 <= key[32*NK-1 -: 128];
        rk1 <= (NK == 8) ? key[127:0] : key[32*NK-1 -: 128];
      end else if (active && run) begin
        if (r == NR) begin
          ks <= round_out; ks_valid <= 1'b1;
          ctr <= ctr + 32'd1; r <= 4'd1;
          state <= {nreg, ctr + 32'd1} ^ k0;
          rk2 <= k0; rk1 <= k1;
        end else begin
          state <= round_out; r <= r + 4'd1;
          if (!first256) begin rk2 <= rk1; rk1 <= rk_new; end
        end
      end
    end
  end
endmodule
