// ChaCha20 keystream generator (RFC 8439), round-iterative: one round (four parallel
// quarter-rounds, column and diagonal rounds alternating) per clock, a new 64-byte
// keystream block every 20 clocks.
//
// key[255:248] is key byte 0, nonce[95:88] nonce byte 0; ctr0 is the 32-bit block counter
// (state word 12), wrapping mod 2^32. ks[511:504] is keystream byte 0 (each state word is
// serialized little-endian, as the RFC).
//
// The feed-forward addition (working state + input state) has its own register stage: the
// clock after round 20 adds while the next block already runs its round 1. So the first
// block is valid 22 clocks after the `load` pulse (as tb_ctr.v counts it) and then one every
// 20 clocks.
`timescale 1ns/1ps
module chacha20_ctr (
  input  wire         clk,
  input  wire         rst,
  input  wire         load,
  input  wire [255:0] key,
  input  wire [95:0]  nonce,
  input  wire [31:0]  ctr0,
  input  wire         run,
  output reg  [511:0] ks,
  output reg          ks_valid
);
  function [31:0] bswap(input [31:0] w);
    bswap = {w[7:0], w[15:8], w[23:16], w[31:24]};
  endfunction
  function [31:0] rotl(input [31:0] x, input integer n);
    rotl = (x << n) | (x >> (32 - n));
  endfunction
  // quarter round on (a, b, c, d) packed as {a, b, c, d}
  function [127:0] qr(input [127:0] v);
    reg [31:0] a, b, c, d;
    begin
      {a, b, c, d} = v;
      a = a + b; d = rotl(d ^ a, 16);
      c = c + d; b = rotl(b ^ c, 12);
      a = a + b; d = rotl(d ^ a, 8);
      c = c + d; b = rotl(b ^ c, 7);
      qr = {a, b, c, d};
    end
  endfunction

  // state word i at w[i]
  reg [31:0] x [0:15];
  reg [31:0] fin [0:15];     // working state after round 20, awaiting the feed-forward add
  reg [255:0] kreg;
  reg [95:0]  nreg;
  reg [31:0]  ctr, ctr_fin;
  reg [4:0]   r;             // round being computed, 0..19 (even: column, odd: diagonal)
  reg         active, fin_pending;

  function [31:0] init_word(input integer i, input [255:0] k, input [95:0] n, input [31:0] c);
    case (i)
      0: init_word = 32'h61707865; 1: init_word = 32'h3320646e;
      2: init_word = 32'h79622d32; 3: init_word = 32'h6b206574;
      12: init_word = c;
      13: init_word = bswap(n[95:64]); 14: init_word = bswap(n[63:32]); 15: init_word = bswap(n[31:0]);
      default: init_word = bswap(k[255 - 32 * (i - 4) -: 32]);
    endcase
  endfunction

  // one round: column round (0,4,8,12)... or diagonal round (0,5,10,15), (1,6,11,12), ...
  wire diag = r[0];
  wire [31:0] y [0:15];
  genvar q;
  generate
    for (q = 0; q < 4; q = q + 1) begin : g_qr
      wire [3:0] ia = q, ib = diag ? 4 + (q + 1) % 4 : 4 + q,
                 ic = diag ? 8 + (q + 2) % 4 : 8 + q, id = diag ? 12 + (q + 3) % 4 : 12 + q;
      wire [127:0] o = qr({x[ia], x[ib], x[ic], x[id]});
      // route results back: word k gets the output of the quarter round that read it
      assign y[q] = o[127:96];
    end
  endgenerate
  // b, c, d outputs: in a column round word 4+q, 8+q, 12+q come from QR q; in a diagonal
  // round word 4+j comes from QR (j+3)%4, 8+j from QR (j+2)%4, 12+j from QR (j+1)%4.
  generate
    for (q = 0; q < 4; q = q + 1) begin : g_route
      assign y[4 + q]  = diag ? g_qr[(q + 3) % 4].o[95:64] : g_qr[q].o[95:64];
      assign y[8 + q]  = diag ? g_qr[(q + 2) % 4].o[63:32] : g_qr[q].o[63:32];
      assign y[12 + q] = diag ? g_qr[(q + 1) % 4].o[31:0]  : g_qr[q].o[31:0];
    end
  endgenerate

  integer i;
  always @(posedge clk) begin
    if (rst) begin
      active <= 1'b0; fin_pending <= 1'b0; ks_valid <= 1'b0; ks <= 512'h0; r <= 5'd0;
      ctr <= 32'h0; ctr_fin <= 32'h0; kreg <= 256'h0; nreg <= 96'h0;
      for (i = 0; i < 16; i = i + 1) begin x[i] <= 32'h0; fin[i] <= 32'h0; end
    end else begin
      ks_valid <= 1'b0;
      if (load) begin
        kreg <= key; nreg <= nonce; ctr <= ctr0; r <= 5'd0; active <= 1'b1; fin_pending <= 1'b0;
        for (i = 0; i < 16; i = i + 1) x[i] <= init_word(i, key, nonce, ctr0);
      end else if (active && run) begin
        if (fin_pending) begin   // feed-forward add of the block finished last clock
          for (i = 0; i < 16; i = i + 1)
            ks[511 - 32 * i -: 32] <= bswap(fin[i] + init_word(i, kreg, nreg, ctr_fin));
          ks_valid <= 1'b1;
          fin_pending <= 1'b0;
        end
        if (r == 5'd19) begin
          for (i = 0; i < 16; i = i + 1) begin
            fin[i] <= y[i];
            x[i] <= init_word(i, kreg, nreg, ctr + 32'd1);
          end
          fin_pending <= 1'b1; ctr_fin <= ctr; ctr <= ctr + 32'd1; r <= 5'd0;
        end else begin
          for (i = 0; i < 16; i = i + 1) x[i] <= y[i];
          r <= r + 5'd1;
        end
      end
    end
  end
endmodule
