// Ascon-AEAD128 encryption (NIST SP 800-232; same algorithm as ascon-c crypto_aead/asconaead128),
// round-iterative: one permutation round per clock. Initialization p^12, 16-byte blocks of
// associated data and plaintext with p^8, finalization p^12, 128-bit tag.
//
// Interface (byte strings in memory order, byte 0 in the most significant bits):
//   load            pulse with key and nonce: starts the initialization (12 clocks).
//   in_ready        the core takes a block in this clock if in_valid is high.
//   in_valid, in_ad (1 = associated data, 0 = plaintext), in_last, in_bytes, in_data
//                   Non-last blocks carry 16 bytes. Each kind ends with exactly one last
//                   block of 0..15 bytes (as the reference: 16 bytes of AD are one full block
//                   and an empty last block). No AD at all: send no AD blocks. The plaintext
//                   always ends with a last block, possibly empty.
//   ct_valid, ct    ciphertext block for each plaintext block (bytes past in_bytes are zero).
//   tag_valid, tag  after the last plaintext block, p^12 later.
// A plaintext block is absorbed in the same clock as the first round of its p^8, so a long
// message streams at one 16-byte block per 8 clocks.
`timescale 1ns/1ps
module ascon128_aead (
  input  wire         clk,
  input  wire         rst,
  input  wire         load,
  input  wire [127:0] key,
  input  wire [127:0] nonce,
  output wire         in_ready,
  input  wire         in_valid,
  input  wire         in_ad,
  input  wire         in_last,
  input  wire [4:0]   in_bytes,
  input  wire [127:0] in_data,
  output reg          ct_valid,
  output reg  [127:0] ct,
  output reg          tag_valid,
  output reg  [127:0] tag
);
  localparam [63:0] IV = 64'h00001000808c0001;   // ASCON_128A_IV of ascon-c (SP 800-232)

  function [63:0] bswap64(input [63:0] v);
    integer i;
    for (i = 0; i < 8; i = i + 1) bswap64[8 * i +: 8] = v[63 - 8 * i -: 8];
  endfunction
  function [63:0] ror(input [63:0] x, input integer n);
    ror = (x >> n) | (x << (64 - n));
  endfunction
  // one round with round constant c on {x0, x1, x2, x3, x4}
  function [319:0] round_fn(input [319:0] s, input [7:0] c);
    reg [63:0] x0, x1, x2, x3, x4, t0, t1, t2, t3, t4;
    begin
      {x0, x1, x2, x3, x4} = s;
      x2 = x2 ^ {56'h0, c};
      x0 = x0 ^ x4; x4 = x4 ^ x3; x2 = x2 ^ x1;
      t0 = x0 ^ (~x1 & x2); t1 = x1 ^ (~x2 & x3); t2 = x2 ^ (~x3 & x4);
      t3 = x3 ^ (~x4 & x0); t4 = x4 ^ (~x0 & x1);
      t1 = t1 ^ t0; t0 = t0 ^ t4; t3 = t3 ^ t2; t2 = ~t2;
      round_fn = {t0 ^ ror(t0, 19) ^ ror(t0, 28), t1 ^ ror(t1, 61) ^ ror(t1, 39),
                  t2 ^ ror(t2, 1) ^ ror(t2, 6), t3 ^ ror(t3, 10) ^ ror(t3, 17),
                  t4 ^ ror(t4, 7) ^ ror(t4, 41)};
    end
  endfunction

  reg [319:0] s;
  reg [63:0]  k0, k1;
  reg [3:0]   rnd;          // index of the next round, 0..11 (constant (15-i)<<4 | i)
  reg         busy;         // a permutation is running
  reg         post_key;     // XOR 0..0 || K at the end of this permutation (init and final)
  reg         final_perm;   // this permutation is the finalization: emit the tag
  reg         ready_st;     // initialized and accepting data
  reg         dsep_done;

  wire [319:0] post = post_key ? {192'h0, k0, k1} : 320'h0;

  // absorb: memory-order block (masked, padded if last) -> x0 || x1
  wire [127:0] mask = in_last ? ~({128{1'b1}} >> (8 * in_bytes)) : {128{1'b1}};
  wire [127:0] pad  = in_last ? (128'h01 << (8 * (15 - in_bytes))) : 128'h0;
  wire [127:0] blk  = (in_data & mask) | pad;
  wire [127:0] blk_le = {bswap64(blk[127:64]), bswap64(blk[63:0])};
  wire [127:0] rate_mem = {bswap64(s[319:256]), bswap64(s[255:192])};
  wire take = in_valid && in_ready;
  wire is_msg = !in_ad;
  wire do_final = is_msg && in_last;
  wire [63:0] dsep = (is_msg && !dsep_done) ? 64'h8000000000000000 : 64'h0;
  // state entering the first round of the block's permutation
  wire [319:0] s_abs = {s[319:192] ^ blk_le,
                        s[191:128] ^ (do_final ? k0 : 64'h0),
                        s[127:64] ^ (do_final ? k1 : 64'h0),
                        s[63:0] ^ dsep};
  wire [7:0] rc_first = do_final ? 8'hf0 : 8'hb4;   // p^12 starts at round 0, p^8 at round 4
  // one round datapath, shared: the running permutation, or the first round of a block being
  // absorbed (the absorb is an XOR in front of the same round)
  wire absorb = !busy && take;
  wire [7:0] rc = absorb ? rc_first : {4'hf - rnd, rnd};
  wire [319:0] rout = round_fn(absorb ? s_abs : s, rc);

  assign in_ready = ready_st && !busy;

  always @(posedge clk) begin
    if (rst) begin
      s <= 320'h0; k0 <= 64'h0; k1 <= 64'h0; rnd <= 4'd0; busy <= 1'b0; post_key <= 1'b0;
      final_perm <= 1'b0; ready_st <= 1'b0; dsep_done <= 1'b0;
      ct_valid <= 1'b0; ct <= 128'h0; tag_valid <= 1'b0; tag <= 128'h0;
    end else begin
      ct_valid <= 1'b0; tag_valid <= 1'b0;
      if (load) begin
        k0 <= bswap64(key[127:64]); k1 <= bswap64(key[63:0]);
        s <= {IV, bswap64(key[127:64]), bswap64(key[63:0]), bswap64(nonce[127:64]), bswap64(nonce[63:0])};
        rnd <= 4'd0; busy <= 1'b1; post_key <= 1'b1; final_perm <= 1'b0;
        ready_st <= 1'b0; dsep_done <= 1'b0;
      end else if (busy) begin
        if (rnd == 4'd11) begin
          s <= rout ^ post; busy <= 1'b0;
          if (final_perm) begin
            tag <= {bswap64(rout[127:64] ^ k0), bswap64(rout[63:0] ^ k1)};
            tag_valid <= 1'b1; ready_st <= 1'b0;
          end else ready_st <= 1'b1;
        end else begin
          s <= rout; rnd <= rnd + 4'd1;
        end
      end else if (take) begin
        if (is_msg) begin
          ct <= (rate_mem ^ in_data) & mask; ct_valid <= 1'b1; dsep_done <= 1'b1;
        end
        s <= rout;
        rnd <= do_final ? 4'd1 : 4'd5;
        busy <= 1'b1; post_key <= do_final; final_perm <= do_final;
      end
    end
  end
endmodule
