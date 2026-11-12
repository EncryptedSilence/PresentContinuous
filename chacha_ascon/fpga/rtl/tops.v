// Synthesis wrappers of the full-round cores for place-and-route on the GW5A-25A (Gowin IDE
// projects in fpga/gowin/, open-source flow in fpga/tools/oss_flow.py). The cores have
// hundreds of ports; the wrappers give them four input pins and eight output pins without
// letting synthesis treat anything as constant:
//   - key, nonce, counter (and Ascon's data and controls) come from a shift register fed
//     serially from pin `din`, so every bit is a live register;
//   - `go` (edge-detected) pulses the core's load;
//   - the core runs continuously (run = 1, Ascon: a block whenever it is ready), and every
//     output block is XOR-folded into the 8-bit register on `dout`.
// The wrapper's own logic (the shift register and the fold tree) is reported separately
// from the core in fpga/README.md: resource counts of the core come from synthesizing the
// core module alone.
`timescale 1ns/1ps

module fold_reg #(parameter W = 128) (
  input  wire         clk,
  input  wire         en,
  input  wire [W-1:0] v,
  output reg  [7:0]   q
);
  integer i;
  reg [7:0] f;
  always @(*) begin
    f = 8'h0;
    for (i = 0; i < W / 8; i = i + 1) f = f ^ v[8 * i +: 8];
  end
  always @(posedge clk) if (en) q <= q ^ f;
endmodule

module cfg_shift #(parameter W = 64) (
  input  wire         clk,
  input  wire         din,
  output reg  [W-1:0] q
);
  always @(posedge clk) q <= {q[W-2:0], din};
endmodule

module top_aes128 (input wire clk, input wire rst, input wire din, input wire go, output wire [7:0] dout);
  wire [255:0] c; reg go_q; always @(posedge clk) go_q <= go;
  cfg_shift #(256) cfg(.clk(clk), .din(din), .q(c));
  wire [127:0] ks; wire v;
  aes_ctr #(.NK(4)) core(.clk(clk), .rst(rst), .load(go & ~go_q), .key(c[255:128]), .nonce(c[127:32]),
                         .ctr0(c[31:0]), .run(1'b1), .ks(ks), .ks_valid(v));
  fold_reg #(128) f(.clk(clk), .en(v), .v(ks), .q(dout));
endmodule

module top_aes256 (input wire clk, input wire rst, input wire din, input wire go, output wire [7:0] dout);
  wire [383:0] c; reg go_q; always @(posedge clk) go_q <= go;
  cfg_shift #(384) cfg(.clk(clk), .din(din), .q(c));
  wire [127:0] ks; wire v;
  aes_ctr #(.NK(8)) core(.clk(clk), .rst(rst), .load(go & ~go_q), .key(c[383:128]), .nonce(c[127:32]),
                         .ctr0(c[31:0]), .run(1'b1), .ks(ks), .ks_valid(v));
  fold_reg #(128) f(.clk(clk), .en(v), .v(ks), .q(dout));
endmodule

module top_qalqan (input wire clk, input wire rst, input wire din, input wire go, output wire [7:0] dout);
  wire [383:0] c; reg go_q; always @(posedge clk) go_q <= go;
  cfg_shift #(384) cfg(.clk(clk), .din(din), .q(c));
  wire [127:0] ks; wire v;
  qalqan_ctr core(.clk(clk), .rst(rst), .load(go & ~go_q), .key(c[383:128]), .nonce(c[127:32]),
                  .ctr0(c[31:0]), .run(1'b1), .ks(ks), .ks_valid(v));
  fold_reg #(128) f(.clk(clk), .en(v), .v(ks), .q(dout));
endmodule

module top_chacha20 (input wire clk, input wire rst, input wire din, input wire go, output wire [7:0] dout);
  wire [383:0] c; reg go_q; always @(posedge clk) go_q <= go;
  cfg_shift #(384) cfg(.clk(clk), .din(din), .q(c));
  wire [511:0] ks; wire v;
  chacha20_ctr core(.clk(clk), .rst(rst), .load(go & ~go_q), .key(c[383:128]), .nonce(c[127:32]),
                    .ctr0(c[31:0]), .run(1'b1), .ks(ks), .ks_valid(v));
  fold_reg #(512) f(.clk(clk), .en(v), .v(ks), .q(dout));
endmodule

module top_present80 (input wire clk, input wire rst, input wire din, input wire go, output wire [7:0] dout);
  wire [143:0] c; reg go_q; always @(posedge clk) go_q <= go;
  cfg_shift #(144) cfg(.clk(clk), .din(din), .q(c));
  wire [63:0] ks; wire v;
  present80_ctr core(.clk(clk), .rst(rst), .load(go & ~go_q), .key(c[143:64]), .ctr0(c[63:0]),
                     .run(1'b1), .ks(ks), .ks_valid(v));
  fold_reg #(64) f(.clk(clk), .en(v), .v(ks), .q(dout));
endmodule

module top_ascon128 (input wire clk, input wire rst, input wire din, input wire go, output wire [7:0] dout);
  wire [391:0] c; reg go_q; always @(posedge clk) go_q <= go;
  cfg_shift #(392) cfg(.clk(clk), .din(din), .q(c));
  wire rdy, cv, tv; wire [127:0] ct, tag; wire [7:0] d1, d2;
  ascon128_aead core(.clk(clk), .rst(rst), .load(go & ~go_q), .key(c[391:264]), .nonce(c[263:136]),
                     .in_ready(rdy), .in_valid(1'b1), .in_ad(c[135]), .in_last(c[134]),
                     .in_bytes({1'b0, c[131:128]}), .in_data(c[127:0]),
                     .ct_valid(cv), .ct(ct), .tag_valid(tv), .tag(tag));
  fold_reg #(128) f1(.clk(clk), .en(cv), .v(ct), .q(d1));
  fold_reg #(128) f2(.clk(clk), .en(tv), .v(tag), .q(d2));
  assign dout = d1 ^ d2;
endmodule
