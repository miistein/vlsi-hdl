module sha256_blk2(input logic clk, reset_n, start,
    input logic [15:0] message_addr, output_addr,
    output logic done, mem_clk, mem_we,
    output logic [15:0] mem_addr,
    output logic [31:0] mem_write_data,
    input logic [31:0] mem_read_data,
    input logic [31:0] nonce);

parameter init_sha256 = 256'h6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19;

enum logic [2:0] {IDLE,PROLOG,READ_SHA256,KERNEL_SHA256,POSTPROCESSING,WRITE,PREP_KERNEL_SHA256} state;
typedef enum logic {FALSE=1'b0,TRUE=1'b1} bool_t;
bool_t padding;

reg [31:0] a,b,c,d,e,m,f1,g,h1; //init for KERNEL_SHA256
reg [0:7] [31:0] h; //init for prolog, I write h0 without a mux.
reg [0:15] [31:0] w; // hold blocks.
reg [7:0] t; //counter,1bit used for signed
reg [31:0] offset; // read counter, number of words
reg        cur_we;
reg [15:0] cur_addr;
reg [31:0] cur_write_data;

assign mem_clk = clk;
assign mem_we = cur_we;
assign mem_addr = cur_addr + offset;
assign mem_write_data = cur_write_data;
assign done = (state == IDLE);

// ---------------------------------------------------------------------------------------
// define wires for conditionals
wire [4:0] num_words = 20; // wires better for assignment to registers
wire [31:0] num_bits = 32'd640;
wire [31:0] lw = 32'h80000000;
wire [31:0] n = nonce;

// ---------------------------------------------------------------------------------------
// SHA256 K constants
parameter int sha256_k1[0:15] = '{
      32'h428a2f98, 32'h71374491, 32'hb5c0fbcf, 32'he9b5dba5, 32'h3956c25b, 32'h59f111f1, 32'h923f82a4, 32'hab1c5ed5,
      32'hd807aa98, 32'h12835b01, 32'h243185be, 32'h550c7dc3, 32'h72be5d74, 32'h80deb1fe, 32'h9bdc06a7, 32'hc19bf174
};

parameter int sha256_k2[16:63] = '{
      32'he49b69c1, 32'hefbe4786, 32'h0fc19dc6, 32'h240ca1cc, 32'h2de92c6f, 32'h4a7484aa, 32'h5cb0a9dc, 32'h76f988da,
      32'h983e5152, 32'ha831c66d, 32'hb00327c8, 32'hbf597fc7, 32'hc6e00bf3, 32'hd5a79147, 32'h06ca6351, 32'h14292967,
      32'h27b70a85, 32'h2e1b2138, 32'h4d2c6dfc, 32'h53380d13, 32'h650a7354, 32'h766a0abb, 32'h81c2c92e, 32'h92722c85,
      32'ha2bfe8a1, 32'ha81a664b, 32'hc24b8b70, 32'hc76c51a3, 32'hd192e819, 32'hd6990624, 32'hf40e3585, 32'h106aa070,
      32'h19a4c116, 32'h1e376c08, 32'h2748774c, 32'h34b0bcb5, 32'h391c0cb3, 32'h4ed8aa4a, 32'h5b9cca4f, 32'h682e6ff3,
      32'h748f82ee, 32'h78a5636f, 32'h84c87814, 32'h8cc70208, 32'h90befffa, 32'ha4506ceb, 32'hbef9a3f7, 32'hc67178f2
};

// ---------------------------------------------------------------------------------------
// right rotation
function [31:0] rightrotate(input logic [31:0] in1,
                                  input logic [7:0] r);
   rightrotate = (in1 >> r) | (in1 << (32-r));
endfunction

//wtnew
function [31:0] wtnew();
    wtnew = w[0] + (rightrotate(w[1], 7) ^ rightrotate(w[1], 18) ^ (w[1]  >>  3)) + w[9] + (rightrotate(w[14], 17) ^ rightrotate(w[14], 19) ^ (w[14] >> 10));
endfunction

// ---------------------------------------------------------------------------------------

always_ff @(posedge clk, negedge reset_n)
begin
    if (!reset_n) begin
        state <= IDLE;
        cur_we <= 1'b0;
        t <= -1;
    end else case(state)
    IDLE:
        if (start) begin
            offset <= 0;

            padding <= FALSE;
            {h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]} <= init_sha256;
            cur_addr <= message_addr;
            cur_we <= 1'b0;
            cur_write_data <= 0; //~3MHz improvement

            state <= PROLOG;
        end

    PROLOG:
    begin
        cur_we <= 1'b0;
        cur_addr <= message_addr;
        offset <= offset + 1;
        t <= t+1;

        a <= h[0];
        b <= h[1];
        c <= h[2];
        d <= h[3];
        e <= h[4];
        f1 <= h[5];
        g <= h[6];
        h1 <= h[7];

        state <= READ_SHA256;
    end

    READ_SHA256:
    begin
        c <= b;
        d <= c;
        g <= f1;
        h1 <= g;
        a <= d;

        if ((offset==1) || (offset==17)) begin
            b <= a;
            f1 <= e;
        end else begin
            b <= ((rightrotate(f1,6)) ^ (rightrotate(f1,11)) ^ (rightrotate(f1,25))) + ((f1 & g) | ((~f1) & h1)) + ((rightrotate(b,2))
                   ^ (rightrotate(b,13)) ^ (rightrotate(b,22))) + ((b & c) | (b & d) | (c & d)) + m;
            f1 <= ((rightrotate(f1,6)) ^ (rightrotate(f1,11)) ^ (rightrotate(f1,25))) + a + ((f1 & g) | ((~f1) & h1)) + m;
        end

        if (offset>=16) begin
            if (t==4'd15) begin
                w[t] <= num_bits;
                m <= sha256_k1[t] + num_bits + h1;
            end else begin // add zeros
                w[t] <= 32'd0;
                m <= sha256_k1[t] + 32'd0 + h1;
            end
        end else begin
            if (offset == num_words) begin // add delimiter
                w[t] <= lw;
                m <= sha256_k1[t] + lw + h1;
                padding <= TRUE;
            end else begin //default
                w[t] <= mem_read_data;
                m <= sha256_k1[t] + mem_read_data + h1;
            end
        end
// wow don't even need t to be used at all because we know the message holy fuck.
        if (t==4'd15) begin
            state <= PREP_KERNEL_SHA256;
        end else begin // READ.
            cur_we <= 1'b0;
            cur_addr <= message_addr;
            offset<=offset + 1;

            state <= READ_SHA256;
        end
    end

    PREP_KERNEL_SHA256:
    begin
        for (int n = 0; n < 15; n++) w[n] <= w[n+1];
        w[15] <= wtnew();
        state <= KERNEL_SHA256;
    end

    KERNEL_SHA256:
    begin
        if (t==7'd64) begin
            a <= ((rightrotate(f1,6)) ^ (rightrotate(f1,11)) ^ (rightrotate(f1,25))) + ((f1 & g) | ((~f1) & h1)) + ((rightrotate(b,2))
                 ^ (rightrotate(b,13)) ^ (rightrotate(b,22))) + ((b & c) | (b & d) | (c & d)) + m;
            e <= ((rightrotate(f1,6)) ^ (rightrotate(f1,11)) ^ (rightrotate(f1,25))) + a + ((f1 & g) | ((~f1) & h1)) + m;

            state <= POSTPROCESSING;
        end else begin
            c <= b;
            d <= c;
            g <= f1;
            h1 <= g;
            a <= d;

            b <= ((rightrotate(f1,6)) ^ (rightrotate(f1,11)) ^ (rightrotate(f1,25))) + ((f1 & g) | ((~f1) & h1)) + ((rightrotate(b,2))
                 ^ (rightrotate(b,13)) ^ (rightrotate(b,22))) + ((b & c) | (b & d) | (c & d)) + m;
            f1 <= ((rightrotate(f1,6)) ^ (rightrotate(f1,11)) ^ (rightrotate(f1,25))) + a + ((f1 & g) | ((~f1) & h1)) + m;
            m <=  sha256_k2[t] + h1 + w[15];

            for (int n = 0; n < 15; n++) w[n] <= w[n+1];
            w[15] <= wtnew();

            state <= KERNEL_SHA256;
            t <= t + 1;
        end
    end

    POSTPROCESSING:
    begin
        h[0] <= a + h[0];
        h[1] <= b + h[1];
        h[2] <= c + h[2];
        h[3] <= d + h[3];
        h[4] <= e + h[4];
        h[5] <= f1 + h[5];
        h[6] <= g + h[6];
        h[7] <= h1 + h[7];

        if (offset == 32) begin // start to write under this block
            state <= WRITE;
            cur_we <= 1'b1;
            offset <= 0;
            cur_addr <= output_addr;
            cur_write_data <= (a + h[0]);
            t <= t+1;
        end else begin
            state <=PROLOG;
            t <= -1;
        end
    end

    WRITE: begin
        if (t[2:0] == 0) // t hits 72
            state <= IDLE;
        else
            cur_we <= 1'b1;

        cur_write_data <= h[t[2:0]];
        cur_addr <= output_addr;
        offset <= offset + 1;
        t <= t + 1;
        end
    endcase
    end
endmodule
//192 MHz
