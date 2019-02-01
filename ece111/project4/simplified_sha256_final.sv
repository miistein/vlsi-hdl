module simplified_sha256(input logic clk, reset_n, start,
    input logic [15:0] message_addr, output_addr,
    output logic done, mem_clk, mem_we,
    output logic [15:0] mem_addr,
    output logic [31:0] mem_write_data,
    input logic [31:0] mem_read_data);
// Compute sha256(message).
// Return the 256 bit hash written to the caller in the form of 7 words.
// Design structure will only work if reading from memory and message is 2 blocks (after padding).
// This design uses the fact that e is not needed until the end, neither is a, when computing h0-7 since b<=a,f<=e.
// As described in the paper "Improving SHA-2 Hardware Implementations" by Ricardo Chaves,Georgi Kuzmanov,Leonel Sousa, Stamatis Vassiliadis

parameter INIT_SHA256 = 256'h6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19;
parameter WORDS_TO_READ = 21;

enum logic [2:0] {IDLE,PROLOG,FIRST_SIXTEEN_SHA256,KERNEL_SHA256,POSTPROCESSING,WRITE,PREP_KERNEL_SHA256} state;
typedef enum logic {FALSE=1'b0,TRUE=1'b1} bool_t;

assign done = (state == IDLE);

// ---------------------------------------------------------------------------------------
reg [31:0] d_prev,b,c,d,m,f,g,h1; // intermediate values
reg [31:0] h[8]; // hold output
reg [0:15] [31:0] w; // hold words of the padded message.
reg [5:0] t; // count round
reg [31:0] rw; // read/write counter
bool_t padding; // true only if we are padding

// ---------------------------------------------------------------------------------------
// Memory Model
logic        cur_we;
logic [15:0] cur_addr;
logic [31:0] cur_write_data;

assign mem_clk = clk;
assign mem_we = cur_we;
assign mem_addr = cur_addr + rw;
assign mem_write_data = cur_write_data;

// ---------------------------------------------------------------------------------------
// define constants used for padding multiple times
wire [31:0] size_bits = 32'd640;
wire [31:0] delimiter = 32'h80000000;

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
// Functions
// Perform right rotation on a 32 bit number
function [31:0] rightrotate(input logic [31:0] in1,
                            input logic [31:0] r);
   rightrotate = (in1 >> r) | (in1 << (32-r));
endfunction

// Find intermediate values for h0-h7 which are a-h accordingly. a,e are ommitted in this implementation.
function logic [223:0] sha256_op(input logic [31:0] d_prev, b, c, d, f, g, h_compute, m);
begin
	logic [31:0] b_next,f_next;

    b_next = ((rightrotate(f,6)) ^ (rightrotate(f,11)) ^ (rightrotate(f,25))) + ((f & g) | ((~f) & h_compute)) + ((rightrotate(b,2))
               ^ (rightrotate(b,13)) ^ (rightrotate(b,22))) + ((b & c) | (b & d) | (c & d)) + m;
    f_next = ((rightrotate(f,6)) ^ (rightrotate(f,11)) ^ (rightrotate(f,25))) + d_prev + ((f & g) | ((~f) & h_compute)) + m;

    sha256_op = {d,b_next,b,c,f_next,f,g};
end
endfunction

// Find w[16] given w[0] to w[15]
function [31:0] next_word();
    next_word = w[0] + (rightrotate(w[1], 7) ^ rightrotate(w[1], 18) ^ (w[1]  >>  3)) + w[9] + (rightrotate(w[14], 17) ^ rightrotate(w[14], 19) ^ (w[14] >> 10));
endfunction

always_ff @(posedge clk, negedge reset_n)
begin
    if (!reset_n) begin
        state <= IDLE;
        cur_we <= 1'b0;

        padding <= FALSE;

    end else case(state)

    IDLE:
        if (start) begin
            rw <= 0;

            {h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]} <= INIT_SHA256;
            cur_addr <= message_addr;
            cur_we <= 1'b0;
            cur_write_data <= 0;

            state <= PROLOG;
        end

    PROLOG:
    begin
        cur_we <= 1'b0;
        cur_addr <= message_addr;
        rw <= rw + 1;
        t <= 0;

        b <= h[0];
        c <= h[1];
        d <= h[2];
        d_prev <= h[3];
        f <= h[4];
        g <= h[5];
        // Since
        // b <= a = h[0];
        // c <= b = h[1];
        // d <= c = h[2];
        // a <= d = h[3]; (d_prev is a)
        // f <= e = h[4];
        // g <= f = h[5];

        // h1 is used in precomputing part of b,f (see m <= ..) in the next cycle
        // so h1 is itself (h[7])
        h1 <= h[7];
        state <= FIRST_SIXTEEN_SHA256;
    end

    FIRST_SIXTEEN_SHA256:
    begin
        t <= t + 1;

        if(t==0) begin
            h1 <= h[6]; // h1 <= g = h[6];
        end else begin
            {d_prev,b,c,d,f,g,h1} <= sha256_op(d_prev,b,c,d,f,g,h1,m);
        end

        if (padding) begin
            if (rw==32) begin // add size in bits
                w[t] <= size_bits;
                m <= sha256_k1[t] + size_bits + h1;
            end else begin // add zeros
                w[t] <= 32'd0;
                m <= sha256_k1[t] + 32'd0 + h1;
            end
        end else begin
            if (rw == WORDS_TO_READ) begin // add delimiter (10...0)
                w[t] <= delimiter;
                m <= sha256_k1[t] + delimiter + h1;
                padding <= TRUE;
            end else begin // read from memory
                w[t] <= mem_read_data;
                m <= sha256_k1[t] + mem_read_data + h1;
            end
        end

        // read from memory even if there is nothing to read
        if ((rw==16)||(rw==32)) begin
            state <= PREP_KERNEL_SHA256;
        end else begin
            cur_we <= 1'b0;
            cur_addr <= message_addr;
            rw<=rw + 1;

            state <= FIRST_SIXTEEN_SHA256;
        end
    end

    PREP_KERNEL_SHA256:
    begin
        for (int n = 0; n < 15; n++) w[n] <= w[n+1];
        w[15] <= next_word();

        state <= KERNEL_SHA256;
    end

    KERNEL_SHA256:
    begin
        m <=  sha256_k2[t] + h1 + w[15];

        for (int n = 0; n < 15; n++) w[n] <= w[n+1];
        w[15] <= next_word();

        {d_prev,b,c,d,f,g,h1} <= sha256_op(d_prev,b,c,d,f,g,h1,m);

        if (t==0) begin // "t" hits 64 but only have 6 bits
            h[1] <= b + h[1]; // b is b here
            h[5] <= f + h[5]; // f is f here
            h[2] <= c + h[2];
            h[3] <= d + h[3];
            h[6] <= g + h[6];
            h[7] <= h1 + h[7];
            state <= POSTPROCESSING;
        end else begin
            state <= KERNEL_SHA256;
            t <= t + 1;
        end
    end

    POSTPROCESSING:
    begin
        h[0] <= b + h[0]; // b is a here
        h[4] <= f + h[4]; // f is e here

        if (rw == 32) begin // write when block is 2
            state <= WRITE;
            cur_we <= 1'b1;
            rw <= 0;
            cur_addr <= output_addr;
            cur_write_data <= (b + h[0]);
            t <= t + 1;
        end else begin
            state <=PROLOG;
        end
    end

    WRITE:
    begin
        case(t)
        0: begin
            cur_write_data <= h[0];
        end
        1: begin
            cur_write_data <= h[1];
        end
        2: begin
            cur_write_data <= h[2];
        end
        3: begin
            cur_write_data <= h[3];
        end
        4: begin
            cur_write_data <= h[4];
        end
        5: begin
            cur_write_data <= h[5];
        end
        6: begin
            cur_write_data <= h[6];
        end
        7: begin
            cur_write_data <= h[7];
        end
        endcase

        if (rw==8)
            state <= IDLE;
        else begin
            t <= t + 1;
            cur_we <= 1'b1;
            cur_addr <= output_addr;
            rw <= rw + 1;
        end
    end

    endcase
    end
endmodule
