module bitcoin_hash(input logic        clk, reset_n, start,
                    input logic [15:0] message_addr, output_addr,
                   output logic        done, mem_clk, mem_we,
                   output logic [15:0] mem_addr,
                   output logic [31:0] mem_write_data,
                    input logic [31:0] mem_read_data);

// 192.75 MHz, 2331 +
// remove post in substate
enum logic [3:0] {IDLE,PREP,FIRST_SIXTEEN,PREP_KERNEL,KERNEL,POST_PHASE1,PREP_PHASE2,PHASE2,POSTPROCESS} state;
enum logic [2:0] {P2_PREP,P2_FIRST_SIXTEEN,P3_PREP,P3_FIRST_SIXTEEN,PREP_COMPUTE,COMPUTE} substate;
typedef enum logic {FALSE=1'b0,TRUE=1'b1} bool_t;

assign done = (state == IDLE);

parameter INIT_H0 = 32'h6a09e667;
parameter INIT_H1 = 32'hbb67ae85;
parameter INIT_H2 = 32'h3c6ef372;
parameter INIT_H3 = 32'ha54ff53a;
parameter INIT_H4 = 32'h510e527f;
parameter INIT_H5 = 32'h9b05688c;
wire [31:0] INIT_H6 = 32'h1f83d9ab; // used over and over in phase 3 so make a wire.
parameter INIT_H7 = 32'h5be0cd19;
parameter WORDS_TO_READ = 20;

// ---------------------------------------------------------------------------------------
reg [31:0] d_prev,b,c,d,m,f,g,h1; // intermedimediate values
reg [5:0] nonce;
reg [0:7] [31:0] h; // hold output
reg [0:7] [31:0] h_p1; // hold output, phase 1
reg [0:15] [31:0] w; // hold words of the padded message.
reg [5:0] t; // count round
reg [5:0] rw; // read/write counter
reg [0:2] [31:0] w_temp;
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
wire [31:0] size_phase3 = 32'd256;

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

            h_p1[0:7] <= {INIT_H0,INIT_H1,INIT_H2,INIT_H3,INIT_H4,INIT_H5,INIT_H6,INIT_H7};
            cur_addr <= message_addr;
            cur_we <= 1'b0;
            cur_write_data <= 0;

            state <= PREP;
        end

    PREP:
    begin
        cur_we <= 1'b0;
        cur_addr <= message_addr;
        rw <= rw + 1;
        nonce <= 0;
        t <= 0;

        {b,c,d,d_prev,f,g,h1} <= {h_p1[0:5],h_p1[7]};
        state <= FIRST_SIXTEEN;
    end

    FIRST_SIXTEEN:
    begin
        t <= t + 1;

        if(t==0) begin
            h1 <= h_p1[6]; // h1 <= g = h[6];
        end else begin
            {d_prev,b,c,d,f,g,h1} <= sha256_op(d_prev,b,c,d,f,g,h1,m);
        end

        w[t] <= mem_read_data;
        m <= sha256_k1[t] + mem_read_data + h1;

        // read from memory even if there is nothing to read
        if (rw==16) begin
            state <= PREP_KERNEL;
        end else begin
            cur_we <= 1'b0;
            cur_addr <= message_addr;
            rw<=rw + 1;

            state <= FIRST_SIXTEEN;
        end
    end

    PREP_KERNEL:
    begin
        for (int n = 0; n < 15; n++) w[n] <= w[n+1];
        w[15] <= next_word();
        w_temp[0] <= mem_read_data;
        cur_we <= 1'b0;
        cur_addr <= message_addr;
        rw<=rw + 1;

        state <= KERNEL;
    end

    KERNEL:
    begin
        m <=  sha256_k2[t] + h1 + w[15];

        for (int n = 0; n < 15; n++) w[n] <= w[n+1];
        w[15] <= next_word();

        {d_prev,b,c,d,f,g,h1} <= sha256_op(d_prev,b,c,d,f,g,h1,m);

        if (t==0) begin // "t" hits 64 but only have 6 bits
            h_p1[1] <= b + h_p1[1];
            h_p1[5] <= f + h_p1[5];
            h_p1[2] <= c + h_p1[2];
            h_p1[3] <= d + h_p1[3];
            h_p1[6] <= g + h_p1[6];
            h_p1[7] <= h1 + h_p1[7];

            state <= KERNEL;
        end

        if(t==1) begin
            w_temp[1] <= mem_read_data;
            h_p1[0] <= h_p1[0] + b;
            h_p1[4] <= h_p1[4] + f;
            state <= PREP_PHASE2;
        end else begin
            state <= KERNEL;
            t <= t + 1;
        end
    end

    PREP_PHASE2: begin
        w_temp[2] <= mem_read_data;
        state <= PHASE2;
        substate <= P2_PREP;
    end

    PHASE2: begin
        case(substate)
        P2_PREP: begin
            t <= 0;
            substate <= P2_FIRST_SIXTEEN;
            {b,c,d,d_prev,f,g,h1} <= {h_p1[0:5],h_p1[7]};
        end
        P2_FIRST_SIXTEEN:
        begin
            t <= t + 1;

            if(t==0) begin
                h1 <= h_p1[6]; // h1 <= g = h[6];
            end else begin
                {d_prev,b,c,d,f,g,h1} <= sha256_op(d_prev,b,c,d,f,g,h1,m);
            end

            unique case(padding)
            TRUE: begin
                if (t==15) begin // add size in bits
                    w[t] <= size_bits;
                    m <= sha256_k1[t] + size_bits + h1;
                end else if(t==4) begin
                    w[t] <= delimiter;
                    m <= sha256_k1[t] + delimiter + h1;
                end else begin // add zeros
                    w[t] <= 32'd0;
                    m <= sha256_k1[t] + 32'd0 + h1;
                end
            end
            default: begin
                if (t==3) begin // add delimiter (10...0)
                    w[t] <= nonce;
                    m <= sha256_k1[t] + nonce + h1;
                    padding <= TRUE;
                end else begin // read from memory
                    w[t] <= w_temp[t];
                    m <= sha256_k1[t] + w_temp[t] + h1;
                end
            end
            endcase

            if (t==15) begin
                substate <= PREP_COMPUTE;
            end else begin
                substate <= P2_FIRST_SIXTEEN;
            end
        end

        PREP_COMPUTE:
        begin
            for (int n = 0; n < 15; n++) w[n] <= w[n+1];
            w[15] <= next_word();

            substate <= COMPUTE;
        end

        COMPUTE:
        begin
            m <=  sha256_k2[t] + h1 + w[15];

            for (int n = 0; n < 15; n++) w[n] <= w[n+1];
            w[15] <= next_word();

            {d_prev,b,c,d,f,g,h1} <= sha256_op(d_prev,b,c,d,f,g,h1,m);

            unique case(padding)
            TRUE: begin
                if (t==0) begin // "t" hits 64 but only have 6 bits
                    h[1] <= b + h_p1[1]; // b is b heres
                    h[5] <= f + h_p1[5]; // f is f here
                    h[2] <= c + h_p1[2];
                    h[3] <= d + h_p1[3];
                    h[6] <= g + h_p1[6];
                    h[7] <= h1 + h_p1[7];
                    substate <= P3_PREP;
                end else begin
                    substate <= COMPUTE;
                    t <= t + 1;
                end
            end
            default: begin
                if (t==0) begin // "t" hits 64 but only have 6 bits
                    state <= POSTPROCESS;
                    substate <= P2_PREP;
                end else begin
                    substate <= COMPUTE;
                    t <= t + 1;
                end
            end
            endcase
        end

        P3_PREP:
        begin
            {b,c,d,d_prev,f,g,h1} <= {INIT_H0,INIT_H1,INIT_H2,INIT_H3,INIT_H4,INIT_H5,INIT_H7};
            padding <= FALSE;

            h[0] <= b + h_p1[0];
            h[4] <= f + h_p1[4];

            substate <= P3_FIRST_SIXTEEN;
        end

        P3_FIRST_SIXTEEN:
        begin
            t <= t + 1;

            if(t==0) begin
                h1 <= INIT_H6;
            end else begin
                {d_prev,b,c,d,f,g,h1} <= sha256_op(d_prev,b,c,d,f,g,h1,m);
            end

            unique casez(t)
            15: begin
                w[t] <= size_phase3;
                m <= size_phase3 + sha256_k1[t] + h1;
            end
            8: begin
                w[t] <= delimiter;
                m <= delimiter + sha256_k1[t] + h1;
            end
            6'b000???: begin
                w[t] <= h[t];
                m <= h[t] + sha256_k1[t] + h1;
            end
            default:begin
                w[t] <= 32'd0;
                m <= 32'd0 + sha256_k1[t] + h1;
            end
            endcase

            // read from memory even if there is nothing to read
            if (t==15) begin
                substate <= PREP_COMPUTE;
            end else begin
                substate <= P3_FIRST_SIXTEEN;
            end
        end

        endcase // PHASE 3
    end

    POSTPROCESS: begin
        cur_we <= 1'b1;
        cur_addr <= output_addr;
        rw <= nonce;
        nonce <= nonce + 1;
        cur_write_data <= (b + INIT_H0);

        unique case(nonce)
        16: begin
            state <= IDLE;
        end
        15: begin
            state <= POSTPROCESS;
        end
        default: begin
            state <= PHASE2;
        end
        endcase
    end
    endcase
end
endmodule
