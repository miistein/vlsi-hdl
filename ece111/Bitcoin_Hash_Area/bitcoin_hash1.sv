module bitcoin_hash(input logic        clk, reset_n, start,
                    input logic [15:0] message_addr, output_addr,
                   output logic        done, mem_clk, mem_we,
                   output logic [15:0] mem_addr,
                   output logic [31:0] mem_write_data,
                    input logic [31:0] mem_read_data);
`include "sha256_functions.sv"

enum logic [3:0] {IDLE,PREP,FIRST_SIXTEEN,PREP_KERNEL,P2_PREP,P2_FIRST_SIXTEEN,P3_PREP,P3_FIRST_SIXTEEN,PREP_COMPUTE,COMPUTE,POSTPROCESS} state;
typedef enum logic {FALSE=1'b0,TRUE=1'b1} bool_t;

assign done = (state == IDLE);

wire [31:0] INIT_H6 = 32'h1f83d9ab; // used over and over in phase 3 so make a wire.

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

// Find w[16] given w[0] to w[15]
function [31:0] next_word();
    next_word = w[0] + (rightrotate(w[1], 7) ^ rightrotate(w[1], 18) ^ (w[1]  >>  3)) + w[9] + (rightrotate(w[14], 17) ^ rightrotate(w[14], 19) ^ (w[14] >> 10));
endfunction

always_ff @(posedge clk, negedge reset_n)
begin
    if (!reset_n) begin
        state <= IDLE;
        cur_we <= 1'b0;
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
            state <= PREP_COMPUTE;
        end else begin
            cur_we <= 1'b0;
            cur_addr <= message_addr;
            rw<=rw + 1;

            state <= FIRST_SIXTEEN;
        end
    end

    P2_PREP: begin
        t <= 0;
        w[5:14] <= 0;
        w_temp[2] <= mem_read_data;
        padding <= FALSE;

        state <= P2_FIRST_SIXTEEN;
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

        case(padding)
        TRUE: begin
            if (t==15) begin // add size in bits
                w[t] <= size_bits;
                m <= sha256_k1[t] + size_bits + h1;
            end else if(t==4) begin
                w[t] <= delimiter;
                m <= sha256_k1[t] + delimiter + h1;
            end else if(t<=3) begin // add zeros
                m <= sha256_k1[t] + h1;
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

        if (t==16) begin
            for (int n = 0; n < 15; n++) w[n] <= w[n+1];
            w[15] <= next_word();
            state <= PREP_COMPUTE;
        end else begin
            state <= P2_FIRST_SIXTEEN;
        end
    end

    PREP_COMPUTE:
    begin
        state <= COMPUTE;
    end

    COMPUTE:
    begin
        m <=  sha256_k2[t] + h1 + w[15];

        for (int n = 0; n < 15; n++) w[n] <= w[n+1];
        w[15] <= next_word();

        {d_prev,b,c,d,f,g,h1} <= sha256_op(d_prev,b,c,d,f,g,h1,m);

        case(padding)
        TRUE: begin
            if (t==0) begin // "t" hits 64 but only have 6 bits
                h[1] <= b + h_p1[1]; // b is b heres
                h[5] <= f + h_p1[5]; // f is f here
                h[2] <= c + h_p1[2];
                h[3] <= d + h_p1[3];
                h[6] <= g + h_p1[6];
                h[7] <= h1 + h_p1[7];
                state <= P3_PREP;
            end else begin
                state <= COMPUTE;
                t <= t + 1;
            end
        end
        FALSE: begin
            if (t==0) begin // "t" hits 64 but only have 6 bits
                state <= POSTPROCESS;
            end else begin
                t <= t + 1;
					 state <= COMPUTE;
            end
        end
        default: begin
            case(t)
            1: begin
                w_temp[1] <= mem_read_data;
                h_p1[0] <= h_p1[0] + b;
                h_p1[4] <= h_p1[4] + f;
                state <= P2_PREP;
            end
            default: begin
                t <= t + 1;
                state <= COMPUTE;
            end
            endcase

            if(t==0) begin
                h_p1[1] <= b + h_p1[1];
                h_p1[5] <= f + h_p1[5];
                h_p1[2] <= c + h_p1[2];
                h_p1[3] <= d + h_p1[3];
                h_p1[6] <= g + h_p1[6];
                h_p1[7] <= h1 + h_p1[7];
                cur_we <= 1'b0;
                cur_addr <= message_addr;
                rw<=rw + 1;
            end
        end
        endcase
    end

    P3_PREP:
    begin
        {b,c,d,d_prev,f,g,h1} <= {INIT_H0,INIT_H1,INIT_H2,INIT_H3,INIT_H4,INIT_H5,INIT_H7};
        padding <= FALSE;
        w[9:14] <= 0;

        h[0] <= b + h_p1[0];
        h[4] <= f + h_p1[4];

        state <= P3_FIRST_SIXTEEN;
    end

    P3_FIRST_SIXTEEN:
    begin
        t <= t + 1;

        if(t==0) begin
            h1 <= INIT_H6;
        end else begin
            {d_prev,b,c,d,f,g,h1} <= sha256_op(d_prev,b,c,d,f,g,h1,m);
        end

        casez(t)
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
            m <= sha256_k1[t] + h1;
        end
        endcase

        // read from memory even if there is nothing to read
        if (t==15) begin
            state <= PREP_COMPUTE;
        end else begin
            state <= P3_FIRST_SIXTEEN;
        end
    end


    POSTPROCESS: begin
        cur_we <= 1'b1;
        cur_addr <= output_addr;
        rw <= nonce;
        nonce <= nonce + 1;
        cur_write_data <= (b + INIT_H0);

        case(nonce)
        16: begin
            state <= IDLE;
        end
        15: begin
            state <= POSTPROCESS;
        end
        default: begin
            state <= P2_PREP;
        end
        endcase
    end
    endcase
end
endmodule
