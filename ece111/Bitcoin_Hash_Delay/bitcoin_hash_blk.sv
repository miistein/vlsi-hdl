module two_blk_hash (input logic        clk, reset_n, two_blk_start,
                 output logic        two_blk_done,
                 input reg [31:0] nonce,
                 input  reg [0:7] [31:0] h_p1, // hold output, phase 1
                 input reg [0:2] [31:0] w_temp,
                 output reg [31:0] h_out // hold output
);
// combine phase 2 and phase 3. But the best way to do this was to use double always_ff
// and
// probably not combine phase 2 and phase 3.
//

`include "sha256_functions.sv"

enum logic [2:0] {P2_PREP,P2_FIRST_SIXTEEN,P3_PREP,P3_FIRST_SIXTEEN,PREP_COMPUTE,COMPUTE,POST} substate;
typedef enum logic {FALSE=1'b0,TRUE=1'b1} bool_t;
bool_t padding; // true only if we are padding

wire [31:0] INIT_H6 = 32'h1f83d9ab;
wire [31:0] size_bits = 32'd640;
wire [31:0] delimiter = 32'h80000000;
wire [31:0] size_phase3 = 32'd256;

reg [0:7] [31:0] h;
reg [0:15] [31:0] w; // hold words of the padded message.
reg [5:0] t; // count round
// ---------------------------------------------------------------------------------------

assign two_blk_done = (substate == P2_PREP);

// Find w[16] given w[0] to w[15]
function [31:0] next_word();
    next_word = w[0] + (rightrotate(w[1], 7) ^ rightrotate(w[1], 18) ^ (w[1]  >>  3)) + w[9] + (rightrotate(w[14], 17) ^ rightrotate(w[14], 19) ^ (w[14] >> 10));
endfunction

always_ff @(posedge clk, negedge reset_n)
begin
    if (!reset_n) begin
        substate <= P2_PREP;
    end else case(substate)

    P2_PREP: begin
        if(two_blk_start) begin
            t <= 0;
            substate <= P2_FIRST_SIXTEEN;
            {b,c,d,d_prev,f,g,h1} <= {h_p1[0:5],h_p1[7]};

        end
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
                m <= sha256_k1[t] + h1 + size_bits;
            end else if(t==4) begin
                w[t] <= delimiter;
                m <= sha256_k1[t] + h1 + delimiter;
            end else begin // add zeros
                w[t] <= 32'd0;
                m <= sha256_k1[t] + 32'd0 + h1;
            end
        end
        default: begin
            if (t==3) begin // add delimiter (10...0)
                w[t] <= nonce;
                m <= sha256_k1[t] + h1 + nonce;
                padding <= TRUE;
            end else begin // read from memory
                w[t] <= w_temp[t];
                m <= sha256_k1[t] + h1 + w_temp[t];
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
                substate <= POST;
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
            m <= sha256_k1[t] + 32'd0 + h1;
        end
        endcase

        // read from memory even if there is nothing to read
        if (t==15) begin
            substate <= PREP_COMPUTE;
        end else begin
            substate <= P3_FIRST_SIXTEEN;
        end
    end

    POST: begin
        h_out <= b + INIT_H0;
        substate <= P2_PREP;
    end

    endcase // PHASE 3
end

endmodule
