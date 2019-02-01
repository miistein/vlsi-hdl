module bitcoin_hash(input logic        clk, reset_n, start,
                    input logic [15:0] message_addr, output_addr,
                   output logic        done, mem_clk, mem_we,
                   output logic [15:0] mem_addr,
                   output logic [31:0] mem_write_data,
                    input logic [31:0] mem_read_data);
`include "sha256_functions.sv"

enum logic [3:0] {IDLE,PREP,FIRST_SIXTEEN,PREP_KERNEL,KERNEL,PHASE2,PREP_PHASE3,PHASE3,PREP_WRITE,WRITE} state;
enum logic [1:0] {PREP_COMPUTE, WAIT_COMPUTE, COMPUTE} substate;

parameter NUM_NONCES = 16;
parameter INIT_H6 = 32'h1f83d9ab;

// ---------------------------------------------------------------------------------------
reg [0:7] [31:0] h_p1; // hold output, phase 1
reg [0:15] [31:0] w; // hold words of the padded message.
reg [5:0] t; // count round
reg [5:0] rw; // read/write counter
reg [0:2] [31:0] w_temp;

// ---------------------------------------------------------------------------------------
logic        cur_we;
logic [15:0] cur_addr;
logic [31:0] cur_write_data;

assign mem_clk = clk;
assign mem_we = cur_we;
assign mem_addr = cur_addr + rw;
assign mem_write_data = cur_write_data;
assign done = (state == IDLE);
// ---------------------------------------------------------------------------------------
wire [31:0] H_out[NUM_NONCES];
wire [31:0] H_p3[NUM_NONCES][8];
wire start_p2,start_p3;
wire finish_p2[NUM_NONCES],finish_p3[NUM_NONCES];

parameter int nonce_values[0:15] = '{
      32'd0,32'd1,32'd2,32'd3,32'd4,32'd5,32'd6,32'd7,32'd8,32'd9,32'd10,32'd11,32'd12,32'd13,32'd14,32'd15
};
// INSTANTIATE SHA256 MODULES
genvar q;
generate
    for (q = 0; q < NUM_NONCES; q++) begin : generate_sha256_blocks
        phase2 block (
            .clk(clk),
            .start(start_p2),
            .reset_n(reset_n),
            .h_out(H_p3[q]),
            .nonce(nonce_values[q]),
            .done(finish[q]),
            .h_p1(h_p1),
            .w_temp(w_temp));
    end
    for (q = 0; q < NUM_NONCES; q++) begin : generate_sha256_blocks
        phase3 block (
            .clk(clk),
            .start(start_p3),
            .reset_n(reset_n),
            .h_in(H_p3[q]),
            .h_out(H_out[q]),
            .done(finish[q]),
            .h_p1(h_p1));
    end
endgenerate

// Find w[16] given w[0] to w[15]
function [31:0] next_word();
    next_word = w[0] + (rightrotate(w[1], 7) ^ rightrotate(w[1], 18) ^ (w[1]  >>  3)) + w[9] + (rightrotate(w[14], 17) ^ rightrotate(w[14], 19) ^ (w[14] >> 10));
endfunction

assign start_p2 = (state == PHASE2);
assign start_p3 = (state == PHASE3);

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
            substate <= PREP_COMPUTE;

            state <= PREP;
        end

    PREP:
    begin
        cur_we <= 1'b0;
        cur_addr <= message_addr;
        rw <= rw + 1;
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
            cur_we <= 1'b0;
            cur_addr <= message_addr;
            rw<=rw + 1;
            state <= PREP_FINAL;
        end else begin
            state <= KERNEL;
            t <= t + 1;
        end
    end

    PREP_FINAL: begin
        w_temp[1] <= mem_read_data;

        h_p1[0] <= h_p1[0] + b;
        h_p1[4] <= h_p1[4] + f;
        state <= PHASE2;
    end

    PHASE2: begin
        w_temp[2] <= mem_read_data;

        state <= PREP_PHASE3;
    end

    PREP_PHASE3: begin
        if(finish_p2[0]) begin
            state <= PHASE3;
        end
    end

    PHASE3: begin
        state <= PREP_WRITE;
    end

    PREP_WRITE: begin
        if (finish[0]) begin
            rw <= 0;
            cur_write_data <= (H_out[0]);
            cur_we <= 1'b1;
            t <= t + 1;
            cur_addr <= output_addr;
            state <= WRITE;
        end
    end

    WRITE: begin
        case(t)
        0: begin
            cur_write_data <= (H_out[0]);
        end
        1: begin
            cur_write_data <= (H_out[1]);
        end
        2: begin
            cur_write_data <= (H_out[2]);
        end
        3: begin
            cur_write_data <= (H_out[3]);
        end
        4: begin
            cur_write_data <= (H_out[4]);
        end
        5: begin
            cur_write_data <= (H_out[5]);
        end
        6: begin
            cur_write_data <= (H_out[6]);
        end
        7: begin
            cur_write_data <= (H_out[7]);
        end
        8: begin
            cur_write_data <= (H_out[8]);
        end
        9: begin
            cur_write_data <= (H_out[9]);
        end
        10: begin
            cur_write_data <= (H_out[10]);
        end
        11: begin
            cur_write_data <= (H_out[11]);
        end
        12: begin
            cur_write_data <= (H_out[12]);
        end
        13: begin
            cur_write_data <= (H_out[13]);
        end
        14: begin
            cur_write_data <= (H_out[14]);
        end
        15: begin
            cur_write_data <= (H_out[15]);
        end
        endcase

        if(rw==16) begin
            state <= IDLE;
        end else begin
            cur_we <= 1'b1;
            cur_addr <= output_addr;
            rw <= rw + 1;
            state <= WRITE;
            t <= t + 1;
        end
    end
    endcase
end
endmodule
