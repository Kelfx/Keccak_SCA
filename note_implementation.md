# Keccak Implementation Summary 

keccak specifications summary with pseudo-code: https://keccak.team/keccak_specs_summary.html

Keccak implementation: keccal.vhd from https://zenodo.org/records/14891518

Open-source compiler for the implementation (and VHDL files in general): http://ghdl.free.fr/

# 0. High-Level Overview of the Design

This VHDL module implements the Keccak-f[1600] permutation, used in:

- SHA-3
- SHAKE (used in PQC like ML-KEM / ML-DSA)

### Key architectural features:

- State size: 1600 bits → 5 × 5 × 64-bit lanes ( 5 x 5 lanes of 64 bits )
- Architecture type: iterative (1 round per clock cycle)
- Rounds: 24
  
# 1. Internal State Representation

    type k_state is array(0 to 4, 0 to 4) of std_logic_vector(63 downto 0);
    
    signal s, reg_s: k_state;

### Meaning:

- `reg_s` : registered state (flip-flops)
  
    - this is the physical state stored in hardware

    - this is where power leakage occurs

- s : next-state (combinational logic output)

### State update model

Each clock cycle:

> reg_s → combinational logic → s → reg_s

This is a classic synchronous register-transfer structure

# 2. Round Structure (Combinational Datapath)

The round is split into **three** clearly defined stages:

- theta_out
- rho_pi_out
- chi_iota_out

### Dataflow:

    reg_s
      ↓
    theta_out
      ↓
    rho_pi_out
      ↓
    chi_iota_out
      ↓
      s
      ↓ (clock edge)
     reg_s

# 3. Theta Step (Column Mixing)

`c(x) <= reg_s(x,0) xor ... xor reg_s(x,4);` ( XOR of the columns )

`d(x) <= c(x-1) xor (c(x+1) rol 1);`

`theta_out(x,y) <= reg_s(x,y) xor d(x);`

### Function:

- Computes parity of each column (c)
- Mixes neighboring columns (d)
- Applies correction to each lane

### Properties:

- Linear operation (XOR + rotation)
- Strong diffusion across columns

### Relevant for SCA:

- Leakage is spread across many bits
- Hard to exploit directly (low signal-to-noise ratio (SNR))

# 4. Rho and Pi Steps (Permutation)

`rho_pi_out(...) <= theta_out(...) rol constant;`

### Function:

`ρ (rho)`: rotates each lane by a fixed offset

`π (pi)`: permutes lane positions

### Properties:

- Purely linear
- No mixing of values (only relocation)

### Relevant for SCA:

- Does not create new exploitable leakage
- Only redistributes existing data

# 5. Chi + Iota Step (Non-linear)

`chi_iota_out(x,y) <= rho_pi_out(x,y) xor 
                     (not rho_pi_out((x+1) mod 5,y) and rho_pi_out((x+2) mod 5,y));`

### Special case:

`chi_iota_out(0,0) <= ... xor RC(current_round);`

### Function:

> $\chi$ (chi): **non-linear** substitution layer
> $\iota$ (iota): adds round constant

### Important observation:

This is the only non-linear operation in Keccak.

The key term `(~A & B)` introduces:

> AND gate -> non-linear dependency

> data-dependent switching activity -> strong leakage source

## Local dependency

Each output depends only on:

> A[x,y], A[x+1,y], A[x+2,y]

(Important for ideas of *divide & conquer* and *localized attacks*)

# 6. State Update Logic

    s(x,y) <=
        reg_s(x,y) xor msg          when absorbing
        chi_iota_out(x,y)           when computing_round
        reg_s(x,y)                  otherwise

This is a multiplexer controlled by:

- absorbing_msg
- computing_round

# 7. Control Flow (Implicit FSM)

Instead of a single FSM, the design uses control signals:

## A. Absorbing Phase

`absorbing_msg = '1'`

When you are uploading the input (msg)

### Behavior:

`reg_s <= reg_s xor msg`

- Input message is XORed into the state
- Corresponds to Keccak "absorbing"

## B. Round Computation

`computing_round = '1'`

### Behavior:

`reg_s <= chi_iota_out`

Executes one round per clock

### Controlled by:

> current_round: 0 → 23

## C. Squeezing Phase

`reading_hash = '1'`

### Behavior:

`m_axis_tdata <= reg_s(...)`

Outputs hash lanes *sequentially*

# 8. Round Counter

> current_round: natural range 0 to 23;

### Updated in:

`proc_round`

### Logic:

- Starts when the absorbing phase ends
- Increments each cycle
- Stops after round 23

# 9. Transaction Control (Lane Sequencing)

> current_transaction: std_logic_vector(20 downto 0);

### Function:

- Acts like a shift register
- Selects which lane is:
  - absorbed
  - output

# 10. Output Logic

`m_axis_tdata <= reg_s(i mod 5, i / 5);`

### Behavior:

- Outputs one 64-bit lane at a time
- Controlled by current_transaction

# 11. Timing and Hardware Behavior

At each rising clock edge:

`reg_s ← s`

### Important:

> theta_out, rho_pi_out, chi_iota_out are **combinational**

*Only reg_s is stored*

## Leakage implication

Power consumption occurs when:

`reg_s <= chi_iota_out`

because:

- flip-flops switch
- transitions depend on data

# 12. Precise Leakage Points

### Primary leakage:

`reg_s <= chi_iota_out`

during:

`computing_round = '1'`

### Fine-grained leakage:

Inside:

`(~rho_pi_out(...) & rho_pi_out(...))`

but physically observable only when stored in `reg_s`

# 13. Clean Architectural Decomposition

### Level 1 (macro)

- Absorbing
- Round computation
- Output

### Level 2 (round)

- `θ` (theta) (linear diffusion)
- `ρ + π` (rho + pi) (permutation)
- `χ + ι` (chi + iota) (nonlinear core)

### Level 3 (micro)

single Boolean operation:
`(~A & B)`

# 14. Summary

## 1. Iterative architecture

One round per cycle

## 2. Registered state

`reg_s` is the only storage -> main leakage source

## 3. Clear and separated combinational stages

- It's easy to isolate `χ` (chi), the target attack.
- The locality of `χ` (chi) enables lane-wise / row-wise attacks

## 4. Control signals exposed

`computing_round`, `current_round` -> perfect for trace alignment
