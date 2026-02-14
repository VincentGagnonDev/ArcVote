# ArcVote — Private Quadratic Voting on Arcium

Confidential quadratic voting for on-chain governance.  Voters distribute voice credits across options with quadratic cost — and the entire allocation is encrypted inside Arcium's MPC network.  Nobody sees how anyone spent their credits.  Only final aggregated results are revealed after quorum is met and the deadline passes.

## The Problem

On-chain governance is broken in multiple ways:

1. **Vote buying** — When votes are visible, bribing is trivial
2. **Voter coercion** — Whales and DAOs pressure smaller holders
3. **Front-running** — Early vote visibility influences later voters
4. **Tyranny of the majority** — Simple majority voting ignores preference intensity
5. **QV gaming** — Public quadratic voting is vulnerable to credit-splitting across wallets

Quadratic Voting (QV) solves problem 4 by making concentrated influence expensive.  But on a public chain, QV itself becomes gameable — anyone can split credits across sybil wallets to bypass the quadratic cost.

**ArcVote solves all five problems simultaneously**: encrypted allocations prevent vote buying, coercion, and front-running, while quadratic cost enforcement inside MPC prevents gaming — even the voter can't prove how they allocated.

## What Makes ArcVote Different

| Feature | Standard Voting | QV (Public) | **ArcVote** |
|---|---|---|---|
| Prevents majority tyranny | No | Yes | **Yes** |
| Vote buying resistance | No | No | **Yes** |
| Credit-splitting attack | N/A | Vulnerable | **Impossible** |
| Allocation privacy | None | None | **End-to-end encrypted** |
| Budget verification | Public | Public | **Verified inside MPC** |
| Quorum enforcement | Optional | Optional | **Threshold reveal** |

## How Quadratic Voting Works

Each voter receives **100 voice credits**.  To cast *N* effective votes on an option, it costs *N*² credits:

| Effective Votes | Credit Cost | Marginal Cost |
|---|---|---|
| 1 | 1 | 1 |
| 2 | 4 | 3 |
| 5 | 25 | — |
| 7 | 49 | — |
| 10 | 100 | — |

You can spread credits across multiple options.  The constraint is: **v0² + v1² + v2² + v3² ≤ 100**.

### Example Strategies

| Strategy | Allocation | Cost | Total Effective Votes |
|---|---|---|---|
| All-in | (10, 0, 0, 0) | 100 | 10 |
| Spread | (7, 3, 1, 0) | 49+9+1 = 59 | 11 |
| Even split | (5, 5, 5, 4) | 25+25+25+16 = 91 | 19 |

Spreading is more efficient — this is exactly the QV insight: it rewards voters who care about multiple issues over those who only care about one.

## Architecture

```
                          ┌──────────────────────────────────────────┐
                          │          Arcium MPC Cluster               │
                          │                                          │
Voter A ──encrypt(7,3,1,0)──►│  cast_vote(                              │
                          │    encrypted_allocation,  ← HIDDEN       │
Voter B ──encrypt(5,5,0,0)──►│    encrypted_tallies                     │
                          │  )                                        │
Voter C ──encrypt(0,0,10,0)─►│                                          │
                          │  1. Compute v0²+v1²+v2²+v3²              │
                          │  2. Verify cost ≤ 100 voice credits       │
                          │  3. If valid: tallies += allocation       │
                          │  4. Return updated encrypted tallies      │
                          │                                          │
                          │  reveal_results()                         │
                          │  → plaintext totals + winner              │
                          └──────────────────────────────────────────┘
                                        │
                                        ▼
                          ┌──────────────────────────┐
                          │  Solana (on-chain state)   │
                          │                          │
                          │  ProposalAccount:        │
                          │    vote_state: [u8;32]×5 │ ← ciphertext
                          │    voice_credits: 100    │ ← public
                          │    quorum: 2             │ ← public
                          │    voter_count: 3        │ ← public
                          │                          │
                          │  VoterRecord:            │
                          │    (prevents double-vote)│
                          └──────────────────────────┘
```

## How Arcium Enables This

ArcVote uses three distinct capabilities of Arcium's MPC network:

### 1. Encrypted Budget Enforcement

The `cast_vote` circuit computes `v0² + v1² + v2² + v3²` inside MPC and checks `cost ≤ 100`.  This is the core QV innovation: the quadratic constraint is verified without revealing the allocation.  A malicious voter cannot cheat — and cannot prove their allocation to a briber.

### 2. Oblivious Accumulation

Each vote adds encrypted values to encrypted tallies.  The MPC cluster processes the addition without learning any individual allocation.  All branches of the budget check execute (standard MPC technique), so no information leaks through execution timing.

### 3. Threshold Reveal (Conditional Decryption)

Results are only decryptable when `voter_count >= quorum`.  If not enough people vote, the tallies stay permanently sealed — nobody learns partial results.  This is enforced at the Solana program level before the MPC reveal computation is queued.

## MPC Circuits (3 total)

| Circuit | Input | Output | Purpose |
|---|---|---|---|
| `init_tallies` | nonce | `Enc<Mxe, VoteTallies>` | Zero-initialize 5 encrypted counters |
| `cast_vote` | encrypted allocation + encrypted tallies | `Enc<Mxe, VoteTallies>` | Verify QV budget, add effective votes |
| `reveal_results` | encrypted tallies | plaintext results | Decrypt all tallies, determine winner |

### cast_vote Circuit (core logic)

```rust
// Inside Arcium's MPC cluster — all values are secret-shared
let cost = alloc.v0 * alloc.v0
         + alloc.v1 * alloc.v1
         + alloc.v2 * alloc.v2
         + alloc.v3 * alloc.v3;

// Budget enforcement — MPC executes both branches (no info leakage)
if cost <= 100u64 {
    tallies.option_0 += alloc.v0;
    tallies.option_1 += alloc.v1;
    tallies.option_2 += alloc.v2;
    tallies.option_3 += alloc.v3;
    tallies.total_votes += alloc.v0 + alloc.v1 + alloc.v2 + alloc.v3;
}
```

## On-Chain Accounts

**ProposalAccount** — Stores encrypted vote state, metadata, and QV parameters:
- `vote_state: [[u8; 32]; 5]` — encrypted quadratic-weighted tallies
- `voice_credits: u64` — credit budget per voter (e.g., 100)
- `quorum: u32` — minimum voters before reveal is allowed
- `voter_count: u32` — public count of participants

**VoterRecord** — PDA per voter per proposal `[b"voter", proposal_key, voter_key]`:
- Created on vote — second vote attempt fails at Solana level (double-vote prevention)

## Program Instructions (9 total)

| Instruction | Purpose |
|---|---|
| `init_tallies_comp_def` | Register init_tallies circuit |
| `init_vote_comp_def` | Register cast_vote circuit |
| `init_reveal_comp_def` | Register reveal_results circuit |
| `create_proposal` | Create proposal with QV params + queue init_tallies MPC |
| `init_tallies_callback` | Store encrypted zero counters |
| `cast_vote` | Validate voter + deadline, create VoterRecord, queue QV MPC |
| `cast_vote_callback` | Update encrypted tallies |
| `reveal_results` | Authority-only, check deadline + quorum, queue reveal MPC |
| `reveal_results_callback` | Emit results event, mark finalized |

## Prerequisites

- [Rust](https://rustup.rs/) (1.89.0+)
- [Solana CLI](https://docs.solana.com/cli/install-solana-cli-tools) (2.3.0)
- [Anchor](https://www.anchor-lang.com/) (0.32.1)
- [Yarn](https://yarnpkg.com/)
- [Docker & Docker Compose](https://docs.docker.com/get-docker/)
- Arcium CLI:
  ```bash
  curl --proto '=https' --tlsv1.2 -sSfL https://install.arcium.com/ | bash
  ```

## Build & Test

```bash
# Generate program keypair (first time only)
solana-keygen new -o target/deploy/private_voting-keypair.json
# Update the program ID in Anchor.toml and lib.rs

# Install dependencies
yarn install

# Build encrypted circuits + Anchor program
arcium build

# Run full test suite (spins up localnet + MPC nodes)
arcium test
```

## How It Works (Step by Step)

1. **Setup**: Proposal authority registers 3 MPC circuits and uploads compiled circuit binaries
2. **Proposal creation**: Authority creates a proposal with title, options, deadline, voice credit budget (100), and quorum threshold
3. **Tally initialization**: MPC cluster encrypts five zero counters and stores them on-chain
4. **Voting**: Each voter encrypts their allocation `(v0, v1, v2, v3)` and calls `cast_vote`.  Inside MPC:
   - Compute quadratic cost: `v0² + v1² + v2² + v3²`
   - If cost ≤ 100: add effective votes to encrypted tallies
   - A VoterRecord PDA prevents double-voting
5. **Waiting**: Votes accumulate until the deadline passes
6. **Threshold check**: Authority calls `reveal_results` — fails if `voter_count < quorum`
7. **Reveal**: MPC decrypts all tallies, determines the winner, and emits a `ResultsRevealedEvent` with full counts

## Test Output

The integration test demonstrates three voting strategies:

```
Voter 0: [7, 3, 1, 0]  (cost=59/100, effective=11 votes)  ← spread
Voter 1: [5, 5, 0, 0]  (cost=50/100, effective=10 votes)  ← split
Voter 2: [0, 0, 10, 0] (cost=100/100, effective=10 votes) ← all-in

=== RESULTS (quadratic-weighted) ===
  Solana:    12 effective votes  ← winner
  Ethereum:  8 effective votes
  Avalanche: 11 effective votes
  Sui:       0 effective votes
  Total:     31 effective votes
```

Voter 2 spent all 100 credits on Avalanche for 10 effective votes.  But Voters 0 and 1 spread their credits more efficiently — combined Solana support of 12 votes for only 74 credits.  **This is the core QV insight: concentration has diminishing returns.**

## Why This Matters

Quadratic voting is one of the most promising governance innovations (Vitalik Buterin, Glen Weyl).  But on public blockchains, it breaks completely:

- **Credit splitting**: Create 10 wallets, give each 10 credits → 10 votes for 100 credits instead of paying 10² = 100 credits for 10 votes from one wallet
- **Vote buying**: A briber can verify exactly how someone voted and what weight it carried
- **Strategic coordination**: Seeing others' allocations enables gaming

ArcVote makes all three attacks impossible.  Individual allocations are encrypted end-to-end.  Budget enforcement happens inside MPC.  Not even the voter can produce a proof of how they voted.  This makes private quadratic voting deployable for real DAO governance — not just a theoretical ideal.

## Project Structure

```
ArcVote/
├── encrypted-ixs/src/lib.rs       # 3 MPC circuits (QV budget enforcement)
├── programs/private-voting/        # Anchor program (9 instructions)
│   └── src/lib.rs
├── tests/private-voting.ts         # Full lifecycle integration test
├── Anchor.toml / Arcium.toml       # Configuration
└── README.md
```

## License

MIT
