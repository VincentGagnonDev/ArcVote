# ArcVote — Private DAO Governance on Arcium

Confidential multi-option voting for on-chain governance. Votes are encrypted, tallied inside Arcium's MPC network, and only final results are published to Solana — individual ballots are never revealed.

## Why Private Voting Matters

Public on-chain voting creates serious problems for governance:

- **Vote buying** — Observable votes enable direct bribery
- **Voter coercion** — DAOs, whales, or external actors pressure voters
- **Front-running** — Early vote visibility influences later voters
- **Strategic voting** — Voters game outcomes instead of voting honestly

ArcVote eliminates these issues. Each vote is encrypted client-side, processed by Arcium's MPC cluster, and only the aggregated result is made public after the voting period ends.

## How Arcium Enables This

```
Voter                  Solana Program              Arcium MPC Cluster
  │                         │                              │
  │  encrypt(choice, key)   │                              │
  │────────────────────────>│                              │
  │                         │  queue_computation(          │
  │                         │    encrypted_vote,           │
  │                         │    encrypted_tallies)        │
  │                         │─────────────────────────────>│
  │                         │                              │
  │                         │              cast_vote(      │
  │                         │                vote, tallies)│
  │                         │              [MPC execution] │
  │                         │                              │
  │                         │  callback(updated_tallies)   │
  │                         │<─────────────────────────────│
  │                         │                              │
  │                         │  [After deadline]            │
  │                         │  reveal_results(tallies)     │
  │                         │─────────────────────────────>│
  │                         │                              │
  │                         │  callback(plaintext_results) │
  │                         │<─────────────────────────────│
  │  emit ResultsRevealed   │                              │
  │<────────────────────────│                              │
```

1. **Client-side encryption**: Voter's choice (0-3) is encrypted using x25519 key exchange with the MXE, then Rescue cipher encryption
2. **Encrypted on-chain state**: Vote tallies are stored as `[[u8; 32]; 5]` ciphertexts — only the MPC cluster can decrypt them
3. **MPC computation**: `cast_vote` runs inside the MPC cluster, incrementing the correct counter without revealing which one
4. **Verified reveal**: After the deadline, `reveal_results` decrypts all tallies and returns plaintext counts with correctness proofs

## Features

| Feature | Description |
|---|---|
| **Multi-option voting** | Up to 4 candidates/choices per proposal (not just yes/no) |
| **Double-vote prevention** | VoterRecord PDA — attempting to vote twice fails at the Solana level |
| **Time-gated periods** | Proposals have deadlines enforced by `Clock` sysvar |
| **Full tally reveal** | All option counts + winner index published (not just a boolean) |
| **Authority model** | Only the proposal creator can trigger result reveal |

## Project Structure

```
ArcVote/
├── encrypted-ixs/src/lib.rs    # 3 MPC circuits (init_tallies, cast_vote, reveal_results)
├── programs/private-voting/     # Anchor program (9 instructions)
│   └── src/lib.rs
├── tests/private-voting.ts      # Integration test suite
├── Anchor.toml / Arcium.toml    # Configuration
└── README.md
```

## Encrypted Instructions

Three circuits compiled for Arcium's MPC cluster:

### `init_tallies`
Initializes 5 encrypted counters (option_0 through option_3 + total_votes) to zero.

### `cast_vote`
Takes an encrypted voter choice and the encrypted tallies. Increments the chosen option's counter and total_votes. All branches execute in MPC — no information leakage about which option was chosen.

### `reveal_results`
Decrypts all tallies, determines the winner, and returns plaintext results. Every field is `.reveal()`'d so the callback receives actual counts.

## On-Chain Program

### Accounts

**ProposalAccount** — Stores encrypted vote state, metadata, and deadline:
- `vote_state: [[u8; 32]; 5]` — encrypted tallies
- `title`, `options`, `num_options` — proposal metadata
- `deadline: i64` — voting cutoff timestamp
- `is_finalized: bool` — set after reveal
- `voter_count: u32` — number of votes cast

**VoterRecord** — PDA seeded with `[b"voter", proposal_key, voter_key]`. Created on first vote; attempting to create it again (double vote) fails.

### Instructions

| Instruction | Purpose |
|---|---|
| `init_tallies_comp_def` | Register init_tallies circuit |
| `init_vote_comp_def` | Register cast_vote circuit |
| `init_reveal_comp_def` | Register reveal_results circuit |
| `create_proposal` | Create proposal + queue init_tallies MPC |
| `init_tallies_callback` | Store encrypted zero counters |
| `cast_vote` | Validate voter, create VoterRecord, queue MPC |
| `cast_vote_callback` | Update encrypted tallies |
| `reveal_results` | Authority-only, check deadline, queue MPC |
| `reveal_results_callback` | Emit results event, mark finalized |

### Validation Checks

- `cast_vote`: `Clock < deadline` (voting period active)
- `cast_vote`: VoterRecord `init` fails if already exists (no double voting)
- `reveal_results`: `payer == proposal.authority` (only creator reveals)
- `reveal_results`: `Clock >= deadline` (voting period ended)
- `reveal_results`: `!is_finalized` (single reveal only)

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
# Update the program ID in Anchor.toml and lib.rs with the generated pubkey

# Install dependencies
yarn install

# Build encrypted circuits + Anchor program
arcium build

# Run full test suite (spins up localnet + MPC nodes)
arcium test
```

## How It Works (Step by Step)

1. **Proposal creator** calls `create_proposal` with a title, up to 4 option labels, and a deadline
2. Arcium MPC initializes encrypted counters to zero via `init_tallies`
3. **Voters** encrypt their choice (0-3) client-side and call `cast_vote`
4. Each vote is processed inside the MPC cluster — only the updated encrypted tallies return to Solana
5. A VoterRecord PDA is created per voter, preventing double-voting at the protocol level
6. After the deadline passes, the **proposal authority** calls `reveal_results`
7. MPC decrypts all counters, determines the winner, and the callback emits a `ResultsRevealedEvent` with full tallies

## License

MIT
