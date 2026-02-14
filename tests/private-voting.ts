import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { PublicKey } from "@solana/web3.js";
import { PrivateVoting } from "../target/types/private_voting";
import { randomBytes, createHash } from "crypto";
import nacl from "tweetnacl";
import {
  awaitComputationFinalization,
  getArciumEnv,
  getCompDefAccOffset,
  getArciumAccountBaseSeed,
  getArciumProgramId,
  uploadCircuit,
  RescueCipher,
  deserializeLE,
  getMXEAccAddress,
  getMempoolAccAddress,
  getCompDefAccAddress,
  getExecutingPoolAccAddress,
  x25519,
  getComputationAccAddress,
  getMXEPublicKey,
  getClusterAccAddress,
  getLookupTableAddress,
  getArciumProgram,
} from "@arcium-hq/client";
import * as fs from "fs";
import * as os from "os";
import { expect } from "chai";

const ENCRYPTION_KEY_MESSAGE = "arcvote-encryption-key-v1";

function deriveEncryptionKey(
  wallet: anchor.web3.Keypair,
  message: string
): { privateKey: Uint8Array; publicKey: Uint8Array } {
  const messageBytes = new TextEncoder().encode(message);
  const signature = nacl.sign.detached(messageBytes, wallet.secretKey);
  const privateKey = new Uint8Array(
    createHash("sha256").update(signature).digest()
  );
  const publicKey = x25519.getPublicKey(privateKey);
  return { privateKey, publicKey };
}

function readKpJson(path: string): anchor.web3.Keypair {
  const file = fs.readFileSync(path);
  return anchor.web3.Keypair.fromSecretKey(
    new Uint8Array(JSON.parse(file.toString()))
  );
}

async function getMXEPublicKeyWithRetry(
  provider: anchor.AnchorProvider,
  programId: PublicKey,
  maxRetries: number = 20,
  retryDelayMs: number = 500
): Promise<Uint8Array> {
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      const key = await getMXEPublicKey(provider, programId);
      if (key) return key;
    } catch (error) {
      console.log(`Attempt ${attempt} failed to get MXE public key:`, error);
    }
    if (attempt < maxRetries) {
      await new Promise((r) => setTimeout(r, retryDelayMs));
    }
  }
  throw new Error(`Failed to get MXE public key after ${maxRetries} attempts`);
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

describe("ArcVote — Private Quadratic Voting", () => {
  anchor.setProvider(anchor.AnchorProvider.env());
  const program = anchor.workspace.PrivateVoting as Program<PrivateVoting>;
  const provider = anchor.getProvider() as anchor.AnchorProvider;

  type Event = anchor.IdlEvents<(typeof program)["idl"]>;
  const awaitEvent = async <E extends keyof Event>(
    eventName: E
  ): Promise<Event[E]> => {
    let listenerId: number;
    const event = await new Promise<Event[E]>((res) => {
      listenerId = program.addEventListener(eventName, (event) => {
        res(event);
      });
    });
    await program.removeEventListener(listenerId);
    return event;
  };

  const arciumEnv = getArciumEnv();
  const clusterAccount = getClusterAccAddress(arciumEnv.arciumClusterOffset);

  it("full quadratic voting lifecycle: create, allocate credits, threshold reveal", async () => {
    const PROPOSAL_ID = 1;
    const VOICE_CREDITS = 100;
    const QUORUM = 2;
    const owner = readKpJson(`${os.homedir()}/.config/solana/id.json`);

    const mxePublicKey = await getMXEPublicKeyWithRetry(
      provider,
      program.programId
    );
    console.log("MXE x25519 pubkey:", mxePublicKey);

    // ---- Initialize computation definitions ----
    console.log("\n=== Initializing computation definitions ===");
    await initCompDef(program, provider, owner, "init_tallies", "initTalliesCompDef");
    await initCompDef(program, provider, owner, "cast_vote", "initVoteCompDef");
    await initCompDef(program, provider, owner, "reveal_results", "initRevealCompDef");
    console.log("All comp defs initialized.\n");

    // ---- Create voter keypairs and airdrop SOL ----
    const voters = [
      anchor.web3.Keypair.generate(),
      anchor.web3.Keypair.generate(),
      anchor.web3.Keypair.generate(),
    ];

    for (const voter of voters) {
      const sig = await provider.connection.requestAirdrop(
        voter.publicKey,
        2 * anchor.web3.LAMPORTS_PER_SOL
      );
      await provider.connection.confirmTransaction(sig, "confirmed");
    }
    console.log("Airdropped SOL to 3 voters.\n");

    // ---- Create proposal ----
    console.log("=== Creating proposal (100 voice credits, quorum=2) ===");
    const proposalNonce = randomBytes(16);
    const proposalComputationOffset = new anchor.BN(randomBytes(8), "hex");

    const slot = await provider.connection.getSlot("confirmed");
    const blockTime = await provider.connection.getBlockTime(slot);
    const deadline = new anchor.BN(
      (blockTime || Math.floor(Date.now() / 1000)) + 60
    );

    const createSig = await program.methods
      .createProposal(
        proposalComputationOffset,
        PROPOSAL_ID,
        "Best L1 blockchain?",
        ["Solana", "Ethereum", "Avalanche", "Sui"],
        4,
        deadline,
        new anchor.BN(VOICE_CREDITS),
        QUORUM,
        new anchor.BN(deserializeLE(proposalNonce).toString())
      )
      .accountsPartial({
        computationAccount: getComputationAccAddress(
          arciumEnv.arciumClusterOffset,
          proposalComputationOffset
        ),
        clusterAccount,
        mxeAccount: getMXEAccAddress(program.programId),
        mempoolAccount: getMempoolAccAddress(arciumEnv.arciumClusterOffset),
        executingPool: getExecutingPoolAccAddress(arciumEnv.arciumClusterOffset),
        compDefAccount: getCompDefAccAddress(
          program.programId,
          Buffer.from(getCompDefAccOffset("init_tallies")).readUInt32LE()
        ),
      })
      .rpc({ skipPreflight: true, commitment: "confirmed" });

    console.log("Proposal created:", createSig);

    await awaitComputationFinalization(
      provider,
      proposalComputationOffset,
      program.programId,
      "confirmed"
    );
    console.log("Init tallies finalized.\n");

    // ---- Derive proposal PDA ----
    const [proposalPDA] = PublicKey.findProgramAddressSync(
      [
        Buffer.from("proposal"),
        owner.publicKey.toBuffer(),
        Buffer.from(new Uint8Array(new Int32Array([PROPOSAL_ID]).buffer)),
      ],
      program.programId
    );

    // ---- Cast quadratic votes ----
    // Three different strategies to demonstrate QV mechanics:
    //
    //   Voter 0: Spread  — v0=7, v1=3, v2=1, v3=0  (cost: 49+9+1+0 = 59)
    //   Voter 1: Split   — v0=5, v1=5, v2=0, v3=0  (cost: 25+25+0+0 = 50)
    //   Voter 2: All-in  — v0=0, v1=0, v2=10, v3=0 (cost: 0+0+100+0 = 100)
    //
    // Expected tallies:
    //   option_0 = 7+5+0 = 12   (winner)
    //   option_1 = 3+5+0 = 8
    //   option_2 = 1+0+10 = 11
    //   option_3 = 0
    //   total    = 31

    const allocations: [number, number, number, number][] = [
      [7, 3, 1, 0],   // Voter 0: spread across 3 options
      [5, 5, 0, 0],   // Voter 1: split between 2 options
      [0, 0, 10, 0],  // Voter 2: all-in on option 2
    ];

    console.log("=== Casting quadratic votes ===");
    for (let i = 0; i < voters.length; i++) {
      const voter = voters[i];
      const [v0, v1, v2, v3] = allocations[i];
      const cost = v0 * v0 + v1 * v1 + v2 * v2 + v3 * v3;

      console.log(
        `  Voter ${i}: [${v0}, ${v1}, ${v2}, ${v3}] ` +
        `(cost=${cost}/${VOICE_CREDITS}, effective=${v0 + v1 + v2 + v3} votes)`
      );

      const { privateKey, publicKey } = deriveEncryptionKey(
        voter,
        ENCRYPTION_KEY_MESSAGE
      );
      const sharedSecret = x25519.getSharedSecret(privateKey, mxePublicKey);
      const cipher = new RescueCipher(sharedSecret);

      const nonce = randomBytes(16);
      const ciphertexts = cipher.encrypt(
        [BigInt(v0), BigInt(v1), BigInt(v2), BigInt(v3)],
        nonce
      );

      const voteComputationOffset = new anchor.BN(randomBytes(8), "hex");
      const eventPromise = awaitEvent("voteCastEvent");

      const voteSig = await program.methods
        .castVote(
          voteComputationOffset,
          PROPOSAL_ID,
          Array.from(ciphertexts[0]),
          Array.from(ciphertexts[1]),
          Array.from(ciphertexts[2]),
          Array.from(ciphertexts[3]),
          Array.from(publicKey),
          new anchor.BN(deserializeLE(nonce).toString())
        )
        .accountsPartial({
          payer: voter.publicKey,
          computationAccount: getComputationAccAddress(
            arciumEnv.arciumClusterOffset,
            voteComputationOffset
          ),
          clusterAccount,
          mxeAccount: getMXEAccAddress(program.programId),
          mempoolAccount: getMempoolAccAddress(arciumEnv.arciumClusterOffset),
          executingPool: getExecutingPoolAccAddress(arciumEnv.arciumClusterOffset),
          compDefAccount: getCompDefAccAddress(
            program.programId,
            Buffer.from(getCompDefAccOffset("cast_vote")).readUInt32LE()
          ),
          authority: owner.publicKey,
          proposalAcc: proposalPDA,
        })
        .signers([voter])
        .rpc({ skipPreflight: true, commitment: "confirmed" });

      console.log(`  Vote ${i} queued:`, voteSig);

      await awaitComputationFinalization(
        provider,
        voteComputationOffset,
        program.programId,
        "confirmed"
      );

      const event = await eventPromise;
      console.log(
        `  Vote cast event: proposal=${event.proposalId}, count=${event.voterCount}`
      );
    }
    console.log("");

    // ---- Wait for deadline ----
    console.log("=== Waiting for voting deadline ===");
    while (true) {
      const currentSlot = await provider.connection.getSlot("confirmed");
      const currentTime = await provider.connection.getBlockTime(currentSlot);
      if (currentTime && currentTime >= deadline.toNumber()) break;
      await sleep(1000);
    }
    console.log("Deadline passed.\n");

    // ---- Reveal results (threshold check: voter_count >= quorum) ----
    console.log("=== Revealing results (quorum met: 3 >= 2) ===");
    const revealComputationOffset = new anchor.BN(randomBytes(8), "hex");
    const revealEventPromise = awaitEvent("resultsRevealedEvent");

    const revealSig = await program.methods
      .revealResults(revealComputationOffset, PROPOSAL_ID)
      .accountsPartial({
        computationAccount: getComputationAccAddress(
          arciumEnv.arciumClusterOffset,
          revealComputationOffset
        ),
        clusterAccount,
        mxeAccount: getMXEAccAddress(program.programId),
        mempoolAccount: getMempoolAccAddress(arciumEnv.arciumClusterOffset),
        executingPool: getExecutingPoolAccAddress(arciumEnv.arciumClusterOffset),
        compDefAccount: getCompDefAccAddress(
          program.programId,
          Buffer.from(getCompDefAccOffset("reveal_results")).readUInt32LE()
        ),
        proposalAcc: proposalPDA,
      })
      .rpc({ skipPreflight: true, commitment: "confirmed" });

    console.log("Reveal queued:", revealSig);

    await awaitComputationFinalization(
      provider,
      revealComputationOffset,
      program.programId,
      "confirmed"
    );

    const revealEvent = await revealEventPromise;
    console.log("\n=== RESULTS (quadratic-weighted) ===");
    console.log(`  Solana:    ${revealEvent.option_0} effective votes`);
    console.log(`  Ethereum:  ${revealEvent.option_1} effective votes`);
    console.log(`  Avalanche: ${revealEvent.option_2} effective votes`);
    console.log(`  Sui:       ${revealEvent.option_3} effective votes`);
    console.log(`  Total:     ${revealEvent.totalVotes} effective votes`);
    console.log(`  Winner:    option ${revealEvent.winner}`);

    // Verify quadratic tallies:
    //   option_0 = 7+5+0 = 12  (Solana wins)
    //   option_1 = 3+5+0 = 8
    //   option_2 = 1+0+10 = 11 (all-in only gets 10, not enough to beat spread)
    //   option_3 = 0
    //   total = 31
    expect(revealEvent.option_0.toString()).to.equal("12");
    expect(revealEvent.option_1.toString()).to.equal("8");
    expect(revealEvent.option_2.toString()).to.equal("11");
    expect(revealEvent.option_3.toString()).to.equal("0");
    expect(revealEvent.totalVotes.toString()).to.equal("31");
    expect(revealEvent.winner).to.equal(0); // Solana wins

    // Verify proposal state
    const proposalAcc = await program.account.proposalAccount.fetch(proposalPDA);
    expect(proposalAcc.isFinalized).to.equal(true);
    expect(proposalAcc.voterCount).to.equal(3);
    expect(proposalAcc.voiceCredits.toString()).to.equal("100");
    expect(proposalAcc.quorum).to.equal(2);

    console.log("\n=== QV demonstration ===");
    console.log("Voter 2 went all-in on Avalanche (10 effective votes, cost=100)");
    console.log("But Voters 0+1 spread their credits more efficiently:");
    console.log("  Combined Solana support: 12 votes for only 49+25=74 credits");
    console.log("  This is the power of QV — concentration has diminishing returns.");
    console.log("\nAll assertions passed!");
  });
});

// ---- Helper: initialize a computation definition + upload circuit ----
async function initCompDef(
  program: Program<PrivateVoting>,
  provider: anchor.AnchorProvider,
  owner: anchor.web3.Keypair,
  circuitName: string,
  methodName: string
): Promise<string> {
  const baseSeed = getArciumAccountBaseSeed("ComputationDefinitionAccount");
  const offset = getCompDefAccOffset(circuitName);

  const compDefPDA = PublicKey.findProgramAddressSync(
    [baseSeed, program.programId.toBuffer(), offset],
    getArciumProgramId()
  )[0];

  console.log(`  ${circuitName} comp def PDA:`, compDefPDA.toBase58());

  const arciumProgram = getArciumProgram(provider);
  const mxeAccount = getMXEAccAddress(program.programId);
  const mxeAcc = await arciumProgram.account.mxeAccount.fetch(mxeAccount);
  const lutAddress = getLookupTableAddress(
    program.programId,
    mxeAcc.lutOffsetSlot
  );

  const sig = await (program.methods as any)[methodName]()
    .accounts({
      compDefAccount: compDefPDA,
      payer: owner.publicKey,
      mxeAccount,
      addressLookupTable: lutAddress,
    })
    .signers([owner])
    .rpc({ preflightCommitment: "confirmed", commitment: "confirmed" });

  console.log(`  ${circuitName} comp def tx:`, sig);

  const rawCircuit = fs.readFileSync(`build/${circuitName}.arcis`);
  await uploadCircuit(
    provider,
    circuitName,
    program.programId,
    rawCircuit,
    true
  );

  console.log(`  ${circuitName} circuit uploaded.`);
  return sig;
}
