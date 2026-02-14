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

describe("ArcVote — Private Multi-Option Voting", () => {
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

  it("full voting lifecycle: create, vote, reveal", async () => {
    const PROPOSAL_ID = 1;
    const owner = readKpJson(`${os.homedir()}/.config/solana/id.json`);

    // ---- Setup encryption ----
    const mxePublicKey = await getMXEPublicKeyWithRetry(
      provider,
      program.programId
    );
    console.log("MXE x25519 pubkey:", mxePublicKey);

    // ---- Initialize computation definitions ----
    console.log("Initializing comp defs...");
    await initCompDef(program, provider, owner, "init_tallies", "initTalliesCompDef");
    await initCompDef(program, provider, owner, "cast_vote", "initVoteCompDef");
    await initCompDef(program, provider, owner, "reveal_results", "initRevealCompDef");
    console.log("All comp defs initialized.");

    // ---- Create proposal ----
    const proposalNonce = randomBytes(16);
    const proposalComputationOffset = new anchor.BN(randomBytes(8), "hex");

    // Deadline: 30 seconds from now
    const slot = await provider.connection.getSlot("confirmed");
    const blockTime = await provider.connection.getBlockTime(slot);
    const deadline = new anchor.BN((blockTime || Math.floor(Date.now() / 1000)) + 30);

    console.log(`Creating proposal ${PROPOSAL_ID} with deadline ${deadline.toString()}...`);

    const createSig = await program.methods
      .createProposal(
        proposalComputationOffset,
        PROPOSAL_ID,
        "Best L1 blockchain?",
        ["Solana", "Ethereum", "Avalanche", "Sui"],
        4,
        deadline,
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

    const initFinalizeSig = await awaitComputationFinalization(
      provider,
      proposalComputationOffset,
      program.programId,
      "confirmed"
    );
    console.log("Init tallies finalized:", initFinalizeSig);

    // ---- Derive proposal PDA ----
    const [proposalPDA] = PublicKey.findProgramAddressSync(
      [
        Buffer.from("proposal"),
        owner.publicKey.toBuffer(),
        Buffer.from(new Uint8Array(new Int32Array([PROPOSAL_ID]).buffer)),
      ],
      program.programId
    );

    // ---- Cast votes from multiple voters ----
    // Generate 3 additional voter keypairs
    const voters = [
      anchor.web3.Keypair.generate(),
      anchor.web3.Keypair.generate(),
      anchor.web3.Keypair.generate(),
    ];
    const choices = [0, 0, 2]; // Two votes for Solana, one for Avalanche

    // Airdrop SOL to voters
    for (const voter of voters) {
      const airdropSig = await provider.connection.requestAirdrop(
        voter.publicKey,
        2 * anchor.web3.LAMPORTS_PER_SOL
      );
      await provider.connection.confirmTransaction(airdropSig, "confirmed");
    }
    console.log("Airdropped SOL to 3 voters.");

    // Cast each vote
    for (let i = 0; i < voters.length; i++) {
      const voter = voters[i];
      const choice = choices[i];

      const { privateKey, publicKey } = deriveEncryptionKey(
        voter,
        ENCRYPTION_KEY_MESSAGE
      );
      const sharedSecret = x25519.getSharedSecret(privateKey, mxePublicKey);
      const cipher = new RescueCipher(sharedSecret);

      const nonce = randomBytes(16);
      const ciphertext = cipher.encrypt([BigInt(choice)], nonce);

      const voteComputationOffset = new anchor.BN(randomBytes(8), "hex");

      const eventPromise = awaitEvent("voteCastEvent");

      console.log(`Voter ${i} casting vote for option ${choice}...`);

      const voteSig = await program.methods
        .castVote(
          voteComputationOffset,
          PROPOSAL_ID,
          Array.from(ciphertext[0]),
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
          executingPool: getExecutingPoolAccAddress(
            arciumEnv.arciumClusterOffset
          ),
          compDefAccount: getCompDefAccAddress(
            program.programId,
            Buffer.from(getCompDefAccOffset("cast_vote")).readUInt32LE()
          ),
          authority: owner.publicKey,
          proposalAcc: proposalPDA,
        })
        .signers([voter])
        .rpc({ skipPreflight: true, commitment: "confirmed" });

      console.log(`Vote ${i} queued:`, voteSig);

      const finalizeSig = await awaitComputationFinalization(
        provider,
        voteComputationOffset,
        program.programId,
        "confirmed"
      );
      console.log(`Vote ${i} finalized:`, finalizeSig);

      const event = await eventPromise;
      console.log(
        `Vote cast event: proposal=${event.proposalId}, count=${event.voterCount}`
      );
    }

    // ---- Wait for deadline to pass ----
    console.log("Waiting for voting deadline to pass...");
    while (true) {
      const currentSlot = await provider.connection.getSlot("confirmed");
      const currentTime = await provider.connection.getBlockTime(currentSlot);
      if (currentTime && currentTime >= deadline.toNumber()) break;
      await sleep(1000);
    }
    console.log("Deadline passed.");

    // ---- Reveal results ----
    const revealComputationOffset = new anchor.BN(randomBytes(8), "hex");
    const revealEventPromise = awaitEvent("resultsRevealedEvent");

    console.log("Revealing results...");

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

    const revealFinalizeSig = await awaitComputationFinalization(
      provider,
      revealComputationOffset,
      program.programId,
      "confirmed"
    );
    console.log("Reveal finalized:", revealFinalizeSig);

    const revealEvent = await revealEventPromise;
    console.log("=== RESULTS ===");
    console.log(`  Solana:    ${revealEvent.option_0} votes`);
    console.log(`  Ethereum:  ${revealEvent.option_1} votes`);
    console.log(`  Avalanche: ${revealEvent.option_2} votes`);
    console.log(`  Sui:       ${revealEvent.option_3} votes`);
    console.log(`  Total:     ${revealEvent.totalVotes} votes`);
    console.log(`  Winner:    option ${revealEvent.winner}`);

    // Verify: 2 votes for Solana (option 0), 1 for Avalanche (option 2)
    expect(revealEvent.option_0.toString()).to.equal("2");
    expect(revealEvent.option_1.toString()).to.equal("0");
    expect(revealEvent.option_2.toString()).to.equal("1");
    expect(revealEvent.option_3.toString()).to.equal("0");
    expect(revealEvent.totalVotes.toString()).to.equal("3");
    expect(revealEvent.winner).to.equal(0); // Solana wins

    // Verify proposal is finalized
    const proposalAcc = await program.account.proposalAccount.fetch(proposalPDA);
    expect(proposalAcc.isFinalized).to.equal(true);
    expect(proposalAcc.voterCount).to.equal(3);

    console.log("All assertions passed!");
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
