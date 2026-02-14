use anchor_lang::prelude::*;
use arcium_anchor::prelude::*;
use arcium_client::idl::arcium::types::CallbackAccount;

const COMP_DEF_OFFSET_INIT_TALLIES: u32 = comp_def_offset("init_tallies");
const COMP_DEF_OFFSET_CAST_VOTE: u32 = comp_def_offset("cast_vote");
const COMP_DEF_OFFSET_REVEAL_RESULTS: u32 = comp_def_offset("reveal_results");

declare_id!("11111111111111111111111111111111");

#[arcium_program]
pub mod private_voting {
    use super::*;

    // ================================================================
    // Computation Definition Initializers
    // ================================================================

    pub fn init_tallies_comp_def(ctx: Context<InitTalliesCompDef>) -> Result<()> {
        init_comp_def(ctx.accounts, None, None)?;
        Ok(())
    }

    pub fn init_vote_comp_def(ctx: Context<InitVoteCompDef>) -> Result<()> {
        init_comp_def(ctx.accounts, None, None)?;
        Ok(())
    }

    pub fn init_reveal_comp_def(ctx: Context<InitRevealCompDef>) -> Result<()> {
        init_comp_def(ctx.accounts, None, None)?;
        Ok(())
    }

    // ================================================================
    // Proposal Lifecycle
    // ================================================================

    /// Create a new proposal with up to 4 options, a voting deadline,
    /// a voice credit budget, and a quorum threshold.
    /// Queues an MPC computation to initialize encrypted tallies.
    pub fn create_proposal(
        ctx: Context<CreateProposal>,
        computation_offset: u64,
        id: u32,
        title: String,
        options: Vec<String>,
        num_options: u8,
        deadline: i64,
        voice_credits: u64,
        quorum: u32,
        nonce: u128,
    ) -> Result<()> {
        let proposal = &mut ctx.accounts.proposal_acc;
        proposal.bump = ctx.bumps.proposal_acc;
        proposal.id = id;
        proposal.authority = ctx.accounts.payer.key();
        proposal.nonce = nonce;
        proposal.title = title;
        proposal.options = options;
        proposal.num_options = num_options;
        proposal.deadline = deadline;
        proposal.voice_credits = voice_credits;
        proposal.quorum = quorum;
        proposal.is_finalized = false;
        proposal.voter_count = 0;
        proposal.vote_state = [[0; 32]; 5];

        let args = ArgBuilder::new().plaintext_u128(nonce).build();

        ctx.accounts.sign_pda_account.bump = ctx.bumps.sign_pda_account;

        queue_computation(
            ctx.accounts,
            computation_offset,
            args,
            vec![InitTalliesCallback::callback_ix(
                computation_offset,
                &ctx.accounts.mxe_account,
                &[CallbackAccount {
                    pubkey: ctx.accounts.proposal_acc.key(),
                    is_writable: true,
                }],
            )?],
            1,
            0,
        )?;

        Ok(())
    }

    #[arcium_callback(encrypted_ix = "init_tallies")]
    pub fn init_tallies_callback(
        ctx: Context<InitTalliesCallback>,
        output: SignedComputationOutputs<InitTalliesOutput>,
    ) -> Result<()> {
        let o = match output.verify_output(
            &ctx.accounts.cluster_account,
            &ctx.accounts.computation_account,
        ) {
            Ok(InitTalliesOutput { field_0 }) => field_0,
            Err(_) => return Err(ErrorCode::AbortedComputation.into()),
        };

        ctx.accounts.proposal_acc.vote_state = o.ciphertexts;
        ctx.accounts.proposal_acc.nonce = o.nonce;

        Ok(())
    }

    // ================================================================
    // Quadratic Voting
    // ================================================================

    /// Cast a quadratic vote.
    ///
    /// The voter encrypts their credit allocation (v0, v1, v2, v3) where
    /// each value is the number of effective votes for that option.
    /// The quadratic cost v0² + v1² + v2² + v3² is verified inside MPC
    /// against the 100 voice credit budget.  Nobody sees individual allocations.
    ///
    /// Creates a VoterRecord PDA to prevent double-voting.
    pub fn cast_vote(
        ctx: Context<CastVote>,
        computation_offset: u64,
        _id: u32,
        vote_v0: [u8; 32],
        vote_v1: [u8; 32],
        vote_v2: [u8; 32],
        vote_v3: [u8; 32],
        vote_encryption_pubkey: [u8; 32],
        vote_nonce: u128,
    ) -> Result<()> {
        let clock = Clock::get()?;
        require!(
            clock.unix_timestamp < ctx.accounts.proposal_acc.deadline,
            ErrorCode::VotingPeriodEnded
        );

        require!(
            !ctx.accounts.proposal_acc.is_finalized,
            ErrorCode::ProposalAlreadyFinalized
        );

        // VoterRecord init fails if PDA already exists = double vote prevention
        let voter_record = &mut ctx.accounts.voter_record;
        voter_record.bump = ctx.bumps.voter_record;
        voter_record.proposal = ctx.accounts.proposal_acc.key();
        voter_record.voter = ctx.accounts.payer.key();
        voter_record.has_voted = true;

        ctx.accounts.proposal_acc.voter_count += 1;

        // ArgBuilder order must match circuit params:
        // cast_vote(alloc_ctxt: Enc<Shared, VoteAllocation>, tallies_ctxt: Enc<Mxe, VoteTallies>)
        let args = ArgBuilder::new()
            // VoteAllocation: Enc<Shared, VoteAllocation>
            .x25519_pubkey(vote_encryption_pubkey)
            .plaintext_u128(vote_nonce)
            .encrypted_u64(vote_v0)
            .encrypted_u64(vote_v1)
            .encrypted_u64(vote_v2)
            .encrypted_u64(vote_v3)
            // VoteTallies: Enc<Mxe, VoteTallies>
            .plaintext_u128(ctx.accounts.proposal_acc.nonce)
            .account(
                ctx.accounts.proposal_acc.key(),
                8 + 1, // discriminator + bump
                32 * 5, // 5 encrypted u64 counters
            )
            .build();

        ctx.accounts.sign_pda_account.bump = ctx.bumps.sign_pda_account;

        queue_computation(
            ctx.accounts,
            computation_offset,
            args,
            vec![CastVoteCallback::callback_ix(
                computation_offset,
                &ctx.accounts.mxe_account,
                &[CallbackAccount {
                    pubkey: ctx.accounts.proposal_acc.key(),
                    is_writable: true,
                }],
            )?],
            1,
            0,
        )?;

        Ok(())
    }

    #[arcium_callback(encrypted_ix = "cast_vote")]
    pub fn cast_vote_callback(
        ctx: Context<CastVoteCallback>,
        output: SignedComputationOutputs<CastVoteOutput>,
    ) -> Result<()> {
        let o = match output.verify_output(
            &ctx.accounts.cluster_account,
            &ctx.accounts.computation_account,
        ) {
            Ok(CastVoteOutput { field_0 }) => field_0,
            Err(_) => return Err(ErrorCode::AbortedComputation.into()),
        };

        ctx.accounts.proposal_acc.vote_state = o.ciphertexts;
        ctx.accounts.proposal_acc.nonce = o.nonce;

        let clock = Clock::get()?;
        emit!(VoteCastEvent {
            proposal_id: ctx.accounts.proposal_acc.id,
            timestamp: clock.unix_timestamp,
            voter_count: ctx.accounts.proposal_acc.voter_count,
        });

        Ok(())
    }

    // ================================================================
    // Reveal
    // ================================================================

    /// Reveal results.  Only callable by the proposal authority, after the
    /// deadline, and only when quorum is met (voter_count >= quorum).
    pub fn reveal_results(
        ctx: Context<RevealResults>,
        computation_offset: u64,
        id: u32,
    ) -> Result<()> {
        require!(
            ctx.accounts.payer.key() == ctx.accounts.proposal_acc.authority,
            ErrorCode::InvalidAuthority
        );

        let clock = Clock::get()?;
        require!(
            clock.unix_timestamp >= ctx.accounts.proposal_acc.deadline,
            ErrorCode::VotingPeriodNotEnded
        );

        require!(
            !ctx.accounts.proposal_acc.is_finalized,
            ErrorCode::ProposalAlreadyFinalized
        );

        require!(
            ctx.accounts.proposal_acc.voter_count >= ctx.accounts.proposal_acc.quorum,
            ErrorCode::QuorumNotMet
        );

        msg!(
            "Revealing results for proposal {} (id={})",
            ctx.accounts.proposal_acc.title,
            id
        );

        let args = ArgBuilder::new()
            .plaintext_u128(ctx.accounts.proposal_acc.nonce)
            .account(
                ctx.accounts.proposal_acc.key(),
                8 + 1,
                32 * 5,
            )
            .build();

        ctx.accounts.sign_pda_account.bump = ctx.bumps.sign_pda_account;

        queue_computation(
            ctx.accounts,
            computation_offset,
            args,
            vec![RevealResultsCallback::callback_ix(
                computation_offset,
                &ctx.accounts.mxe_account,
                &[CallbackAccount {
                    pubkey: ctx.accounts.proposal_acc.key(),
                    is_writable: true,
                }],
            )?],
            1,
            0,
        )?;

        Ok(())
    }

    #[arcium_callback(encrypted_ix = "reveal_results")]
    pub fn reveal_results_callback(
        ctx: Context<RevealResultsCallback>,
        output: SignedComputationOutputs<RevealResultsOutput>,
    ) -> Result<()> {
        let o = match output.verify_output(
            &ctx.accounts.cluster_account,
            &ctx.accounts.computation_account,
        ) {
            Ok(RevealResultsOutput {
                field_0,
                field_1,
                field_2,
                field_3,
                field_4,
                field_5,
            }) => (field_0, field_1, field_2, field_3, field_4, field_5),
            Err(_) => return Err(ErrorCode::AbortedComputation.into()),
        };

        ctx.accounts.proposal_acc.is_finalized = true;

        emit!(ResultsRevealedEvent {
            proposal_id: ctx.accounts.proposal_acc.id,
            option_0: o.0,
            option_1: o.1,
            option_2: o.2,
            option_3: o.3,
            total_votes: o.4,
            winner: o.5,
        });

        Ok(())
    }
}

// ============================================================
// Account Structs — Computation Definition Initializers
// ============================================================

#[init_computation_definition_accounts("init_tallies", payer)]
#[derive(Accounts)]
pub struct InitTalliesCompDef<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(mut, address = derive_mxe_pda!())]
    pub mxe_account: Box<Account<'info, MXEAccount>>,
    #[account(mut)]
    /// CHECK: comp_def_account, checked by arcium program.
    pub comp_def_account: UncheckedAccount<'info>,
    #[account(mut, address = derive_mxe_lut_pda!(mxe_account.lut_offset_slot))]
    /// CHECK: address_lookup_table, checked by arcium program.
    pub address_lookup_table: UncheckedAccount<'info>,
    #[account(address = LUT_PROGRAM_ID)]
    /// CHECK: lut_program is the Address Lookup Table program.
    pub lut_program: UncheckedAccount<'info>,
    pub arcium_program: Program<'info, Arcium>,
    pub system_program: Program<'info, System>,
}

#[init_computation_definition_accounts("cast_vote", payer)]
#[derive(Accounts)]
pub struct InitVoteCompDef<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(mut, address = derive_mxe_pda!())]
    pub mxe_account: Box<Account<'info, MXEAccount>>,
    #[account(mut)]
    /// CHECK: comp_def_account, checked by arcium program.
    pub comp_def_account: UncheckedAccount<'info>,
    #[account(mut, address = derive_mxe_lut_pda!(mxe_account.lut_offset_slot))]
    /// CHECK: address_lookup_table, checked by arcium program.
    pub address_lookup_table: UncheckedAccount<'info>,
    #[account(address = LUT_PROGRAM_ID)]
    /// CHECK: lut_program is the Address Lookup Table program.
    pub lut_program: UncheckedAccount<'info>,
    pub arcium_program: Program<'info, Arcium>,
    pub system_program: Program<'info, System>,
}

#[init_computation_definition_accounts("reveal_results", payer)]
#[derive(Accounts)]
pub struct InitRevealCompDef<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(mut, address = derive_mxe_pda!())]
    pub mxe_account: Box<Account<'info, MXEAccount>>,
    #[account(mut)]
    /// CHECK: comp_def_account, checked by arcium program.
    pub comp_def_account: UncheckedAccount<'info>,
    #[account(mut, address = derive_mxe_lut_pda!(mxe_account.lut_offset_slot))]
    /// CHECK: address_lookup_table, checked by arcium program.
    pub address_lookup_table: UncheckedAccount<'info>,
    #[account(address = LUT_PROGRAM_ID)]
    /// CHECK: lut_program is the Address Lookup Table program.
    pub lut_program: UncheckedAccount<'info>,
    pub arcium_program: Program<'info, Arcium>,
    pub system_program: Program<'info, System>,
}

// ============================================================
// Account Structs — Proposal
// ============================================================

#[queue_computation_accounts("init_tallies", payer)]
#[derive(Accounts)]
#[instruction(computation_offset: u64, id: u32)]
pub struct CreateProposal<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(
        init_if_needed, space = 9, payer = payer,
        seeds = [&SIGN_PDA_SEED], bump,
        address = derive_sign_pda!(),
    )]
    pub sign_pda_account: Account<'info, ArciumSignerAccount>,
    #[account(address = derive_mxe_pda!())]
    pub mxe_account: Account<'info, MXEAccount>,
    #[account(mut, address = derive_mempool_pda!(mxe_account, ErrorCode::ClusterNotSet))]
    /// CHECK: mempool_account
    pub mempool_account: UncheckedAccount<'info>,
    #[account(mut, address = derive_execpool_pda!(mxe_account, ErrorCode::ClusterNotSet))]
    /// CHECK: executing_pool
    pub executing_pool: UncheckedAccount<'info>,
    #[account(mut, address = derive_comp_pda!(computation_offset, mxe_account, ErrorCode::ClusterNotSet))]
    /// CHECK: computation_account
    pub computation_account: UncheckedAccount<'info>,
    #[account(address = derive_comp_def_pda!(COMP_DEF_OFFSET_INIT_TALLIES))]
    pub comp_def_account: Account<'info, ComputationDefinitionAccount>,
    #[account(mut, address = derive_cluster_pda!(mxe_account, ErrorCode::ClusterNotSet))]
    pub cluster_account: Account<'info, Cluster>,
    #[account(mut, address = ARCIUM_FEE_POOL_ACCOUNT_ADDRESS)]
    pub pool_account: Account<'info, FeePool>,
    #[account(mut, address = ARCIUM_CLOCK_ACCOUNT_ADDRESS)]
    pub clock_account: Account<'info, ClockAccount>,
    pub system_program: Program<'info, System>,
    pub arcium_program: Program<'info, Arcium>,
    #[account(
        init, payer = payer,
        space = 8 + ProposalAccount::INIT_SPACE,
        seeds = [b"proposal", payer.key().as_ref(), id.to_le_bytes().as_ref()],
        bump,
    )]
    pub proposal_acc: Account<'info, ProposalAccount>,
}

#[callback_accounts("init_tallies")]
#[derive(Accounts)]
pub struct InitTalliesCallback<'info> {
    pub arcium_program: Program<'info, Arcium>,
    #[account(address = derive_comp_def_pda!(COMP_DEF_OFFSET_INIT_TALLIES))]
    pub comp_def_account: Account<'info, ComputationDefinitionAccount>,
    #[account(address = derive_mxe_pda!())]
    pub mxe_account: Account<'info, MXEAccount>,
    /// CHECK: computation_account
    pub computation_account: UncheckedAccount<'info>,
    #[account(address = derive_cluster_pda!(mxe_account, ErrorCode::ClusterNotSet))]
    pub cluster_account: Account<'info, Cluster>,
    #[account(address = ::anchor_lang::solana_program::sysvar::instructions::ID)]
    /// CHECK: instructions_sysvar
    pub instructions_sysvar: AccountInfo<'info>,
    #[account(mut)]
    pub proposal_acc: Account<'info, ProposalAccount>,
}

// ============================================================
// Account Structs — Voting
// ============================================================

#[queue_computation_accounts("cast_vote", payer)]
#[derive(Accounts)]
#[instruction(computation_offset: u64, _id: u32)]
pub struct CastVote<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(
        init_if_needed, space = 9, payer = payer,
        seeds = [&SIGN_PDA_SEED], bump,
        address = derive_sign_pda!(),
    )]
    pub sign_pda_account: Account<'info, ArciumSignerAccount>,
    #[account(address = derive_mxe_pda!())]
    pub mxe_account: Account<'info, MXEAccount>,
    #[account(mut, address = derive_mempool_pda!(mxe_account, ErrorCode::ClusterNotSet))]
    /// CHECK: mempool_account
    pub mempool_account: UncheckedAccount<'info>,
    #[account(mut, address = derive_execpool_pda!(mxe_account, ErrorCode::ClusterNotSet))]
    /// CHECK: executing_pool
    pub executing_pool: UncheckedAccount<'info>,
    #[account(mut, address = derive_comp_pda!(computation_offset, mxe_account, ErrorCode::ClusterNotSet))]
    /// CHECK: computation_account
    pub computation_account: UncheckedAccount<'info>,
    #[account(address = derive_comp_def_pda!(COMP_DEF_OFFSET_CAST_VOTE))]
    pub comp_def_account: Account<'info, ComputationDefinitionAccount>,
    #[account(mut, address = derive_cluster_pda!(mxe_account, ErrorCode::ClusterNotSet))]
    pub cluster_account: Account<'info, Cluster>,
    #[account(mut, address = ARCIUM_FEE_POOL_ACCOUNT_ADDRESS)]
    pub pool_account: Account<'info, FeePool>,
    #[account(mut, address = ARCIUM_CLOCK_ACCOUNT_ADDRESS)]
    pub clock_account: Account<'info, ClockAccount>,
    pub system_program: Program<'info, System>,
    pub arcium_program: Program<'info, Arcium>,
    /// CHECK: Proposal authority pubkey
    #[account(address = proposal_acc.authority)]
    pub authority: UncheckedAccount<'info>,
    #[account(
        mut,
        seeds = [b"proposal", authority.key().as_ref(), _id.to_le_bytes().as_ref()],
        bump = proposal_acc.bump,
        has_one = authority,
    )]
    pub proposal_acc: Account<'info, ProposalAccount>,
    #[account(
        init, payer = payer,
        space = 8 + VoterRecord::INIT_SPACE,
        seeds = [b"voter", proposal_acc.key().as_ref(), payer.key().as_ref()],
        bump,
    )]
    pub voter_record: Account<'info, VoterRecord>,
}

#[callback_accounts("cast_vote")]
#[derive(Accounts)]
pub struct CastVoteCallback<'info> {
    pub arcium_program: Program<'info, Arcium>,
    #[account(address = derive_comp_def_pda!(COMP_DEF_OFFSET_CAST_VOTE))]
    pub comp_def_account: Account<'info, ComputationDefinitionAccount>,
    #[account(address = derive_mxe_pda!())]
    pub mxe_account: Account<'info, MXEAccount>,
    /// CHECK: computation_account
    pub computation_account: UncheckedAccount<'info>,
    #[account(address = derive_cluster_pda!(mxe_account, ErrorCode::ClusterNotSet))]
    pub cluster_account: Account<'info, Cluster>,
    #[account(address = ::anchor_lang::solana_program::sysvar::instructions::ID)]
    /// CHECK: instructions_sysvar
    pub instructions_sysvar: AccountInfo<'info>,
    #[account(mut)]
    pub proposal_acc: Account<'info, ProposalAccount>,
}

// ============================================================
// Account Structs — Reveal
// ============================================================

#[queue_computation_accounts("reveal_results", payer)]
#[derive(Accounts)]
#[instruction(computation_offset: u64, id: u32)]
pub struct RevealResults<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(
        init_if_needed, space = 9, payer = payer,
        seeds = [&SIGN_PDA_SEED], bump,
        address = derive_sign_pda!(),
    )]
    pub sign_pda_account: Account<'info, ArciumSignerAccount>,
    #[account(address = derive_mxe_pda!())]
    pub mxe_account: Account<'info, MXEAccount>,
    #[account(mut, address = derive_mempool_pda!(mxe_account, ErrorCode::ClusterNotSet))]
    /// CHECK: mempool_account
    pub mempool_account: UncheckedAccount<'info>,
    #[account(mut, address = derive_execpool_pda!(mxe_account, ErrorCode::ClusterNotSet))]
    /// CHECK: executing_pool
    pub executing_pool: UncheckedAccount<'info>,
    #[account(mut, address = derive_comp_pda!(computation_offset, mxe_account, ErrorCode::ClusterNotSet))]
    /// CHECK: computation_account
    pub computation_account: UncheckedAccount<'info>,
    #[account(address = derive_comp_def_pda!(COMP_DEF_OFFSET_REVEAL_RESULTS))]
    pub comp_def_account: Account<'info, ComputationDefinitionAccount>,
    #[account(mut, address = derive_cluster_pda!(mxe_account, ErrorCode::ClusterNotSet))]
    pub cluster_account: Account<'info, Cluster>,
    #[account(mut, address = ARCIUM_FEE_POOL_ACCOUNT_ADDRESS)]
    pub pool_account: Account<'info, FeePool>,
    #[account(mut, address = ARCIUM_CLOCK_ACCOUNT_ADDRESS)]
    pub clock_account: Account<'info, ClockAccount>,
    pub system_program: Program<'info, System>,
    pub arcium_program: Program<'info, Arcium>,
    #[account(
        seeds = [b"proposal", payer.key().as_ref(), id.to_le_bytes().as_ref()],
        bump = proposal_acc.bump,
    )]
    pub proposal_acc: Account<'info, ProposalAccount>,
}

#[callback_accounts("reveal_results")]
#[derive(Accounts)]
pub struct RevealResultsCallback<'info> {
    pub arcium_program: Program<'info, Arcium>,
    #[account(address = derive_comp_def_pda!(COMP_DEF_OFFSET_REVEAL_RESULTS))]
    pub comp_def_account: Account<'info, ComputationDefinitionAccount>,
    #[account(address = derive_mxe_pda!())]
    pub mxe_account: Account<'info, MXEAccount>,
    /// CHECK: computation_account
    pub computation_account: UncheckedAccount<'info>,
    #[account(address = derive_cluster_pda!(mxe_account, ErrorCode::ClusterNotSet))]
    pub cluster_account: Account<'info, Cluster>,
    #[account(address = ::anchor_lang::solana_program::sysvar::instructions::ID)]
    /// CHECK: instructions_sysvar
    pub instructions_sysvar: AccountInfo<'info>,
    #[account(mut)]
    pub proposal_acc: Account<'info, ProposalAccount>,
}

// ============================================================
// State Accounts
// ============================================================

#[account]
#[derive(InitSpace)]
pub struct ProposalAccount {
    pub bump: u8,
    /// Encrypted vote tallies: 5 counters (option_0..3 + total_votes) x 32 bytes
    pub vote_state: [[u8; 32]; 5],
    pub id: u32,
    pub authority: Pubkey,
    pub nonce: u128,
    #[max_len(100)]
    pub title: String,
    #[max_len(4, 32)]
    pub options: Vec<String>,
    pub num_options: u8,
    pub deadline: i64,
    pub voice_credits: u64,
    pub quorum: u32,
    pub is_finalized: bool,
    pub voter_count: u32,
}

#[account]
#[derive(InitSpace)]
pub struct VoterRecord {
    pub bump: u8,
    pub proposal: Pubkey,
    pub voter: Pubkey,
    pub has_voted: bool,
}

// ============================================================
// Events
// ============================================================

#[event]
pub struct VoteCastEvent {
    pub proposal_id: u32,
    pub timestamp: i64,
    pub voter_count: u32,
}

#[event]
pub struct ResultsRevealedEvent {
    pub proposal_id: u32,
    pub option_0: u64,
    pub option_1: u64,
    pub option_2: u64,
    pub option_3: u64,
    pub total_votes: u64,
    pub winner: u8,
}

// ============================================================
// Errors
// ============================================================

#[error_code]
pub enum ErrorCode {
    #[msg("Invalid authority")]
    InvalidAuthority,
    #[msg("Computation was aborted")]
    AbortedComputation,
    #[msg("Cluster not set")]
    ClusterNotSet,
    #[msg("Voting period has ended")]
    VotingPeriodEnded,
    #[msg("Voting period has not ended yet")]
    VotingPeriodNotEnded,
    #[msg("Already voted on this proposal")]
    AlreadyVoted,
    #[msg("Invalid option choice")]
    InvalidChoice,
    #[msg("Proposal already finalized")]
    ProposalAlreadyFinalized,
    #[msg("Quorum not met")]
    QuorumNotMet,
}
