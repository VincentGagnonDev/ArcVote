use arcis::*;

#[encrypted]
mod circuits {
    use arcis::*;

    /// Encrypted vote tallies for up to 4 options.
    pub struct VoteTallies {
        option_0: u64,
        option_1: u64,
        option_2: u64,
        option_3: u64,
        total_votes: u64,
    }

    /// A voter's quadratic credit allocation across options.
    /// Each field is the number of effective votes for that option.
    /// Quadratic cost: v0² + v1² + v2² + v3² must be ≤ 100 voice credits.
    pub struct VoteAllocation {
        v0: u64,
        v1: u64,
        v2: u64,
        v3: u64,
    }

    /// Initialize all vote counters to zero.
    #[instruction]
    pub fn init_tallies(mxe: Mxe) -> Enc<Mxe, VoteTallies> {
        let tallies = VoteTallies {
            option_0: 0,
            option_1: 0,
            option_2: 0,
            option_3: 0,
            total_votes: 0,
        };
        mxe.from_arcis(tallies)
    }

    /// Cast a quadratic vote.
    ///
    /// The MPC cluster computes v0² + v1² + v2² + v3² and only counts the
    /// vote if the total cost ≤ 100 voice credits.  Individual allocations
    /// are never revealed — only aggregated tallies.
    ///
    /// MPC executes both branches of the budget check (no information leakage).
    #[instruction]
    pub fn cast_vote(
        alloc_ctxt: Enc<Shared, VoteAllocation>,
        tallies_ctxt: Enc<Mxe, VoteTallies>,
    ) -> Enc<Mxe, VoteTallies> {
        let alloc = alloc_ctxt.to_arcis();
        let mut tallies = tallies_ctxt.to_arcis();

        // Quadratic cost — sum of squares
        let cost = alloc.v0 * alloc.v0
                 + alloc.v1 * alloc.v1
                 + alloc.v2 * alloc.v2
                 + alloc.v3 * alloc.v3;

        // Budget enforcement inside MPC
        if cost <= 100u64 {
            tallies.option_0 += alloc.v0;
            tallies.option_1 += alloc.v1;
            tallies.option_2 += alloc.v2;
            tallies.option_3 += alloc.v3;
            tallies.total_votes += alloc.v0 + alloc.v1 + alloc.v2 + alloc.v3;
        }

        tallies_ctxt.owner.from_arcis(tallies)
    }

    /// Plaintext results returned after reveal.
    pub struct RevealedResults {
        option_0: u64,
        option_1: u64,
        option_2: u64,
        option_3: u64,
        total_votes: u64,
        winner: u8,
    }

    /// Reveal results — decrypt tallies and determine the winner.
    #[instruction]
    pub fn reveal_results(tallies_ctxt: Enc<Mxe, VoteTallies>) -> RevealedResults {
        let tallies = tallies_ctxt.to_arcis();

        let mut max_votes = tallies.option_0;
        let mut winner: u8 = 0;

        if tallies.option_1 > max_votes {
            max_votes = tallies.option_1;
            winner = 1;
        }
        if tallies.option_2 > max_votes {
            max_votes = tallies.option_2;
            winner = 2;
        }
        if tallies.option_3 > max_votes {
            max_votes = tallies.option_3;
            winner = 3;
        }

        RevealedResults {
            option_0: tallies.option_0.reveal(),
            option_1: tallies.option_1.reveal(),
            option_2: tallies.option_2.reveal(),
            option_3: tallies.option_3.reveal(),
            total_votes: tallies.total_votes.reveal(),
            winner: winner.reveal(),
        }
    }
}
