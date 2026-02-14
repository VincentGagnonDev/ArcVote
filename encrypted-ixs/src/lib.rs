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

    /// A single voter's encrypted choice (0-3).
    pub struct VoterChoice {
        choice: u8,
    }

    /// Initialize all counters to zero.
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

    /// Cast a vote — increment the chosen option's counter.
    /// The individual vote value is never revealed.
    #[instruction]
    pub fn cast_vote(
        vote_ctxt: Enc<Shared, VoterChoice>,
        tallies_ctxt: Enc<Mxe, VoteTallies>,
    ) -> Enc<Mxe, VoteTallies> {
        let vote = vote_ctxt.to_arcis();
        let mut tallies = tallies_ctxt.to_arcis();

        // MPC executes all branches — no information leakage
        if vote.choice == 0u8 {
            tallies.option_0 += 1;
        }
        if vote.choice == 1u8 {
            tallies.option_1 += 1;
        }
        if vote.choice == 2u8 {
            tallies.option_2 += 1;
        }
        if vote.choice == 3u8 {
            tallies.option_3 += 1;
        }

        tallies.total_votes += 1;

        tallies_ctxt.owner.from_arcis(tallies)
    }

    /// Revealed results with all counts and winner index.
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
