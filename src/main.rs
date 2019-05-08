extern crate bulletproofs;
extern crate curve25519_dalek;
extern crate merlin;
mod r1cs_utils;

use bulletproofs::r1cs::{ConstraintSystem, R1CSError, R1CSProof, Variable, Prover, Verifier};
use curve25519_dalek::scalar::Scalar;
use bulletproofs::{BulletproofGens, PedersenGens};
use merlin::Transcript;
use curve25519_dalek::ristretto::CompressedRistretto;
use bulletproofs::r1cs::LinearCombination;
use crate::r1cs_utils::{AllocatedQuantity, positive_no_gadget, constrain_lc_with_scalar};


fn main() {

    let zkp_position = &(PositionRangeZKP::new());
    let (proof, coms) =  zkp_position.generate_proof_for_player_position(1);
    let verification = zkp_position.verify_proof_for_player_position(proof,coms);

    match verification {
        Ok(v) => { println!("Yes");},
        Err(e)=> {println!("No")}
    }

    let zkp_balances = &(SumOfFundsZKP::new());
    let (proof, coms) =  zkp_balances.generate_proof_for_players_balances(2,3,1);
    let verification = zkp_balances.verify_proof_for_players_balances(2,proof, coms);

    match verification {
        Ok(v) => { println!("Yes");},
        Err(e)=> {println!("No")}
    }




}

struct PositionRangeZKP{
    pc_gens: PedersenGens,
    bp_gens: BulletproofGens,
    n: usize,
    max: u64,
    min: u64,
}

impl PositionRangeZKP{
    fn new() -> PositionRangeZKP{
        return PositionRangeZKP{
            pc_gens: PedersenGens::default(),
            bp_gens: BulletproofGens::new(128, 1),
            n: 32,
            max: 21,
            min: 0 ,
        }
    }

    fn generate_proof_for_player_position(&self,v: u64) -> (R1CSProof, Vec<CompressedRistretto>){
        let a = v - self.min;
        let b = self.max - v;

        let mut comms = vec![];

        // Prover makes a `ConstraintSystem` instance representing a range proof gadget
        let mut prover_transcript = Transcript::new(b"BoundsTest");
        let mut rng = rand::thread_rng();
        let mut prover = Prover::new(&self.pc_gens, &mut prover_transcript);

        let (com_v, var_v) = prover.commit(v.into(), Scalar::random(&mut rng));
        let quantity_v = AllocatedQuantity {
            variable: var_v,
            assignment: Some(v),
        };
        comms.push(com_v);

        let (com_a, var_a) = prover.commit(a.into(), Scalar::random(&mut rng));
        let quantity_a = AllocatedQuantity {
            variable: var_a,
            assignment: Some(a),
        };
        comms.push(com_a);

        let (com_b, var_b) = prover.commit(b.into(), Scalar::random(&mut rng));
        let quantity_b = AllocatedQuantity {
            variable: var_b,
            assignment: Some(b),
        };
        comms.push(com_b);

        assert!(bound_check_gadget(&mut prover, quantity_v, quantity_a, quantity_b, self.max, self.min, self.n).is_ok());

        let proof = prover.prove(&self.bp_gens).unwrap();

        (proof, comms)
    }

    fn verify_proof_for_player_position(&self, proof:R1CSProof, commitments: Vec<CompressedRistretto>) -> Result<(), R1CSError>{
        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(128, 1);

        // TODO: Use correct bit size of the field
        let n = 32;



        let mut verifier_transcript = Transcript::new(b"BoundsTest");
        let mut verifier = Verifier::new(&mut verifier_transcript);

        let var_v = verifier.commit(commitments[0]);
        let quantity_v = AllocatedQuantity {
            variable: var_v,
            assignment: None,
        };

        let var_a = verifier.commit(commitments[1]);
        let quantity_a = AllocatedQuantity {
            variable: var_a,
            assignment: None,
        };

        let var_b = verifier.commit(commitments[2]);
        let quantity_b = AllocatedQuantity {
            variable: var_b,
            assignment: None,
        };

        assert!(bound_check_gadget(&mut verifier, quantity_v, quantity_a, quantity_b, self.max, self.min, n).is_ok());

        Ok(verifier.verify(&proof, &pc_gens, &bp_gens)?)
    }
}








pub fn bound_check_gadget<CS: ConstraintSystem>(
    cs: &mut CS,
    v: AllocatedQuantity,
    a: AllocatedQuantity,
    b: AllocatedQuantity,
    max: u64,
    min: u64,
    n: usize
) -> Result<(), R1CSError> {

    // a + b = max - min
    // Constrain a + b to be same as max - min.
    constrain_lc_with_scalar::<CS>(cs, a.variable + b.variable, &Scalar::from(max - min));

    // Constrain a in [0, 2^n)
    assert!(positive_no_gadget(cs, a, n).is_ok());
    // Constrain b in [0, 2^n)
    assert!(positive_no_gadget(cs, b, n).is_ok());

    Ok(())
}


struct SumOfFundsZKP{
    pc_gens: PedersenGens,
    bp_gens: BulletproofGens,
    n: usize,

}

impl SumOfFundsZKP{
    fn new() -> SumOfFundsZKP{
        return SumOfFundsZKP{
            pc_gens: PedersenGens::default(),
            bp_gens: BulletproofGens::new(128, 1),
            n: 32,

        }
    }

    fn generate_proof_for_players_balances(&self, total: u64, player1: u64, player2: u64)-> (R1CSProof, Vec<CompressedRistretto>){


        let mut comms = vec![];

        // Prover makes a `ConstraintSystem` instance representing a range proof gadget
        let mut prover_transcript = Transcript::new(b"BoundsTest");
        let mut rng = rand::thread_rng();
        let mut prover = Prover::new(&self.pc_gens, &mut prover_transcript);

        let (com_v, var_v) = prover.commit(total.into(), Scalar::random(&mut rng));
        let quantity_v = AllocatedQuantity {
            variable: var_v,
            assignment: Some(total),
        };
        comms.push(com_v);

        let (com_a, var_a) = prover.commit(player1.into(), Scalar::random(&mut rng));
        let quantity_a = AllocatedQuantity {
            variable: var_a,
            assignment: Some(player1),
        };
        comms.push(com_a);

        let (com_b, var_b) = prover.commit(player2.into(), Scalar::random(&mut rng));
        let quantity_b = AllocatedQuantity {
            variable: var_b,
            assignment: Some(player2),
        };
        comms.push(com_b);

        assert!(check_sum_gadget(&mut prover, quantity_v, quantity_a, quantity_b, total, self.n).is_ok());

        let proof = prover.prove(&self.bp_gens).unwrap();

        (proof, comms)
    }

    fn verify_proof_for_players_balances(&self,total: u64, proof:R1CSProof, commitments: Vec<CompressedRistretto> ) -> Result<(), R1CSError>{


        let mut verifier_transcript = Transcript::new(b"BoundsTest");
        let mut verifier = Verifier::new(&mut verifier_transcript);

        let var_v = verifier.commit(commitments[0]);
        let quantity_v = AllocatedQuantity {
            variable: var_v,
            assignment: None,
        };

        let var_a = verifier.commit(commitments[1]);
        let quantity_a = AllocatedQuantity {
            variable: var_a,
            assignment: None,
        };

        let var_b = verifier.commit(commitments[2]);
        let quantity_b = AllocatedQuantity {
            variable: var_b,
            assignment: None,
        };

        assert!(check_sum_gadget(&mut verifier, quantity_v, quantity_a, quantity_b, total, self.n).is_ok());

        Ok(verifier.verify(&proof, &self.pc_gens, &self.bp_gens)?)
    }
}











pub fn check_sum_gadget<CS: ConstraintSystem>(
    cs: &mut CS,
    v: AllocatedQuantity,
    a: AllocatedQuantity,
    b: AllocatedQuantity,
    total: u64,
    n: usize
) -> Result<(), R1CSError> {

    // a + b = max - min
    // Constrain a + b to be same as max - min.
    constrain_lc_with_scalar::<CS>(cs, a.variable + b.variable, &Scalar::from(total));

    // Constrain a in [0, 2^n)
    assert!(positive_no_gadget(cs, a, n).is_ok());
    // Constrain b in [0, 2^n)
    assert!(positive_no_gadget(cs, b, n).is_ok());

    Ok(())
}

