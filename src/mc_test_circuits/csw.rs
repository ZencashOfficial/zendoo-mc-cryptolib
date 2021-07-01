use algebra::ToConstraintField;
use proof_systems::darlin::data_structures::{FinalDarlinDeferredData, FinalDarlinProof};
use r1cs_core::{
    ConstraintSynthesizer, ConstraintSystem, SynthesisError,
};
use r1cs_std::{
    alloc::AllocGadget,
    eq::EqGadget,
    instantiated::tweedle::FrGadget,
};
use cctp_primitives::{
    type_mapping::FieldElement,
    proving_system::{
        ProvingSystem, ZendooProverKey, ZendooProof, ZendooVerifierKey,
        error::ProvingSystemError, init::{get_g1_committer_key, get_g2_committer_key},
    },
};
use crate::type_mapping::*;
use rand::rngs::OsRng;
use cctp_primitives::utils::commitment_tree::{ByteAccumulator, hash_vec};

type FieldElementGadget = FrGadget;

fn enforce_csw_inputs_gadget<CS: ConstraintSystem<FieldElement>>(
    mut cs:             CS,
    aggregated_input:   Option<FieldElement>,
) -> Result<(), SynthesisError>
{
    let aggregated_input_g = FieldElementGadget::alloc(
        cs.ns(|| "alloc aggregated_input"),
        || aggregated_input.ok_or(SynthesisError::AssignmentMissing)
    )?;

    let expected_aggregated_input_g = FieldElementGadget::alloc_input(
        cs.ns(|| "alloc expected_aggregated_input"),
        || aggregated_input.ok_or(SynthesisError::AssignmentMissing)
    )?;

    for _ in 0..512 {
        aggregated_input_g.enforce_equal(
            cs.ns(|| "check 1"),
            &expected_aggregated_input_g
        )?;
    }
    
    Ok(())
}

// Simple test circuit, enforcing that the hash of all the witnesses equals the public input
pub struct CSWTestCircuit {
    aggregated_input: Option<FieldElement>,
}

impl ConstraintSynthesizer<FieldElement> for CSWTestCircuit {
    fn generate_constraints<CS: ConstraintSystem<FieldElement>>(self, cs: &mut CS) -> Result<(), SynthesisError>
    {
        enforce_csw_inputs_gadget(cs.ns(|| "enforce witnesses == pub_ins"), self.aggregated_input)
    }
}

// Simple test circuit, enforcing that the hash of all the witnesses equals the public input
pub struct CSWTestCircuitWithAccumulators {
    aggregated_input:   Option<FieldElement>,
    deferred:           Vec<FieldElement>, // Represents deferred data
}

impl ConstraintSynthesizer<FieldElement> for CSWTestCircuitWithAccumulators {
    fn generate_constraints<CS: ConstraintSystem<FieldElement>>(self, cs: &mut CS) -> Result<(), SynthesisError>
    {
        // convert the FinalDarlinDeferred efficiently to circuit inputs
        let deferred_as_native_fes = self.deferred;

        // Alloc deferred data as public input
        let mut deferred_input_gs = Vec::new();
        for (i, fe) in deferred_as_native_fes.iter().enumerate() {
            let ins_g = FieldElementGadget::alloc_input(
                cs.ns(|| format!("Alloc input deferred elem {}", i)),
                || Ok(fe)
            )?;
            deferred_input_gs.push(ins_g);
        }

        // Alloc deferred data as witness
        let mut deferred_gs = Vec::new();
        for (i, fe) in deferred_as_native_fes.into_iter().enumerate() {
            let witness_g = FieldElementGadget::alloc(
                cs.ns(|| format!("Alloc deferred elem {}", i)),
                || Ok(fe)
            )?;
            deferred_gs.push(witness_g);
        }

        // Enforce the system inputs to the circuit to be equal to the allocated `deferred`.
        // This is a simple way to allow test cases where sys data (i.e. the deferred
        // accumulators) are wrong.
        for (i, (deferred_w, deferred_ins)) in deferred_input_gs.into_iter().zip(deferred_gs).enumerate() {
            deferred_w.enforce_equal(
                cs.ns(|| format!("enforce deferred equal {}", i)),
                &deferred_ins
            )?;
        }

        enforce_csw_inputs_gadget(cs.ns(|| "enforce witnesses == pub_ins"), self.aggregated_input)
    }
}

pub fn generate_parameters(ps: ProvingSystem) -> Result<(ZendooProverKey, ZendooVerifierKey), ProvingSystemError>
{
    let ck_g1 = get_g1_committer_key()?;
    match ps {
        ProvingSystem::Undefined => Err(ProvingSystemError::UndefinedProvingSystem),
        ProvingSystem::Darlin => {
            let ck_g2 = get_g2_committer_key()?;
            let circ = CSWTestCircuitWithAccumulators {
                aggregated_input: None,
                deferred: FinalDarlinDeferredData::<G1, G2>::generate_random::<_, Digest>(
                    &mut rand::thread_rng(),
                    ck_g1.as_ref().unwrap(),
                    ck_g2.as_ref().unwrap(),
                ).to_field_elements().unwrap()
            };
            let (pk, vk) =  CoboundaryMarlin::index(ck_g1.as_ref().unwrap(), circ)
                .map_err(|e| ProvingSystemError::SetupFailed(e.to_string()))?;
            Ok((ZendooProverKey::Darlin(pk), ZendooVerifierKey::Darlin(vk)))
        },
        ProvingSystem::CoboundaryMarlin => {
            let circ = CSWTestCircuit {
                aggregated_input: None,
            };
            let (pk, vk) =  CoboundaryMarlin::index(ck_g1.as_ref().unwrap(), circ)
                .map_err(|e| ProvingSystemError::SetupFailed(e.to_string()))?;
            Ok((ZendooProverKey::CoboundaryMarlin(pk), ZendooVerifierKey::CoboundaryMarlin(vk)))
        }
    }
}

pub fn generate_proof(
    pk:                                         &ZendooProverKey,
    zk:                                         bool,
    amount:                                     u64,
    sc_id:                                      &FieldElement,
    nullifier:                                  &FieldElement,
    pub_key_hash:                               &[u8; UINT_160_SIZE],
    cert_data_hash:                             &FieldElement,
    end_cumulative_sc_tx_commitment_tree_root:  &FieldElement,
) -> Result<ZendooProof, ProvingSystemError> {
    let rng = &mut OsRng;
    let ck_g1 = get_g1_committer_key()?;

    let mut fes = ByteAccumulator::init()
        .update(amount).map_err(|e| ProvingSystemError::Other(format!("{:?}", e)))?
        .update(&pub_key_hash[..]).map_err(|e| ProvingSystemError::Other(format!("{:?}", e)))?
        .get_field_elements().map_err(|e| ProvingSystemError::Other(format!("{:?}", e)))?;

    fes.append(&mut vec![
        *sc_id, *nullifier, *cert_data_hash, *end_cumulative_sc_tx_commitment_tree_root
    ]);

    let aggregated_input = hash_vec(fes).map_err(|e| ProvingSystemError::Other(format!("{:?}", e)))?;


    match pk {
        ZendooProverKey::Darlin(pk) => {
            let ck_g2 = get_g2_committer_key()?;
            let deferred = FinalDarlinDeferredData::<G1, G2>::generate_random::<_, Digest>(
                rng,
                ck_g1.as_ref().unwrap(),
                ck_g2.as_ref().unwrap(),
            );
            let deferred_fes = deferred.to_field_elements().unwrap();
            let circ = CSWTestCircuitWithAccumulators {
                aggregated_input: Some(aggregated_input),
                deferred: deferred_fes.clone()
            };
            let proof = CoboundaryMarlin::prove(
                pk,
                ck_g1.as_ref().unwrap(),
                circ,
                zk,
                if zk { Some(rng) } else { None }
            ).map_err(|e| ProvingSystemError::ProofCreationFailed(e.to_string()))?;
            let darlin_proof = FinalDarlinProof::<G1, G2, Digest> {
                proof: MarlinProof(proof),
                deferred
            };
            Ok(ZendooProof::Darlin(darlin_proof))
        },
        ZendooProverKey::CoboundaryMarlin(pk) => {
            let circ = CSWTestCircuit {
                aggregated_input: Some(aggregated_input),
            };
            let proof = CoboundaryMarlin::prove(
                pk,
                ck_g1.as_ref().unwrap(),
                circ,
                zk,
                if zk { Some(rng) } else { None }
            ).map_err(|e| ProvingSystemError::ProofCreationFailed(e.to_string()))?;
            Ok(ZendooProof::CoboundaryMarlin(MarlinProof(proof)))
        }
    }
}