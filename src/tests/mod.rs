use crate::{zendoo_compress_bit_vector, zendoo_decompress_bit_vector, zendoo_free_bws, macros::{BufferWithSize, CctpErrorCode}};
use cctp_primitives::bit_vector::compression::CompressionAlgorithm;
use std::slice;

#[cfg(feature = "mc-test-circuit")]
use crate::{
    zendoo_init_dlog_keys, zendoo_generate_mc_test_params, TestCircuitType, zendoo_get_random_field,
    zendoo_deserialize_sc_pk_from_file, zendoo_create_return_cert_test_proof,
    zendoo_deserialize_sc_proof, zendoo_deserialize_sc_vk_from_file,
    zendoo_add_certificate_proof_to_batch_verifier, zendoo_field_free, zendoo_sc_pk_free,
    zendoo_sc_proof_free, zendoo_sc_vk_free, zendoo_create_return_csw_test_proof,
    zendoo_add_csw_proof_to_batch_verifier, zendoo_batch_verify_all_proofs,
    zendoo_free_batch_proof_verifier_result,
};

#[cfg(feature = "mc-test-circuit")]
use cctp_primitives::proving_system::{
    verifier::batch_verifier::ZendooBatchVerifier,
    ProvingSystem
};

#[cfg(feature = "mc-test-circuit")]
use std::{
    ptr::{null, null_mut},
    sync::{ Arc, RwLock }
};

#[cfg(feature = "mc-test-circuit")]
use rand::{thread_rng, Rng};

#[cfg(target_os = "windows")]
use std::ffi::OsString;
#[cfg(target_os = "windows")]
use std::os::windows::ffi::OsStrExt;


#[cfg(all(feature = "mc-test-circuit", not(target_os = "windows")))]
fn path_as_ptr(path: &str) -> *const u8 { path.as_ptr() }

#[cfg(all(feature = "mc-test-circuit", target_os = "windows"))]
fn path_as_ptr(path: &str) -> *const u16 {
    let tmp: Vec<u16> = OsString::from(path).encode_wide().collect();
    tmp.as_ptr()
}

#[cfg(feature = "mc-test-circuit")]
#[ignore]
#[test]
fn serialization_deserialization_bench_vk_proof() {
    use algebra::UniformRand;
    use rand::thread_rng;
    use cctp_primitives::{
        type_mapping::FieldElement,
        utils::serialization::serialize_to_buffer
    };
    use crate::{
        zendoo_serialize_sc_proof,
        zendoo_deserialize_sc_vk
    };
    use std::convert::TryInto;

    let segment_size = 1 << 17;
    let num_constraints = 1 << 18;
    let num_proofs = 100;

    let mut rng = &mut thread_rng();

    // Init DLOG keys
    println!("Setup DLOG keys...");
    assert!(zendoo_init_dlog_keys(segment_size, &mut CctpErrorCode::OK));

    // CSW
    println!("Bench serialize/deserialize CSW...");
    {   // Generate SNARK keys
        println!("Generate SNARK pk and vk...");
        let (pk, vk) = crate::mc_test_circuits::csw::generate_parameters(ProvingSystem::Darlin, num_constraints).unwrap();

        println!("Generate proof...");
        let proof = crate::mc_test_circuits::csw::generate_proof(
            &pk,
            true,
            0,
            &FieldElement::rand(&mut rng),
            &FieldElement::rand(&mut rng),
            vec![0u8; 20].as_slice().try_into().unwrap(),
            &FieldElement::rand(&mut rng),
            &FieldElement::rand(&mut rng),
            num_constraints
        ).unwrap();

        println!("Test deserialization...");
        for compressed in vec![true, false].into_iter() {

            // Serialize vk and proof in compressed/uncompressed form
            let mut vk_bytes = serialize_to_buffer(&vk, Some(compressed)).unwrap();
            let data_vk = vk_bytes.as_mut_ptr();
            let len_vk = vk_bytes.len();
            let vk_bws = BufferWithSize { data: data_vk, len: len_vk };

            let proof_bws = zendoo_serialize_sc_proof(&proof, &mut CctpErrorCode::OK, compressed);
            assert!(proof_bws != null_mut());
            let len_proof = unsafe { (*proof_bws).len };

            // Deserialize with various combinations
            for semantic_checks in vec![true, false].into_iter() {
                println!(
                    "Compressed: {}, Semantic checks: {}",
                    compressed, semantic_checks
                );
                println!("Vk len: {}", len_vk);
                println!("Proof len: {}", len_proof);

                let total_deser_vk_time = std::time::Instant::now();
                for _ in 0..num_proofs {
                    let vk = zendoo_deserialize_sc_vk(
                        &vk_bws, semantic_checks, &mut CctpErrorCode::OK, compressed
                    );
                    assert!(vk != null_mut());
                }
                println!("Total time to deserialize {} vks: {:?}", num_proofs, total_deser_vk_time.elapsed());


                let total_deser_proof_time = std::time::Instant::now();
                for _ in 0..num_proofs {
                    let proof = zendoo_deserialize_sc_proof(
                        proof_bws, semantic_checks, &mut CctpErrorCode::OK, compressed
                    );
                    assert!(proof != null_mut());
                }
                println!("Total time to deserialize {} proofs: {:?}", num_proofs, total_deser_proof_time.elapsed());
            }

            zendoo_free_bws(proof_bws);
        }
    }
    
    // CERT
    println!("Bench serialize/deserialize CERT...");
    {
        let num_constraints = num_constraints * 2;

        // Generate SNARK keys
        println!("Generate SNARK pk and vk...");
        let (pk, vk) = crate::mc_test_circuits::cert::generate_parameters(ProvingSystem::Darlin, num_constraints).unwrap();

        println!("Generate proof...");
        let proof = crate::mc_test_circuits::cert::generate_proof(
            &pk,
            true,
            &FieldElement::rand(&mut rng),
            &FieldElement::rand(&mut rng),
            0,
            0,
            None,
            None,
            &FieldElement::rand(&mut rng),
            0,
            0,
            num_constraints
        ).unwrap();

        println!("Test deserialization...");
        for compressed in vec![true, false].into_iter() {

            // Serialize vk and proof in compressed/uncompressed form
            let mut vk_bytes = serialize_to_buffer(&vk, Some(compressed)).unwrap();
            let data_vk = vk_bytes.as_mut_ptr();
            let len_vk = vk_bytes.len();
            let vk_bws = BufferWithSize { data: data_vk, len: len_vk };

            let proof_bws = zendoo_serialize_sc_proof(&proof, &mut CctpErrorCode::OK, compressed);
            assert!(proof_bws != null_mut());
            let len_proof = unsafe { (*proof_bws).len };

            // Deserialize with various combinations
            for semantic_checks in vec![true, false].into_iter() {
                println!(
                    "Compressed: {}, Semantic checks: {}",
                    compressed, semantic_checks
                );
                println!("Vk len: {}", len_vk);
                println!("Proof len: {}", len_proof);

                let total_deser_vk_time = std::time::Instant::now();
                for _ in 0..num_proofs {
                    let vk = zendoo_deserialize_sc_vk(
                        &vk_bws, semantic_checks, &mut CctpErrorCode::OK, compressed
                    );
                    assert!(vk != null_mut());
                }
                println!("Total time to deserialize {} vks: {:?}", num_proofs, total_deser_vk_time.elapsed());


                let total_deser_proof_time = std::time::Instant::now();
                for _ in 0..num_proofs {
                    let proof = zendoo_deserialize_sc_proof(
                        proof_bws, semantic_checks, &mut CctpErrorCode::OK, compressed
                    );
                    assert!(proof != null_mut());
                }
                println!("Total time to deserialize {} proofs: {:?}", num_proofs, total_deser_proof_time.elapsed());
            }

            zendoo_free_bws(proof_bws);
        }
    }
}

#[cfg(feature = "mc-test-circuit")]
#[test]
fn zendoo_batch_verifier_multiple_threads_with_priority() {

    let segment_size = 1 << 17;
    let num_proofs = 100;

    // Init DLOG keys
    println!("Setup DLOG keys...");
    assert!(zendoo_init_dlog_keys(segment_size, &mut CctpErrorCode::OK));

    for j in 15..=16 {

        // Get batch verifier
        let mut bv = ZendooBatchVerifier::create();

        // Certificate proof
        {
            let num_constraints = 1 << (j + 1);

            println!("Generating {} cert proofs with {} constraints...", num_proofs/2, num_constraints);

            // Generate SNARK keys
            println!("Generate SNARK pk and vk...");
            assert!(zendoo_generate_mc_test_params(
                TestCircuitType::Certificate,
                ProvingSystem::Darlin,
                num_constraints,
                path_as_ptr("./src/tests"),
                11,
                &mut CctpErrorCode::OK,
                true,
                true
            ));

            // Create test proof
            let sc_id = zendoo_get_random_field();
            assert!(sc_id != null_mut());

            let constant = zendoo_get_random_field();
            assert!(constant != null_mut());

            let end_cum_comm_tree_root = zendoo_get_random_field();
            assert!(end_cum_comm_tree_root != null_mut());

            let pk = zendoo_deserialize_sc_pk_from_file(
                path_as_ptr("./src/tests/darlin_cert_test_pk"),
                31,
                false,
                &mut CctpErrorCode::OK,
                true
            );
            assert!(pk != null_mut());

            println!("Generate proof...");
            let proof_buff = zendoo_create_return_cert_test_proof(
                true,
                constant,
                sc_id,
                0,
                0,
                null(),
                0,
                null(),
                0,
                end_cum_comm_tree_root,
                0,
                0,
                pk,
                num_constraints,
                &mut CctpErrorCode::OK,
                true
            );
            assert!(proof_buff != null_mut());

            let proof = zendoo_deserialize_sc_proof(proof_buff, false, &mut CctpErrorCode::OK, true);
            assert!(proof != null_mut());

            let vk = zendoo_deserialize_sc_vk_from_file(
                path_as_ptr("./src/tests/darlin_cert_test_vk"),
                31,
                false,
                &mut CctpErrorCode::OK,
                true
            );
            assert!(vk != null_mut());

            println!("Add proofs to batch verifier...");
            for i in 0..num_proofs / 2 {
                assert!(zendoo_add_certificate_proof_to_batch_verifier(
                    &mut bv,
                    i,
                    constant,
                    sc_id,
                    0,
                    0,
                    null(),
                    0,
                    null(),
                    0,
                    end_cum_comm_tree_root,
                    0,
                    0,
                    proof,
                    vk,
                    &mut CctpErrorCode::OK
                ));
            }

            // Free memory
            println!("Cleaning up...");
            zendoo_field_free(constant);
            zendoo_field_free(end_cum_comm_tree_root);
            zendoo_sc_pk_free(pk);
            zendoo_free_bws(proof_buff);
            zendoo_sc_proof_free(proof);
            zendoo_sc_vk_free(vk);
        }

        // CSW proof
        {
            let num_constraints = 1 << j;

            println!("Generating {} CSW proofs with {} constraints...", num_proofs/2, num_constraints);

            // Generate SNARK keys
            println!("Generate SNARK pk and vk...");
            assert!(zendoo_generate_mc_test_params(
                TestCircuitType::CSW,
                ProvingSystem::Darlin,
                num_constraints,
                path_as_ptr("./src/tests"),
                11,
                &mut CctpErrorCode::OK,
                true,
                true
            ));

            // Create test proof
            let sc_id = zendoo_get_random_field();
            assert!(sc_id != null_mut());

            let nullifier = zendoo_get_random_field();
            assert!(nullifier != null_mut());

            let mut mc_pk_hash = vec![0u8; 20];
            let data = mc_pk_hash.as_mut_ptr();
            let len = mc_pk_hash.len();

            let buffer = BufferWithSize { data, len };

            let cert_data_hash = zendoo_get_random_field();
            assert!(cert_data_hash != null_mut());

            let end_cum_comm_tree_root = zendoo_get_random_field();
            assert!(end_cum_comm_tree_root != null_mut());

            let pk = zendoo_deserialize_sc_pk_from_file(
                path_as_ptr("./src/tests/darlin_csw_test_pk"),
                30,
                false,
                &mut CctpErrorCode::OK,
                true
            );
            assert!(pk != null_mut());

            println!("Generate proof...");
            let proof_buff = zendoo_create_return_csw_test_proof(
                true,
                0,
                sc_id,
                nullifier,
                &buffer,
                cert_data_hash,
                end_cum_comm_tree_root,
                pk,
                num_constraints,
                &mut CctpErrorCode::OK,
                true
            );
            assert!(proof_buff != null_mut());

            let proof = zendoo_deserialize_sc_proof(proof_buff, false, &mut CctpErrorCode::OK, true);
            assert!(proof != null_mut());

            let vk = zendoo_deserialize_sc_vk_from_file(
                path_as_ptr("./src/tests/darlin_csw_test_vk"),
                30,
                false,
                &mut CctpErrorCode::OK,
                true
            );
            assert!(vk != null_mut());

            println!("Add proofs to batch verifier...");
            for i in num_proofs/2..num_proofs {
                assert!(zendoo_add_csw_proof_to_batch_verifier(
                    &mut bv,
                    i,
                    0,
                    sc_id,
                    nullifier,
                    &buffer,
                    cert_data_hash,
                    end_cum_comm_tree_root,
                    proof,
                    vk,
                    &mut CctpErrorCode::OK
                ));
            }

            // Free memory
            println!("Cleaning up...");
            zendoo_field_free(sc_id);
            zendoo_field_free(nullifier);
            zendoo_field_free(cert_data_hash);
            zendoo_field_free(end_cum_comm_tree_root);
            zendoo_sc_pk_free(pk);
            zendoo_free_bws(proof_buff);
            zendoo_sc_proof_free(proof);
            zendoo_sc_vk_free(vk);
        }

        let bv_arc = Arc::new(bv);

        // Spawn batch verification threads
        let rng = &mut thread_rng();
        let num_threads: usize = rng.gen_range(2, 11);

        println!("Perform {} separate batch verifications with different priority...", num_threads);

        // Keep generating priorities at random, until at least one thread is low priority
        // and at least one thread is high priority
        let mut priorities = (0..num_threads).map(|_| rng.gen()).collect::<Vec<bool>>();
        while priorities.iter().all(|&b| b) || priorities.iter().all(|&b| !b) {
            priorities = (0..num_threads).map(|_| rng.gen()).collect::<Vec<bool>>()
        }

        let mut handles = vec![];
        let low_priority_timings = Arc::new(RwLock::new(vec![]));
        let high_priority_timings = Arc::new(RwLock::new(vec![]));

        for i in 0..num_threads {
            let priority = priorities[i];
            let bv_ref = bv_arc.clone();
            let timings_vec_ref = if priority { high_priority_timings.clone() } else { low_priority_timings.clone() };
            let handle = std::thread::spawn(move || {
                println!("Thread {} started", i);

                // Execute batch verification and take the time
                let start = std::time::Instant::now();
                let result = zendoo_batch_verify_all_proofs(&*bv_ref, priority, &mut CctpErrorCode::OK);
                let time = start.elapsed();

                // Assert verification successfull
                unsafe { assert!((*result).result); }
                zendoo_free_batch_proof_verifier_result(result);

                println!("Thread {} finished in: {:?}", i, time);

                // Push execution time in timings vec
                timings_vec_ref.write().unwrap().push(time.as_millis());
            });
            println!("Spawned batch verification thread {} with priority {}", i, priority);
            handles.push(handle);
        }
        handles.into_iter().for_each(|handle| handle.join().unwrap());

        // Assert high priority verifications finished before low priority verifications
        assert!(
            high_priority_timings.clone().read().unwrap().iter().sum::<u128>()/high_priority_timings.clone().read().unwrap().len() as u128
                <=
            low_priority_timings.clone().read().unwrap().iter().sum::<u128>()/low_priority_timings.clone().read().unwrap().len() as u128
        );

        println!("Cleaning up...");
        std::fs::remove_file("./src/tests/darlin_cert_test_pk").unwrap();
        std::fs::remove_file("./src/tests/darlin_cert_test_vk").unwrap();
        std::fs::remove_file("./src/tests/darlin_csw_test_pk").unwrap();
        std::fs::remove_file("./src/tests/darlin_csw_test_vk").unwrap();
    }
}

#[test]
fn compress_decompress() {
    for _ in 0..10 {
        let mut bit_vector: Vec<u8> = (0..100).collect();
        let data = bit_vector.as_mut_ptr();
        let len = bit_vector.len();

        let buffer = BufferWithSize { data, len };
        let mut ret_code = CctpErrorCode::OK;
        let compressed_buffer = zendoo_compress_bit_vector(&buffer, CompressionAlgorithm::Bzip2, &mut ret_code);
        let uncompressed_buffer = zendoo_decompress_bit_vector(compressed_buffer, len, &mut ret_code);

        let processed_bit_vector = unsafe { slice::from_raw_parts((*uncompressed_buffer).data, (*uncompressed_buffer).len) };
        assert_eq!((0..100).collect::<Vec<u8>>(), processed_bit_vector);

        zendoo_free_bws(compressed_buffer);
        zendoo_free_bws(uncompressed_buffer);
    }
}