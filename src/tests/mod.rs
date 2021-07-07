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
        let (pk, vk) = crate::mc_test_circuits::cert::generate_parameters(ProvingSystem::Darlin, num_constraints, true).unwrap();

        println!("Generate proof...");
        let proof = crate::mc_test_circuits::cert::generate_proof(
            &pk,
            true,
            Some(&FieldElement::rand(&mut rng)),
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

/*use crate::{
    zendoo_deserialize_field,
    // zendoo_deserialize_sc_proof,
    // zendoo_verify_sc_proof,
    zendoo_serialize_field,
    //zendoo_sc_proof_free,
    zendoo_field_free,
    //backward_transfer_t,
    zendoo_field_assert_eq,
    //zendoo_deserialize_sc_vk_from_file,
    //zendoo_sc_vk_free,
    //zendoo_serialize_sc_proof,
    zendoo_init_poseidon_hash,
    zendoo_update_poseidon_hash,
    zendoo_finalize_poseidon_hash,
    zendoo_free_poseidon_hash,
    zendoo_new_ginger_mht,
    zendoo_append_leaf_to_ginger_mht,
    zendoo_get_field_from_long,
    zendoo_finalize_ginger_mht,
    zendoo_get_ginger_mht_root,
    zendoo_finalize_ginger_mht_in_place,
    zendoo_free_ginger_mht,
    zendoo_get_ginger_merkle_path,
    zendoo_verify_ginger_merkle_path,
    zendoo_free_ginger_merkle_path
};

//use std::{fmt::Debug, fs::File, ptr::null};
use std::{
    fmt::Debug,
    ptr::null
};

use algebra::{ ToBytes, to_bytes};
use algebra::{
    fields::tweedle::Fr as FieldElement
};

use std::fmt::Write;

fn field_element_to_hex_string(field_element: FieldElement) -> String {
    let mut hex_string: String = String::new();
    let field_element_bytes = to_bytes!(field_element).unwrap();

    for byte in field_element_bytes {
        write!(hex_string, "0x{:02x}, ", byte).unwrap();
    }

    // remove trailing space and comma
    hex_string.pop();
    hex_string.pop();
    hex_string
}

/*
fn bytes_32_to_hex_string(arr: [u8; 32]) -> String {
    let mut hex_string = String::from("0x");

    for x in arr.iter() {
        write!(hex_string, "{:02x?}", x).unwrap();
    }

    hex_string
}
*/

fn bytes_to_hex_string(arr: &[u8]) -> String {
    let mut hex_string: String = String::new();
    let mut bytes = Vec::<u8>::new();
    bytes.extend(&arr.to_vec());

    for x in bytes.iter() {
        write!(hex_string, "0x{:02x?}, ", x).unwrap();
    }

    // remove trailing space and comma
    hex_string.pop();
    hex_string.pop();
    hex_string
}

fn assert_slice_equals<T: Eq + Debug>(s1: &[T], s2: &[T]) {
    for (i1, i2) in s1.iter().zip(s2.iter()) {
        assert_eq!(i1, i2);
    }
}

#[cfg(target_os = "windows")]
use std::ffi::OsString;
#[cfg(target_os = "windows")]
use std::os::windows::ffi::OsStrExt;

//#[cfg(not(target_os = "windows"))]
//fn path_as_ptr(path: &str) -> *const u8 { path.as_ptr() }

#[cfg(target_os = "windows")]
fn path_as_ptr(path: &str) -> *const u16 {
    let tmp: Vec<u16> = OsString::from(path).encode_wide().collect();
    tmp.as_ptr()
}

/*
#[test]
fn verify_zkproof_test() {

    let mut file = File::open("./test_files/sample_proof").unwrap();
    let proof = Proof::<PairingCurve>::read(&mut file).unwrap();

    //Create inputs for Rust FFI function
    //Positive case
    let mut zkp = [0u8; 771];

    //Get zkp raw pointer
    proof.write(&mut zkp[..]).unwrap();
    let zkp_ptr = zendoo_deserialize_sc_proof(&zkp, true);
    let mut zkp_serialized = [0u8; 771];

    //Test proof serialization/deserialization
    zendoo_serialize_sc_proof(zkp_ptr, &mut zkp_serialized);
    assert_slice_equals(&zkp, &zkp_serialized);
    drop(zkp_serialized);

    //Inputs
    let end_epoch_mc_b_hash: [u8; 32] = [
        204, 105, 194, 216, 9, 69, 112, 49, 125, 186, 124, 147, 158, 2, 146, 250, 127, 197, 209, 248, 215, 186, 225,
        102, 132, 41, 139, 88, 243, 24, 225, 45
    ];

    let prev_end_epoch_mc_b_hash: [u8; 32] = [
        77, 107, 100, 149, 66, 133, 64, 12, 129, 179, 101, 205, 224, 222, 215, 10, 94, 82, 185, 91, 180, 22, 32, 249,
        191, 61, 233, 132, 6, 243, 175, 160
    ];

    let constant_bytes: [u8; 96] = [
        216, 139, 118, 158, 134, 237, 170, 166, 34, 216, 197, 252, 233, 45, 222, 30, 137, 228, 171, 146, 94, 23, 111,
        156, 75, 68, 89, 85, 96, 101, 93, 201, 184, 249, 10, 153, 243, 178, 182, 206, 142, 116, 96, 124, 247, 29, 209,
        33, 52, 217, 110, 145, 19, 27, 198, 93, 55, 184, 137, 54, 172, 83, 73, 255, 0, 57, 85, 59, 73, 168, 63, 79,
        143, 194, 252, 188, 20, 253, 178, 233, 138, 226, 93, 204, 3, 113, 38, 52, 212, 214, 204, 247, 87, 2, 0, 0
    ];

    let constant = zendoo_deserialize_field(&constant_bytes);
    drop(constant_bytes);

    let quality = 2;

    //Create dummy bt
    let bt_num = 10;
    let mut bt_list = vec![];
    for _ in 0..bt_num {
        bt_list.push(backward_transfer_t {
            pk_dest: [0u8; 20],
            amount: 0,
        });
    }

    //Get vk
    let vk = zendoo_deserialize_sc_vk_from_file(
        path_as_ptr("./test_files/sample_vk"),
        22,
        true
    );

    assert!(zendoo_verify_sc_proof(
        &end_epoch_mc_b_hash,
        &prev_end_epoch_mc_b_hash,
        bt_list.as_ptr(),
        bt_num,
        quality,
        constant,
        null(),
        zkp_ptr,
        vk
    ));

    //Negative test: change one of the inputs and assert verification failure

    assert!(!zendoo_verify_sc_proof(
        &end_epoch_mc_b_hash,
        &prev_end_epoch_mc_b_hash,
        bt_list.as_ptr(),
        bt_num,
        quality - 1,
        constant,
        null(),
        zkp_ptr,
        vk
    ));

    //Free memory
    zendoo_sc_proof_free(zkp_ptr);
    zendoo_sc_vk_free(vk);
    zendoo_field_free(constant);
}

#[test]
fn verify_zkproof_no_bwt_test() {

    let mut file = File::open("./test_files/sample_proof_no_bwt").unwrap();
    let proof = Proof::<PairingCurve>::read(&mut file).unwrap();

    //Create inputs for Rust FFI function
    //Positive case
    let mut zkp = [0u8; 771];

    //Get zkp raw pointer
    proof.write(&mut zkp[..]).unwrap();
    let zkp_ptr = zendoo_deserialize_sc_proof(&zkp, true);
    let mut zkp_serialized = [0u8; 771];

    //Test proof serialization/deserialization
    zendoo_serialize_sc_proof(zkp_ptr, &mut zkp_serialized);
    assert_slice_equals(&zkp, &zkp_serialized);
    drop(zkp_serialized);

    //Inputs
    let end_epoch_mc_b_hash: [u8; 32] = [
        8, 57, 79, 205, 58, 30, 190, 170, 144, 137, 231, 236, 172, 54, 173, 50, 69, 208, 163, 134,
        201, 131, 129, 223, 143, 76, 119, 48, 95, 6, 141, 17
    ];

    let prev_end_epoch_mc_b_hash: [u8; 32] = [
        172, 64, 135, 162, 30, 208, 207, 7, 107, 205, 4, 141, 230, 6, 119, 131, 112, 98, 170, 234,
        70, 66, 95, 11, 159, 178, 50, 37, 95, 187, 147, 1
    ];

    let constant_bytes: [u8; 96] = [
        53, 15, 18, 36, 121, 179, 90, 14, 215, 218, 231, 181, 9, 186, 122, 78, 227, 142, 190, 43,
        134, 218, 178, 160, 251, 246, 207, 130, 247, 53, 246, 68, 251, 126, 22, 250, 0, 135, 243,
        13, 97, 76, 166, 142, 143, 19, 69, 66, 225, 142, 210, 176, 253, 197, 145, 68, 142, 4, 96,
        91, 23, 39, 56, 43, 96, 115, 57, 59, 34, 62, 156, 221, 27, 174, 134, 170, 26, 86, 112, 176,
        126, 207, 29, 213, 99, 3, 183, 43, 191, 43, 211, 110, 177, 152, 0, 0
    ];

    let constant = zendoo_deserialize_field(&constant_bytes);
    drop(constant_bytes);

    let quality = 2;

    //Create empty bt list
    let bt_list = vec![];

    //Get vk
    let vk = zendoo_deserialize_sc_vk_from_file(
        path_as_ptr("./test_files/sample_vk_no_bwt"),
        29,
        true
    );

    assert!(zendoo_verify_sc_proof(
        &end_epoch_mc_b_hash,
        &prev_end_epoch_mc_b_hash,
        bt_list.as_ptr(),
        0,
        quality,
        constant,
        null(),
        zkp_ptr,
        vk
    ));

    //Negative test: change one of the inputs and assert verification failure

    assert!(!zendoo_verify_sc_proof(
        &end_epoch_mc_b_hash,
        &prev_end_epoch_mc_b_hash,
        bt_list.as_ptr(),
        0,
        quality - 1,
        constant,
        null(),
        zkp_ptr,
        vk
    ));

    //Free memory
    zendoo_sc_proof_free(zkp_ptr);
    zendoo_sc_vk_free(vk);
    zendoo_field_free(constant);
}

#[cfg(feature = "mc-test-circuit")]
#[test]
fn create_verify_mc_test_proof(){

    use crate::{
        zendoo_generate_mc_test_params, zendoo_get_random_field, zendoo_create_mc_test_proof,
        zendoo_deserialize_sc_proof_from_file,
    };
    use rand::rngs::OsRng;
    use rand::Rng;

    let mut rng = OsRng::default();

    //Generate params
    assert!(zendoo_generate_mc_test_params(path_as_ptr("./test_files"), 12));

    //Generate random inputs
    let end_epoch_mc_b_hash: [u8; 32] = [
        28, 207, 62, 204, 135, 33, 168, 143, 231, 177, 64, 181, 184, 237, 93, 185, 196, 115, 241,
        65, 176, 205, 254, 83, 216, 229, 119, 73, 184, 217, 26, 109
    ];

    let prev_end_epoch_mc_b_hash: [u8; 32] = [
        64, 236, 160, 62, 217, 6, 240, 243, 184, 32, 158, 223, 218, 177, 165, 121, 12, 124, 153,
        137, 218, 208, 152, 125, 187, 145, 172, 244, 223, 220, 234, 195
    ];

    let quality: u64 = rng.gen();

    let bt_num: usize = rng.gen_range(0, 11);
    let mut bt_list = vec![];
    for _ in 0..bt_num {
        bt_list.push(backward_transfer_t {
            pk_dest: [0u8; 20],
            amount: 0,
        });
    }

    let constant = zendoo_get_random_field();

    let pk_path = path_as_ptr("./test_files/test_mc_pk");
    let proof_path = path_as_ptr("./test_files/test_mc_proof");

    //Create proof
    assert!(zendoo_create_mc_test_proof(
        &end_epoch_mc_b_hash,
        &prev_end_epoch_mc_b_hash,
        bt_list.as_ptr(),
        bt_num,
        quality,
        constant,
        pk_path,
        23,
        proof_path,
        26
    ));

    //Verify proof

    //Get vk
    let vk = zendoo_deserialize_sc_vk_from_file(
        path_as_ptr("./test_files/test_mc_vk"),
        23,
        true,
    );

    //Get proof
    let proof = zendoo_deserialize_sc_proof_from_file(
        path_as_ptr("./test_files/test_mc_proof"),
        26
    );

    assert!(zendoo_verify_sc_proof(
        &end_epoch_mc_b_hash,
        &prev_end_epoch_mc_b_hash,
        bt_list.as_ptr(),
        bt_num,
        quality,
        constant,
        null(),
        proof,
        vk
    ));

    //Negative test: change one of the inputs and assert verification failure

    assert!(!zendoo_verify_sc_proof(
        &end_epoch_mc_b_hash,
        &prev_end_epoch_mc_b_hash,
        bt_list.as_ptr(),
        bt_num,
        quality - 1,
        constant,
        null(),
        proof,
        vk
    ));
}
*/

#[test]
fn merkle_tree_test() {
    let height = 5;
    let expected_root_bytes: [u8; 32] = [
        0x5d, 0x60, 0x0c, 0x9b, 0x61, 0x31, 0x4c, 0xf8, 0xa1, 0x7d, 0x09, 0x30, 0xf6, 0x6e, 0x69, 0x47,
        0x72, 0x61, 0xe1, 0x80, 0xc8, 0x53, 0x42, 0xeb, 0xd6, 0x74, 0x60, 0xf0, 0x09, 0xe4, 0x70, 0x23
    ];
    println!("expected_root_bytes: : {}", bytes_to_hex_string( &(&expected_root_bytes)[..]));
    let expected_root = zendoo_deserialize_field(&expected_root_bytes);

    // Generate leaves
    let leaves_len = 32;
    let mut leaves = vec![];
    for i in 0..leaves_len {
        leaves.push(zendoo_get_field_from_long(i as u64));
    }

    // Create tree
    let tree = zendoo_new_ginger_mht(height, leaves_len);

    // Add leaves to tree
    for &leaf in leaves.iter(){
        zendoo_append_leaf_to_ginger_mht(leaf, tree);
    }

    // Finalize tree and assert root equality
    zendoo_finalize_ginger_mht_in_place(tree);
    let root = zendoo_get_ginger_mht_root(tree);
    println!("Computed root: {}", field_element_to_hex_string(unsafe{*root}));
    assert!(zendoo_field_assert_eq(root, expected_root));

    // It is the same by calling zendoo_finalize_ginger_mht
    let tree_copy = zendoo_finalize_ginger_mht(tree);
    let root_copy = zendoo_get_ginger_mht_root(tree_copy);
    assert!(zendoo_field_assert_eq(root, root_copy));

    //Test merkle paths
    for (i, leaf) in leaves.clone().into_iter().skip(500).enumerate() {
        let path = zendoo_get_ginger_merkle_path(tree, i);
        assert!(zendoo_verify_ginger_merkle_path(path, height, leaf, root));
        zendoo_free_ginger_merkle_path(path);
    }

    // Free memory
    zendoo_field_free(expected_root);
    for leaf in leaves.into_iter(){
        zendoo_field_free(leaf);
    }
    zendoo_free_ginger_mht(tree);
    zendoo_field_free(root);

    zendoo_free_ginger_mht(tree_copy);
    zendoo_field_free(root_copy);
}

#[test]
fn poseidon_hash_test() {
    let lhs: [u8; 32] = [
        0x8a, 0xce, 0xc7, 0xf3, 0xc3, 0xfe, 0x19, 0x5e, 0xec, 0x9b, 0xe8, 0xb6, 0x59, 0x7b, 0xa2, 0xcf,
        0x66, 0x34, 0xb2, 0x80, 0x37, 0xf8, 0xea, 0x5f, 0x21, 0xc4, 0xaa, 0x0c, 0x76, 0x10, 0x00, 0x00
    ];

    let rhs: [u8; 32] = [
        0xc7, 0x82, 0xeb, 0x34, 0x2c, 0xdb, 0x05, 0xc3, 0x47, 0x9a, 0x36, 0x79, 0x03, 0x0b, 0x6f, 0xa0,
        0x56, 0xd4, 0xbd, 0x42, 0xeb, 0xec, 0xf0, 0xf2, 0x7e, 0xf8, 0x74, 0x00, 0x00, 0x00, 0x00, 0x00
    ];

    println!("lhs : {}", bytes_to_hex_string( &(&lhs)[..]));
    println!("rhs : {}", bytes_to_hex_string( &(&rhs)[..]));

    let hash: [u8; 32] = [
        0x99, 0x78, 0x7f, 0x27, 0x55, 0xb6, 0xfa, 0xf4, 0x2c, 0xa6, 0x63, 0x27, 0x93, 0xe9, 0x5c, 0x5d,
        0x67, 0xa5, 0x5e, 0x5c, 0x90, 0x40, 0xbf, 0xb2, 0x4c, 0x31, 0xbe, 0xb9, 0x77, 0x1b, 0xa4, 0x26
    ];

    let lhs_field = zendoo_deserialize_field(&lhs);
    let rhs_field = zendoo_deserialize_field(&rhs);
    let expected_hash = zendoo_deserialize_field(&hash);

    //Test field serialization/deserialization
    let mut lhs_serialized = [0u8; 32];
    zendoo_serialize_field(lhs_field, &mut lhs_serialized);
    assert_slice_equals(&lhs, &lhs_serialized);
    drop(lhs_serialized);

    let uh = zendoo_init_poseidon_hash(null(), 0);

    // Call to finalize keeps the state untouched
    zendoo_update_poseidon_hash(lhs_field, uh);
    let temp_hash = zendoo_finalize_poseidon_hash(uh);
    zendoo_update_poseidon_hash(rhs_field, uh);

    let actual_hash = zendoo_finalize_poseidon_hash(uh);
    println!("Computed hash: {}", field_element_to_hex_string(unsafe{*actual_hash}));
    println!("Expected hash: {}", field_element_to_hex_string(unsafe{*expected_hash}));
    assert!(zendoo_field_assert_eq(actual_hash, expected_hash));
    zendoo_field_free(actual_hash);

    // finalize() is idempotent
    let actual_hash_2 = zendoo_finalize_poseidon_hash(uh);
    println!("Computed hash: {}", field_element_to_hex_string(unsafe{*actual_hash_2}));
    println!("Expected hash: {}", field_element_to_hex_string(unsafe{*expected_hash}));
    assert!(zendoo_field_assert_eq(actual_hash_2, expected_hash));
    zendoo_field_free(actual_hash_2);

    zendoo_free_poseidon_hash(uh);
    zendoo_field_free(expected_hash);
    zendoo_field_free(temp_hash);

    zendoo_field_free(lhs_field);
    zendoo_field_free(rhs_field);
}*/
