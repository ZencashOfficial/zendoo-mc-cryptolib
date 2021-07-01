use crate::{
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
}
