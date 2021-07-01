#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN

#include "zendoo_mc.h"
#include "doctest.h"
#include <stdio.h>
#include <iostream>
#include <fstream>
#include <cstring>
#include <string>
#include <cassert>
#include <vector>
#include <time.h>

TEST_SUITE("Field Element") {

    TEST_CASE("Field Size") {
        int field_len = zendoo_get_field_size_in_bytes();
        CHECK(field_len == FIELD_SIZE);
    }

    TEST_CASE("Positive serialize/deserialize"){
        CctpErrorCode ret_code = CctpErrorCode::OK;

        // Check correct serialization
        auto field = zendoo_get_random_field();

        //Serialize and deserialize and check equality
        unsigned char field_bytes[FIELD_SIZE];
        zendoo_serialize_field(field, field_bytes, &ret_code);
        CHECK(ret_code == CctpErrorCode::OK);

        // Check correct deserialization
        auto field_deserialized = zendoo_deserialize_field(field_bytes, &ret_code);
        CHECK(ret_code == CctpErrorCode::OK);

        // Check equality
        CHECK(zendoo_field_assert_eq(field, field_deserialized));

        zendoo_field_free(field);
        zendoo_field_free(field_deserialized);
    }

    TEST_CASE("Negative serialize/deserialize"){
        CctpErrorCode ret_code = CctpErrorCode::OK;

        //Serialize and deserialize and check equality
        unsigned char field_bytes[FIELD_SIZE] = {
            64, 192, 222, 36, 97, 22, 129, 41, 101, 218, 34, 193, 41, 200, 74, 248,
            126, 226, 209, 85, 85, 50, 64, 27, 23, 69, 240, 210, 79, 85, 196, 3
        };

        // Check correct deserialization
        auto correct_field_deserialized = zendoo_deserialize_field(field_bytes, &ret_code);
        CHECK(ret_code == CctpErrorCode::OK);

        // Modify a byte of field_bytes and deserialize
        field_bytes[0] = 0;
        auto wrong_field_deserialized = zendoo_deserialize_field(field_bytes, &ret_code);

        // Check equality
        CHECK_FALSE(zendoo_field_assert_eq(correct_field_deserialized, wrong_field_deserialized));

        // Free memory
        zendoo_field_free(correct_field_deserialized);
        zendoo_field_free(wrong_field_deserialized);
    }

    TEST_CASE("Edge cases serialize/deserialize"){
        CctpErrorCode ret_code = CctpErrorCode::OK;

        // Attempt to deserialize a field element over the modulus
        unsigned char over_the_modulus_fe[FIELD_SIZE] = {
            255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255
        };
        auto field_deserialized = zendoo_deserialize_field(over_the_modulus_fe, &ret_code);
        CHECK(field_deserialized == NULL);
        CHECK(ret_code == CctpErrorCode::InvalidValue);

        zendoo_field_free(field_deserialized);
    }
}

TEST_SUITE("Poseidon Hash") {

    static const unsigned char expected_result_bytes[FIELD_SIZE] = {
        254, 126, 175, 176, 130, 2, 161, 183, 90, 48, 41, 150, 100, 148, 142, 37,
        122, 246, 6, 134, 190, 158, 5, 195, 112, 148, 148, 144, 106, 91, 234, 5
    };

    TEST_CASE("Constant Length Poseidon Hash") {
        CctpErrorCode ret_code = CctpErrorCode::OK;

        // Init digest
        auto digest = ZendooPoseidonHashConstantLength(2, &ret_code);
        CHECK(ret_code == CctpErrorCode::OK);

        //Update with 1 field element
        auto lhs = zendoo_get_field_from_long(1);
        digest.update(lhs, &ret_code);
        CHECK(ret_code == CctpErrorCode::OK);

        // Trying to finalize without having reached the
        // specified input size will cause an error
        auto result_before = digest.finalize(&ret_code);
        CHECK(result_before == NULL);
        CHECK(ret_code == CctpErrorCode::HashingError);

        // Update with 1 field element
        auto rhs = zendoo_get_field_from_long(2);
        digest.update(rhs, &ret_code);
        CHECK(ret_code == CctpErrorCode::OK);

        // Finalize hash
        auto result = digest.finalize(&ret_code);
        CHECK(ret_code == CctpErrorCode::OK);

        // Check result is equal to the expected one
        auto expected_result = zendoo_deserialize_field(expected_result_bytes, &ret_code);
        CHECK(ret_code == CctpErrorCode::OK);
        CHECK(zendoo_field_assert_eq(result, expected_result));

        // Finalize is idempotent
        auto result_copy = digest.finalize(&ret_code);
        CHECK(ret_code == CctpErrorCode::OK);
        CHECK(zendoo_field_assert_eq(result, result_copy));

        // Update once and more and assert that trying to finalize with more
        // inputs than the ones specified at creation will result in an error.
        auto additional_input = zendoo_get_field_from_long(3);
        digest.update(additional_input, &ret_code);
        CHECK(ret_code == CctpErrorCode::OK);

        auto result_after = digest.finalize(&ret_code);
        CHECK(result_after == NULL);
        CHECK(ret_code == CctpErrorCode::HashingError);

        // Free memory
        zendoo_field_free(lhs);
        zendoo_field_free(rhs);
        zendoo_field_free(result);
        zendoo_field_free(expected_result);
        zendoo_field_free(result_copy);
        zendoo_field_free(additional_input);

        // Once out of scope the destructor of ZendooPoseidonHash will automatically free the memory Rust-side
        // for digest
    }

    TEST_CASE("Variable Length Poseidon Hash mod rate") {
        CctpErrorCode ret_code = CctpErrorCode::OK;

        // Init digest
        auto digest = ZendooPoseidonHashVariableLength(true, &ret_code);
        CHECK(ret_code == CctpErrorCode::OK);

        //Update with 1 field element
        auto lhs = zendoo_get_field_from_long(1);
        digest.update(lhs, &ret_code);
        CHECK(ret_code == CctpErrorCode::OK);

        // Trying to finalize with an input size non mod rate
        // will result in an error
        auto result_before = digest.finalize(&ret_code);
        CHECK(result_before == NULL);
        CHECK(ret_code == CctpErrorCode::HashingError);

        // Update with 1 field element
        auto rhs = zendoo_get_field_from_long(2);
        digest.update(rhs, &ret_code);
        CHECK(ret_code == CctpErrorCode::OK);

        // Finalize hash
        auto result = digest.finalize(&ret_code);
        CHECK(ret_code == CctpErrorCode::OK);

        // Check result is equal to the expected one.
        // Result is also the same of the constant length poseidon hash
        // (no unnecessary padding is added)
        auto expected_result = zendoo_deserialize_field(expected_result_bytes, &ret_code);
        CHECK(ret_code == CctpErrorCode::OK);
        CHECK(zendoo_field_assert_eq(result, expected_result));

        // Finalize is idempotent
        auto result_copy = digest.finalize(&ret_code);
        CHECK(ret_code == CctpErrorCode::OK);
        CHECK(zendoo_field_assert_eq(result, result_copy));

        // Update once and more and assert that trying to finalize
        // with an input non mod rate will result in an error
        auto additional_input = zendoo_get_field_from_long(3);
        digest.update(additional_input, &ret_code);
        CHECK(ret_code == CctpErrorCode::OK);

        auto result_after = digest.finalize(&ret_code);
        CHECK(result_after == NULL);
        CHECK(ret_code == CctpErrorCode::HashingError);

        // Free memory
        zendoo_field_free(lhs);
        zendoo_field_free(rhs);
        zendoo_field_free(result);
        zendoo_field_free(expected_result);
        zendoo_field_free(result_copy);
        zendoo_field_free(additional_input);

        // Once out of scope the destructor of ZendooPoseidonHash will automatically free the memory Rust-side
        // for digest
    }

    TEST_CASE("Variable Length Poseidon Hash NON mod rate") {
        CctpErrorCode ret_code = CctpErrorCode::OK;

        unsigned char expected_result_bytes_variable_length[FIELD_SIZE] = {
            212, 129, 183, 174, 117, 46, 61, 128, 124, 74, 158, 233, 177, 251, 225, 0,
            99, 148, 140, 105, 239, 1, 217, 66, 106, 133, 62, 197, 131, 215, 206, 28
        };

        // Init digest
        auto digest = ZendooPoseidonHashVariableLength(false, &ret_code);
        CHECK(ret_code == CctpErrorCode::OK);

        //Update with 1 field element
        auto lhs = zendoo_get_field_from_long(1);
        digest.update(lhs, &ret_code);
        CHECK(ret_code == CctpErrorCode::OK);

        // It's possible to finalize in any moment (padding will be performed)
        auto result_before = digest.finalize(&ret_code);
        CHECK(result_before != NULL);
        CHECK(ret_code == CctpErrorCode::OK);

        // Update with 1 field element
        auto rhs = zendoo_get_field_from_long(2);
        digest.update(rhs, &ret_code);
        CHECK(ret_code == CctpErrorCode::OK);

        // Finalize hash
        auto result = digest.finalize(&ret_code);
        CHECK(ret_code == CctpErrorCode::OK);

        // Check result is equal to the expected one.
        auto expected_result = zendoo_deserialize_field(expected_result_bytes_variable_length, &ret_code);
        CHECK(ret_code == CctpErrorCode::OK);
        CHECK(zendoo_field_assert_eq(result, expected_result));

        // Finalize is idempotent
        auto result_copy = digest.finalize(&ret_code);
        CHECK(ret_code == CctpErrorCode::OK);
        CHECK(zendoo_field_assert_eq(result, result_copy));

        // It's possible to finalize in any moment (padding will be performed)
        auto additional_input = zendoo_get_field_from_long(3);
        digest.update(additional_input, &ret_code);
        CHECK(ret_code == CctpErrorCode::OK);

        auto result_after = digest.finalize(&ret_code);
        CHECK(result_after != NULL);
        CHECK(ret_code == CctpErrorCode::OK);

        // Free memory
        zendoo_field_free(lhs);
        zendoo_field_free(rhs);
        zendoo_field_free(result_before);
        zendoo_field_free(result);
        zendoo_field_free(expected_result);
        zendoo_field_free(result_copy);
        zendoo_field_free(result_after);
        zendoo_field_free(additional_input);

        // Once out of scope the destructor of ZendooPoseidonHash will automatically free the memory Rust-side
        // for digest
    }
}

TEST_CASE("Merkle Tree") {
    size_t height = 5;
    CctpErrorCode ret_code = CctpErrorCode::OK;

    // Deserialize root
    unsigned char expected_root_bytes[FIELD_SIZE] = {
        113, 174, 41, 1, 227, 14, 47, 27, 44, 172, 21, 18, 63, 182, 174, 162, 239, 251,
        93, 88, 43, 221, 235, 253, 30, 110, 180, 114, 134, 192, 15, 20
    };
    auto expected_root = zendoo_deserialize_field(expected_root_bytes, &ret_code);
    CHECK(ret_code == CctpErrorCode::OK);

    //Generate leaves
    int leaves_len = 32;
    const field_t* leaves[leaves_len];
    for (int i = 0; i < leaves_len; i++){
        leaves[i] = zendoo_get_field_from_long(i);
    }

    // Initialize tree
    auto tree = ZendooGingerMerkleTree(height, leaves_len);

    // Add leaves to tree
    for (int i = 0; i < leaves_len; i++){
        tree.append(leaves[i], &ret_code);
        CHECK(ret_code == CctpErrorCode::OK);
    }

    // Adding more leaves than the tree size should result in an error
    tree.append(leaves[0], &ret_code);
    CHECK(ret_code == CctpErrorCode::MerkleTreeError);

    // Asking for the root of a non-finalized tree should result in an error
    auto null_root = tree.root(&ret_code);
    CHECK(null_root == NULL);
    CHECK(ret_code == CctpErrorCode::MerkleRootBuildError);

    // Asking for a merkle path  of a non-finalized tree should result in an error
    auto path = tree.get_merkle_path(0, &ret_code);
    CHECK(path == NULL);
    CHECK(ret_code == CctpErrorCode::MerkleTreeError);

    // Finalize tree
    tree.finalize_in_place(&ret_code);
    CHECK(ret_code == CctpErrorCode::OK);

    // Compute root and assert equality with expected one
    auto root = tree.root(&ret_code);
    CHECK(ret_code == CctpErrorCode::OK);
    CHECK(zendoo_field_assert_eq(root, expected_root));

    // It is the same by calling finalize()
    auto tree_copy = tree.finalize(&ret_code);
    CHECK(ret_code == CctpErrorCode::OK);

    auto root_copy = tree_copy.root(&ret_code);
    CHECK(ret_code == CctpErrorCode::OK);

    CHECK(zendoo_field_assert_eq(root_copy, root));

    auto wrong_root = zendoo_get_random_field();

    // Test Merkle Paths
    for (int i = 0; i < leaves_len; i++) {

        // Get Merkle Path
        auto path = tree.get_merkle_path(i, &ret_code);
        CHECK(ret_code == CctpErrorCode::OK);

        // Verify Merkle Path
        CHECK(zendoo_verify_ginger_merkle_path(path, height, (field_t*)leaves[i], root, &ret_code));
        CHECK(ret_code == CctpErrorCode::OK);

        // Negative test: verify MerklePath for a wrong root and assert failure
        CHECK_FALSE(zendoo_verify_ginger_merkle_path(path, height, (field_t*)leaves[i], wrong_root, &ret_code));
        CHECK(ret_code == CctpErrorCode::OK);

        zendoo_free_ginger_merkle_path(path);
    }

    // Free memory
    for (int i = 0; i < leaves_len; i++){
        zendoo_field_free((field_t*)leaves[i]);
    }
    zendoo_field_free(root);
    zendoo_field_free(root_copy);
    zendoo_field_free(expected_root);
    zendoo_field_free(wrong_root);

    // Once out of scope the destructor of ZendooGingerMerkleTree will automatically free
    // the memory Rust-side for tree and tree_copy
}

void check_root(unsigned char expected_root_bytes[], field_t* actual_root) {
    CctpErrorCode ret_code = CctpErrorCode::OK;
    auto expected_root = zendoo_deserialize_field(expected_root_bytes, &ret_code);
    CHECK(ret_code == CctpErrorCode::OK);
    CHECK(zendoo_field_assert_eq(expected_root, actual_root));
    zendoo_field_free(expected_root);
    zendoo_field_free(actual_root);
}

TEST_CASE("Commitment Tree") {
    CctpErrorCode ret_code = CctpErrorCode::OK;

    // Get commitment tree instance
    auto cmt = zendoo_commitment_tree_create();

    // Test empty tree root
    auto empty_root = zendoo_commitment_tree_get_commitment(cmt, &ret_code);
    CHECK(empty_root != NULL);
    CHECK(ret_code == CctpErrorCode::OK);

    unsigned char expected_empty_root_bytes[FIELD_SIZE] = {
        102, 212, 1, 47, 102, 212, 117, 139, 51, 210, 40, 137, 149, 110, 212, 157,
        149, 193, 18, 216, 145, 99, 127, 83, 230, 240, 0, 196, 108, 233, 101, 13
    };
    check_root(expected_empty_root_bytes, empty_root);

    // Add SCC with random data
    auto sc_id = zendoo_get_field_from_long(1);

    uint64_t amount = 100;
    uint64_t btr_fee = 1000;
    uint64_t ft_min_amount = 5000;
    uint32_t out_idx = 2;
    uint32_t withdrawal_epoch_length = 10;
    uint8_t  mc_btr_request_data_length = 255;

    std::vector<unsigned char> pub_key_vec(FIELD_SIZE, 255);
    auto pub_key = BufferWithSize(pub_key_vec.data(), pub_key_vec.size());

    std::vector<unsigned char> tx_hash_vec(FIELD_SIZE, 255);
    auto tx_hash = BufferWithSize(tx_hash_vec.data(), tx_hash_vec.size());

    std::vector<unsigned char> custom_field_elements_config_vec(5, 1);
    auto custom_field_elements_config = BufferWithSize(custom_field_elements_config_vec.data(), custom_field_elements_config_vec.size());

    size_t custom_bv_elements_config_len = 10;
    const BitVectorElementsConfig custom_bv_elements_config[custom_bv_elements_config_len] = { {2000, 1500} };

    std::vector<unsigned char> custom_creation_data_vec(7, 10);
    auto custom_creation_data = BufferWithSize(custom_creation_data_vec.data(), custom_creation_data_vec.size());

    std::vector<unsigned char> cert_vk_vec(2000, 222);
    auto cert_vk = BufferWithSize(cert_vk_vec.data(), cert_vk_vec.size());

    CHECK(zendoo_commitment_tree_add_scc(
        cmt, sc_id, amount, &pub_key, &tx_hash, out_idx, withdrawal_epoch_length,
        mc_btr_request_data_length, &custom_field_elements_config,
        custom_bv_elements_config, custom_bv_elements_config_len,
        btr_fee, ft_min_amount, &custom_creation_data, NULL,
        &cert_vk, NULL, &ret_code
    ) == true);
    CHECK(ret_code == CctpErrorCode::OK);

    // Test root after add scc
    auto root_after_scc = zendoo_commitment_tree_get_commitment(cmt, &ret_code);
    CHECK(root_after_scc != NULL);
    CHECK(ret_code == CctpErrorCode::OK);

    unsigned char expected_root_after_scc_bytes[FIELD_SIZE] = {
        166, 173, 139, 78, 105, 234, 68, 33, 65, 9, 233, 183, 187, 254, 31, 32,
        108, 89, 112, 235, 163, 14, 114, 28, 58, 169, 97, 183, 11, 168, 106, 63
    };
    check_root(expected_root_after_scc_bytes, root_after_scc);

    // Add fwt with random data
    CHECK(zendoo_commitment_tree_add_fwt(cmt, sc_id, amount, &pub_key, &tx_hash, out_idx, &ret_code) == true);
    CHECK(ret_code == CctpErrorCode::OK);

    // Test root after add fwt
    auto root_after_fwt = zendoo_commitment_tree_get_commitment(cmt, &ret_code);
    CHECK(root_after_fwt != NULL);
    CHECK(ret_code == CctpErrorCode::OK);

    unsigned char expected_root_after_fwt_bytes[FIELD_SIZE] = {
        123, 21, 251, 209, 124, 131, 1, 181, 252, 63, 177, 254, 229, 162, 6, 238,
        78, 249, 207, 112, 48, 46, 36, 96, 248, 119, 84, 57, 74, 229, 233, 26
    };
    check_root(expected_root_after_fwt_bytes, root_after_fwt);

    // Add bwtr with random data
    uint64_t sc_fee = 3333;
    auto nullifier = zendoo_get_field_from_long(2);
    auto end_cum_comm_tree_root = zendoo_get_field_from_long(3);

    std::vector<unsigned char> mc_pk_hash_vec(MC_PK_SIZE, 200);
    auto mc_pk_hash = BufferWithSize(mc_pk_hash_vec.data(), mc_pk_hash_vec.size());

    const field_t* sc_req_data[] = {sc_id, nullifier, end_cum_comm_tree_root};
    CHECK(zendoo_commitment_tree_add_bwtr(cmt, sc_id, sc_fee, sc_req_data, 3, &mc_pk_hash, &tx_hash, out_idx, &ret_code) == true);
    CHECK(ret_code == CctpErrorCode::OK);

    // Test root after add bwtr
    auto root_after_bwtr = zendoo_commitment_tree_get_commitment(cmt, &ret_code);
    CHECK(root_after_bwtr != NULL);
    CHECK(ret_code == CctpErrorCode::OK);

    unsigned char expected_root_after_bwtr_bytes[FIELD_SIZE] = {
        226, 210, 246, 128, 123, 182, 167, 110, 139, 14, 222, 105, 246, 78, 186, 180,
        190, 223, 145, 188, 185, 199, 236, 226, 103, 240, 164, 131, 32, 30, 211, 26
    };
    check_root(expected_root_after_bwtr_bytes, root_after_bwtr);

    // Add csw with random data
    auto new_sc_id = zendoo_get_field_from_long(5); //use new sc_id for csw (it's part of sc_tree_ceased)
    CHECK(zendoo_commitment_tree_add_csw(cmt, new_sc_id, amount, nullifier, &mc_pk_hash, &ret_code) == true);
    CHECK(ret_code == CctpErrorCode::OK);

    // Test root after add csw
    auto root_after_csw = zendoo_commitment_tree_get_commitment(cmt, &ret_code);
    CHECK(root_after_csw != NULL);
    CHECK(ret_code == CctpErrorCode::OK);

    unsigned char expected_root_after_csw_bytes[FIELD_SIZE] = {
        175, 83, 101, 147, 40, 13, 196, 37, 12, 98, 50, 94, 179, 101, 47, 16, 11,
        147, 119, 27, 52, 188, 128, 101, 210, 146, 56, 209, 51, 128, 158, 34
    };
    check_root(expected_root_after_csw_bytes, root_after_csw);

    // Add cert with random data
    uint32_t epoch_number = 10;
    uint64_t quality = 4444;
    size_t bt_list_len = 10;
    std::vector<backward_transfer_t> bt_list;
    if (bt_list_len != 0) {
        for(int i = 0; i < bt_list_len; i++){
            bt_list.push_back({{255}, 10});
        }
    }
    CHECK(zendoo_commitment_tree_add_cert(
        cmt, sc_id, epoch_number, quality, bt_list.data(), bt_list_len, NULL, 0,
        end_cum_comm_tree_root, btr_fee, ft_min_amount, &ret_code
    ) == true);
    CHECK(ret_code == CctpErrorCode::OK);

    // Test root after add cert
    auto root_after_cert = zendoo_commitment_tree_get_commitment(cmt, &ret_code);
    CHECK(root_after_cert != NULL);
    CHECK(ret_code == CctpErrorCode::OK);

    unsigned char expected_root_after_cert_bytes[FIELD_SIZE] = {
        152, 182, 153, 190, 231, 46, 36, 235, 71, 85, 229, 218, 139, 153, 82, 151,
        109, 110, 163, 4, 67, 104, 185, 240, 112, 49, 168, 58, 63, 76, 27, 26
    };
    check_root(expected_root_after_cert_bytes, root_after_cert);

    zendoo_field_free(sc_id);
    zendoo_field_free(new_sc_id);
    zendoo_field_free(nullifier);
    zendoo_field_free(end_cum_comm_tree_root);
}

TEST_SUITE("Bit Vector") {
    void compress_decompress(CompressionAlgorithm algo) {
        CctpErrorCode ret_code = CctpErrorCode::OK;

        // Generate test data
        //2^12 * 254 = 130048 bytes
        int bit_vec_dim = 130048;
        std::vector<unsigned char> bit_vec(bit_vec_dim , 111);
        auto bit_vec_bwt = BufferWithSize(bit_vec.data(), bit_vec.size());

        // Compress bit vec
        auto compressed_bit_vec_bwt = zendoo_compress_bit_vector(&bit_vec_bwt, algo, &ret_code);
        CHECK(compressed_bit_vec_bwt != NULL);
        CHECK(ret_code == CctpErrorCode::OK);

        // Get root from compressed bytes
        auto root = zendoo_merkle_root_from_compressed_bytes(compressed_bit_vec_bwt, bit_vec_dim, &ret_code);
        unsigned char expected_root[FIELD_SIZE] = {
            108, 210, 228, 91, 128, 218, 226, 40, 27, 129, 78, 6, 2, 4, 217,
            120, 17, 147, 56, 236, 6, 120, 85, 112, 229, 38, 56, 227, 56, 16, 109, 34
        };
        check_root(expected_root, root);

        // Decompress bit vec
        auto decompressed_bit_vec_bwt = zendoo_decompress_bit_vector(compressed_bit_vec_bwt, bit_vec_dim, &ret_code);
        CHECK(decompressed_bit_vec_bwt != NULL);
        CHECK(ret_code == CctpErrorCode::OK);

        // Check equality
        for (int i = 0; i < bit_vec_dim; i++){
            if (bit_vec_bwt.data[i] != decompressed_bit_vec_bwt->data[i]) {
                CHECK(false); // Fail
            }
        }

        // Free memory
        zendoo_free_bws(compressed_bit_vec_bwt);
        zendoo_free_bws(decompressed_bit_vec_bwt);
    }

    TEST_CASE("Compress/Decompress") {
        compress_decompress(CompressionAlgorithm::Gzip);
        compress_decompress(CompressionAlgorithm::Bzip2);
    }
}

TEST_SUITE("Single Proof Verifier") {

    static std::string params_dir = std::string("../examples");
    static size_t params_dir_len = params_dir.size();

    bool initDlogKeys() {
        CctpErrorCode ret_code = CctpErrorCode::OK;

        // Bootstrap keys
        bool init_result = zendoo_init_dlog_keys(
            1 << 9,
            (path_char_t*)params_dir.c_str(),
            params_dir_len,
            &ret_code
        );
        CHECK(init_result == true);
        CHECK(ret_code == CctpErrorCode::OK);
    }

    void create_verify_cert_proof(
        size_t numBt,
        bool zk,
        std::string proof_path,
        std::string pk_path,
        std::string vk_path
    ) {
        CctpErrorCode ret_code = CctpErrorCode::OK;

        // Generate random data
        auto constant = zendoo_get_field_from_long(1);
        auto end_cum_comm_tree_root = zendoo_get_field_from_long(2);
        uint32_t epoch_number = 10;
        uint64_t quality = 100;
        uint64_t btr_fee = 1000;
        uint64_t ft_min_amount = 5000;

        //Create dummy bt list
        size_t bt_list_len = numBt;
        std::vector<backward_transfer_t> bt_list;
        if (bt_list_len != 0) {
            for(int i = 0; i < bt_list_len; i++){
                bt_list.push_back({{255}, 10});
            }
        }

        // Create dummy custom_fields re-using fields we already have
        const field_t* custom_fields[] = {constant, end_cum_comm_tree_root};

        // Specify paths
        auto sc_pk = zendoo_deserialize_sc_pk_from_file(
            (path_char_t*)pk_path.c_str(),
            pk_path.size(),
            true,
            &ret_code
        );
        CHECK(sc_pk != NULL);
        CHECK(ret_code == CctpErrorCode::OK);

        CHECK(
            zendoo_create_cert_test_proof(
                zk, constant, epoch_number, quality, bt_list.data(), bt_list_len,
                custom_fields, 2, end_cum_comm_tree_root, btr_fee, ft_min_amount,
                sc_pk, (path_char_t*)proof_path.c_str(), proof_path.size(), &ret_code
            ) == true
        );
        CHECK(ret_code == CctpErrorCode::OK);

        // Verify proof with correct data

        auto sc_proof = zendoo_deserialize_sc_proof_from_file(
            (path_char_t*)proof_path.c_str(),
            proof_path.size(),
            true,
            &ret_code
        );
        CHECK(sc_proof != NULL);
        CHECK(ret_code == CctpErrorCode::OK);

        auto sc_vk = zendoo_deserialize_sc_vk_from_file(
            (path_char_t*)vk_path.c_str(),
            vk_path.size(),
            true,
            &ret_code
        );
        CHECK(sc_vk != NULL);
        CHECK(ret_code == CctpErrorCode::OK);

        // Positive verification
        CHECK(
            zendoo_verify_certificate_proof(
                constant, epoch_number, quality, bt_list.data(), bt_list_len,
                custom_fields, 2, end_cum_comm_tree_root,
                btr_fee, ft_min_amount, sc_proof, sc_vk, &ret_code
            ) == true
        );
        CHECK(ret_code == CctpErrorCode::OK);

        // Negative verification
        auto wrong_constant = zendoo_get_field_from_long(2);
        CHECK(
            zendoo_verify_certificate_proof(
                wrong_constant, epoch_number, quality, bt_list.data(), bt_list_len,
                custom_fields, 2, end_cum_comm_tree_root, btr_fee, ft_min_amount,
                sc_proof, sc_vk, &ret_code
            ) == false
        );
        CHECK(ret_code == CctpErrorCode::OK);

        // Free memory
        zendoo_field_free(constant);
        zendoo_field_free(wrong_constant);
        zendoo_field_free(end_cum_comm_tree_root);
        zendoo_sc_pk_free(sc_pk);
        zendoo_sc_vk_free(sc_vk);
        zendoo_sc_proof_free(sc_proof);

        // Destroy proof file
        remove(proof_path.c_str());
    }

    TEST_CASE("Proof Verifier: Cert - Coboundary Marlin") {
        CctpErrorCode ret_code = CctpErrorCode::OK;

        // Init keys
        initDlogKeys();

        // Generate cert test circuit pk and vk
        CHECK(
            zendoo_generate_mc_test_params(
                TestCircuitType::Certificate,
                ProvingSystem::CoboundaryMarlin,
                (path_char_t*)params_dir.c_str(),
                params_dir_len,
                &ret_code
            ) == true
        );
        CHECK(ret_code == CctpErrorCode::OK);

        auto proof_path = params_dir + std::string("/cob_marlin_cert_test_proof");
        auto pk_path = params_dir + std::string("/cob_marlin_cert_test_pk");
        auto vk_path = params_dir + std::string("/cob_marlin_cert_test_vk");

        // Test all cases
        create_verify_cert_proof(10, true, proof_path, pk_path, vk_path);
        create_verify_cert_proof(0, true, proof_path, pk_path, vk_path);
        create_verify_cert_proof(10, false, proof_path, pk_path, vk_path);
        create_verify_cert_proof(0, false, proof_path, pk_path, vk_path);

        // Delete files
        remove(pk_path.c_str());
        remove(vk_path.c_str());
    }

    TEST_CASE("Proof Verifier: Cert - Darlin") {
       CctpErrorCode ret_code = CctpErrorCode::OK;

       // Init keys
       initDlogKeys();

       // Generate cert test circuit pk and vk
       CHECK(
           zendoo_generate_mc_test_params(
               TestCircuitType::Certificate,
               ProvingSystem::Darlin,
               (path_char_t*)params_dir.c_str(),
               params_dir_len,
               &ret_code
           ) == true
       );
       CHECK(ret_code == CctpErrorCode::OK);

        auto proof_path = params_dir + std::string("/darlin_cert_test_proof");
        auto pk_path = params_dir + std::string("/darlin_cert_test_pk");
        auto vk_path = params_dir + std::string("/darlin_cert_test_vk");

        // Test all cases
        create_verify_cert_proof(10, true, proof_path, pk_path, vk_path);
        create_verify_cert_proof(0, true, proof_path, pk_path, vk_path);
        create_verify_cert_proof(10, false, proof_path, pk_path, vk_path);
        create_verify_cert_proof(0, false, proof_path, pk_path, vk_path);

       // Delete files
       remove(pk_path.c_str());
       remove(vk_path.c_str());
    }

    void create_verify_csw_proof(
        bool phantomCertDataHash,
        bool zk,
        std::string proof_path,
        std::string pk_path,
        std::string vk_path

    ) {
        CctpErrorCode ret_code = CctpErrorCode::OK;

        // Generate random data
        auto sc_id = zendoo_get_field_from_long(1);
        auto nullifier = zendoo_get_field_from_long(11);
        auto end_cum_comm_tree_root = zendoo_get_field_from_long(2);
        field_t* cert_data_hash;
        if (phantomCertDataHash) {
            cert_data_hash = zendoo_get_phantom_cert_data_hash();
        } else {
            cert_data_hash = zendoo_get_field_from_long(3);
        }
        uint64_t amount = 100;
        std::vector<unsigned char> mc_pk_hash_vec(MC_PK_SIZE, 255);
        auto mc_pk_hash = BufferWithSize(mc_pk_hash_vec.data(), mc_pk_hash_vec.size());

        // Specify paths
        auto sc_pk = zendoo_deserialize_sc_pk_from_file(
            (path_char_t*)pk_path.c_str(),
            pk_path.size(),
            true,
            &ret_code
        );
        CHECK(sc_pk != NULL);
        CHECK(ret_code == CctpErrorCode::OK);

        CHECK(
            zendoo_create_csw_test_proof(
                zk, amount, sc_id, nullifier, &mc_pk_hash, cert_data_hash, end_cum_comm_tree_root,
                sc_pk, (path_char_t*)proof_path.c_str(), proof_path.size(),
                &ret_code
            ) == true
        );
        CHECK(ret_code == CctpErrorCode::OK);

        // Verify proof with correct data
        auto sc_proof = zendoo_deserialize_sc_proof_from_file(
            (path_char_t*)proof_path.c_str(),
            proof_path.size(),
            true,
            &ret_code
        );
        CHECK(sc_proof != NULL);
        CHECK(ret_code == CctpErrorCode::OK);

        auto sc_vk = zendoo_deserialize_sc_vk_from_file(
            (path_char_t*)vk_path.c_str(),
            vk_path.size(),
            true,
            &ret_code
        );
        CHECK(sc_vk != NULL);
        CHECK(ret_code == CctpErrorCode::OK);

        // Positive verification
        CHECK(
            zendoo_verify_csw_proof(
                amount, sc_id, nullifier, &mc_pk_hash, cert_data_hash, end_cum_comm_tree_root,
                sc_proof, sc_vk, &ret_code
            ) == true
        );
        CHECK(ret_code == CctpErrorCode::OK);

        // Negative verification
        auto wrong_sc_id = zendoo_get_field_from_long(4);
        CHECK(
            zendoo_verify_csw_proof(
                amount, wrong_sc_id, nullifier, &mc_pk_hash, cert_data_hash, end_cum_comm_tree_root,
                sc_proof, sc_vk, &ret_code
            ) == false
        );
        CHECK(ret_code == CctpErrorCode::OK);

        // Free memory
        zendoo_field_free(sc_id);
        zendoo_field_free(wrong_sc_id);
        zendoo_field_free(cert_data_hash);
        zendoo_field_free(end_cum_comm_tree_root);
        zendoo_sc_pk_free(sc_pk);
        zendoo_sc_vk_free(sc_vk);
        zendoo_sc_proof_free(sc_proof);

        // Destroy proof file
        remove(proof_path.c_str());
    }

    TEST_CASE("Proof Verifier: CSW - Coboundary Marlin") {
        CctpErrorCode ret_code = CctpErrorCode::OK;

        // Init keys
        initDlogKeys();

        // Generate cert test circuit pk and vk
        CHECK(
            zendoo_generate_mc_test_params(
                TestCircuitType::CSW,
                ProvingSystem::CoboundaryMarlin,
                (path_char_t*)params_dir.c_str(),
                params_dir_len,
                &ret_code
            ) == true
        );
        CHECK(ret_code == CctpErrorCode::OK);

        auto proof_path = params_dir + std::string("/cob_marlin_csw_test_proof");
        auto pk_path = params_dir + std::string("/cob_marlin_csw_test_pk");
        auto vk_path = params_dir + std::string("/cob_marlin_csw_test_vk");

        // Test all cases
        create_verify_csw_proof(true, true, proof_path, pk_path, vk_path);
        create_verify_csw_proof(true, false, proof_path, pk_path, vk_path);
        create_verify_csw_proof(false, true, proof_path, pk_path, vk_path);
        create_verify_csw_proof(false, false, proof_path, pk_path, vk_path);

        // Delete files
        remove(pk_path.c_str());
        remove(vk_path.c_str());
    }

    TEST_CASE("Proof Verifier: CSW - Darlin") {
        CctpErrorCode ret_code = CctpErrorCode::OK;

        // Init keys
        initDlogKeys();

        // Generate cert test circuit pk and vk
        CHECK(
           zendoo_generate_mc_test_params(
               TestCircuitType::CSW,
               ProvingSystem::Darlin,
               (path_char_t*)params_dir.c_str(),
               params_dir_len,
               &ret_code
           ) == true
        );
        CHECK(ret_code == CctpErrorCode::OK);

        auto proof_path = params_dir + std::string("/darlin_csw_test_proof");
        auto pk_path = params_dir + std::string("/darlin_csw_test_pk");
        auto vk_path = params_dir + std::string("/darlin_csw_test_vk");

        // Test all cases
        create_verify_csw_proof(true, true, proof_path, pk_path, vk_path);
        create_verify_csw_proof(true, false, proof_path, pk_path, vk_path);
        create_verify_csw_proof(false, true, proof_path, pk_path, vk_path);
        create_verify_csw_proof(false, false, proof_path, pk_path, vk_path);

        // Delete files
        auto ck_g1_path = params_dir + std::string("/ck_g1");
        auto ck_g2_path = params_dir + std::string("/ck_g2");
        remove(pk_path.c_str());
        remove(vk_path.c_str());
        remove(ck_g1_path.c_str());
        remove(ck_g2_path.c_str());
    }
}

TEST_SUITE("ZendooBatchProofVerifier") {

    static std::string params_dir = std::string("../examples");
    static size_t params_dir_len = params_dir.size();

    void add_random_csw_proof(
        ZendooBatchProofVerifier* batch_verifier,
        uint32_t proof_id,
        std::string pk_path,
        std::string vk_path,
        bool wrong_params
    ) {
        CctpErrorCode ret_code = CctpErrorCode::OK;

        // Generate random data
        auto sc_id = zendoo_get_field_from_long(1);
        auto nullifier = zendoo_get_field_from_long(11);
        auto end_cum_comm_tree_root = zendoo_get_field_from_long(2);
        auto cert_data_hash = zendoo_get_phantom_cert_data_hash();

        uint64_t amount = 100;
        std::vector<unsigned char> mc_pk_hash_vec(MC_PK_SIZE, 255);
        auto mc_pk_hash = BufferWithSize(mc_pk_hash_vec.data(), mc_pk_hash_vec.size());

        // Deserialize pk
        auto sc_pk = zendoo_deserialize_sc_pk_from_file(
            (path_char_t*)pk_path.c_str(),
            pk_path.size(),
            true,
            &ret_code
        );
        CHECK(sc_pk != NULL);
        CHECK(ret_code == CctpErrorCode::OK);

        // Create proof
        auto proof_path = params_dir + std::string("/test_proof");
        CHECK(
            zendoo_create_csw_test_proof(
                false, amount, sc_id, nullifier, &mc_pk_hash, cert_data_hash, end_cum_comm_tree_root,
                sc_pk, (path_char_t*)proof_path.c_str(), proof_path.size(),
                &ret_code
            ) == true
        );
        CHECK(ret_code == CctpErrorCode::OK);

        // Deserialize proof and vk
        auto sc_proof = zendoo_deserialize_sc_proof_from_file(
            (path_char_t*)proof_path.c_str(),
            proof_path.size(),
            true,
            &ret_code
        );
        CHECK(sc_proof != NULL);
        CHECK(ret_code == CctpErrorCode::OK);

        auto sc_vk = zendoo_deserialize_sc_vk_from_file(
            (path_char_t*)vk_path.c_str(),
            vk_path.size(),
            true,
            &ret_code
        );
        CHECK(sc_vk != NULL);
        CHECK(ret_code == CctpErrorCode::OK);

        // Add proof to batch
        if (wrong_params) {
            zendoo_field_free(sc_id);
            sc_id = zendoo_get_field_from_long(4);
        }
        CHECK(
            batch_verifier->add_csw_proof(
                proof_id, amount, sc_id, nullifier, &mc_pk_hash, cert_data_hash,
                end_cum_comm_tree_root, sc_proof, sc_vk, &ret_code
            ) == true
        );
        CHECK(ret_code == CctpErrorCode::OK);


        // Free memory
        zendoo_field_free(sc_id);
        zendoo_field_free(cert_data_hash);
        zendoo_field_free(end_cum_comm_tree_root);
        zendoo_sc_pk_free(sc_pk);
        zendoo_sc_vk_free(sc_vk);
        zendoo_sc_proof_free(sc_proof);

        // Destroy proof file
        remove(proof_path.c_str());
    }

    void add_random_cert_proof(
        ZendooBatchProofVerifier* batch_verifier,
        uint32_t proof_id,
        std::string pk_path,
        std::string vk_path,
        bool wrong_params
    ) {
        CctpErrorCode ret_code = CctpErrorCode::OK;

        // Generate random data
        auto constant = zendoo_get_field_from_long(1);
        auto end_cum_comm_tree_root = zendoo_get_field_from_long(2);
        uint32_t epoch_number = 10;
        uint64_t quality = 100;
        uint64_t btr_fee = 1000;
        uint64_t ft_min_amount = 5000;

        // Get pk
        auto sc_pk = zendoo_deserialize_sc_pk_from_file(
            (path_char_t*)pk_path.c_str(),
            pk_path.size(),
            true,
            &ret_code
        );
        CHECK(sc_pk != NULL);
        CHECK(ret_code == CctpErrorCode::OK);

        // Create proof
        auto proof_path = params_dir + std::string("/test_proof");
        CHECK(
            zendoo_create_cert_test_proof(
                false, constant, epoch_number, quality, NULL, 0,
                NULL, 0, end_cum_comm_tree_root, btr_fee, ft_min_amount, sc_pk,
                (path_char_t*)proof_path.c_str(), proof_path.size(),
                &ret_code
            ) == true
        );
        CHECK(ret_code == CctpErrorCode::OK);

        // Deserialize proof and vk
        auto sc_proof = zendoo_deserialize_sc_proof_from_file(
            (path_char_t*)proof_path.c_str(),
            proof_path.size(),
            true,
            &ret_code
        );
        CHECK(sc_proof != NULL);
        CHECK(ret_code == CctpErrorCode::OK);

        auto sc_vk = zendoo_deserialize_sc_vk_from_file(
            (path_char_t*)vk_path.c_str(),
            vk_path.size(),
            true,
            &ret_code
        );
        CHECK(sc_vk != NULL);
        CHECK(ret_code == CctpErrorCode::OK);

        // Add proof to batch
        if (wrong_params) {
            zendoo_field_free(constant);
            constant = zendoo_get_field_from_long(3);
        }
        CHECK(
            batch_verifier->add_certificate_proof(
                proof_id, constant, epoch_number, quality, NULL, 0,
                NULL, 0, end_cum_comm_tree_root, btr_fee, ft_min_amount, sc_proof, sc_vk, &ret_code
            ) == true
        );
        CHECK(ret_code == CctpErrorCode::OK);

        // Free memory
        zendoo_field_free(constant);
        zendoo_field_free(end_cum_comm_tree_root);
        zendoo_sc_pk_free(sc_pk);
        zendoo_sc_vk_free(sc_vk);
        zendoo_sc_proof_free(sc_proof);

        // Destroy proof file
        remove(proof_path.c_str());
    }

    TEST_CASE("ZendooBatchProofVerifierTest") {
        auto batch_verifier = ZendooBatchProofVerifier();
        uint32_t num_proofs = 10;

        CctpErrorCode ret_code = CctpErrorCode::OK;

        // Bootstrap keys used for proving
        bool init_result = zendoo_init_dlog_keys_test_mode(
            1 << 17,
            1 << 9,
            (path_char_t*)params_dir.c_str(),
            params_dir_len,
            &ret_code
        );
        CHECK(init_result == true);


        // Generate csw test circuit Darlin pk and vk
        CHECK(
           zendoo_generate_mc_test_params(
               TestCircuitType::CSW,
               ProvingSystem::Darlin,
               (path_char_t*)params_dir.c_str(),
               params_dir_len,
               &ret_code
           ) == true
        );
        CHECK(ret_code == CctpErrorCode::OK);

        // Generate csw test circuit CobMarlin pk and vk
        CHECK(
           zendoo_generate_mc_test_params(
               TestCircuitType::CSW,
               ProvingSystem::CoboundaryMarlin,
               (path_char_t*)params_dir.c_str(),
               params_dir_len,
               &ret_code
           ) == true
        );
        CHECK(ret_code == CctpErrorCode::OK);

        // Generate cert test circuit Darlin pk and vk
        CHECK(
           zendoo_generate_mc_test_params(
               TestCircuitType::Certificate,
               ProvingSystem::Darlin,
               (path_char_t*)params_dir.c_str(),
               params_dir_len,
               &ret_code
           ) == true
        );

        CHECK(ret_code == CctpErrorCode::OK);

        // Generate cert test circuit CobMarlin pk and vk
        CHECK(
           zendoo_generate_mc_test_params(
               TestCircuitType::Certificate,
               ProvingSystem::CoboundaryMarlin,
               (path_char_t*)params_dir.c_str(),
               params_dir_len,
               &ret_code
           ) == true
        );
        CHECK(ret_code == CctpErrorCode::OK);

        std::string pk_path = params_dir;
        std::string vk_path = params_dir;

        srand(time(NULL));
        for(uint32_t i = 0; i < num_proofs; i++) {
            int comb = rand() % 4;

            switch (comb) {
                case 0: // Darlin - CSW
                    add_random_csw_proof(
                        &batch_verifier,
                        i,
                        pk_path + std::string("/darlin_csw_test_pk"),
                        vk_path + std::string("/darlin_csw_test_vk"),
                        false
                    );
                    break;
                case 1: // Darlin - Cert
                    add_random_cert_proof(
                        &batch_verifier,
                        i,
                        pk_path + std::string("/darlin_cert_test_pk"),
                        vk_path + std::string("/darlin_cert_test_vk"),
                        false
                    );
                    break;
                case 2: // CobMarlin - csw
                    add_random_csw_proof(
                        &batch_verifier,
                        i,
                        pk_path + std::string("/cob_marlin_csw_test_pk"),
                        vk_path + std::string("/cob_marlin_csw_test_vk"),
                        false
                    );
                    break;
                case 3: // CobMarlin - cert
                    add_random_cert_proof(
                        &batch_verifier,
                        i,
                        pk_path + std::string("/cob_marlin_cert_test_pk"),
                        vk_path + std::string("/cob_marlin_cert_test_vk"),
                        false
                    );
                    break;
                default:
                    break;
            }
        }

        // Bootstrap new keys for verification, bigger than the ones used for proving
        // and check everything is ok
        remove((params_dir + std::string("/ck_g1")).c_str());
        remove((params_dir + std::string("/ck_g2")).c_str());

        bool init_result_2 = zendoo_init_dlog_keys(
            1 << 17,
            (path_char_t*)params_dir.c_str(),
            params_dir_len,
            &ret_code
        );
        CHECK(init_result_2 == true);
        CHECK(ret_code == CctpErrorCode::OK);

        // Batch verify all proofs
        auto result_1 = batch_verifier.batch_verify_all(&ret_code);
        CHECK(result_1.result == true);
        CHECK(result_1.failing_proof == -1);
        CHECK(ret_code == CctpErrorCode::OK);

        // Batch verify subset
        const uint32_t ids[5] = {0, 2, 5, 7, 9};
        auto result_2 = batch_verifier.batch_verify_subset(ids, 5, &ret_code);
        CHECK(result_2.result == true);
        CHECK(result_2.failing_proof == -1);
        CHECK(ret_code == CctpErrorCode::OK);

        // Add a wrong proof to the verifier
        add_random_cert_proof(
            &batch_verifier,
            num_proofs,
            pk_path + std::string("/cob_marlin_cert_test_pk"),
            vk_path + std::string("/cob_marlin_cert_test_vk"),
            true
        );

        // Check batch verification of all proofs fails
        auto result_3 = batch_verifier.batch_verify_all(&ret_code);
        CHECK(result_3.result == false);
        CHECK(ret_code == CctpErrorCode::OK);

        // We should be able to retrieve the index of the failing proof
        CHECK(result_3.failing_proof == num_proofs);

        // Check batch verification of all proofs minus the new one passes
        const uint32_t new_ids[10] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
        auto result_4 = batch_verifier.batch_verify_subset(new_ids, 10, &ret_code);
        CHECK(result_4.result == true);
        CHECK(result_4.failing_proof == -1);
        CHECK(ret_code == CctpErrorCode::OK);

        // Bootstrap new keys for verification, smaller than the ones used for proving
        // and assert failure
        remove((params_dir + std::string("/ck_g1")).c_str());
        remove((params_dir + std::string("/ck_g2")).c_str());

        bool init_result_3 = zendoo_init_dlog_keys_test_mode(
            1 << 17,
            1 << 8,
            (path_char_t*)params_dir.c_str(),
            params_dir_len,
            &ret_code
        );
        CHECK(init_result_3 == true);
        CHECK(ret_code == CctpErrorCode::OK);

        // Check batch verification of all valid proofs fails
        auto result_5 = batch_verifier.batch_verify_subset(new_ids, 10, &ret_code);
        CHECK(result_5.result == false);
        CHECK(result_5.failing_proof == -1); // Should fail in the hard part, so it won't be possible to determine the index
        CHECK(ret_code == CctpErrorCode::OK);

        // Bootstrap new keys for verification, but derived from bigger keys than the original
        // ones and check verification fails
        remove((params_dir + std::string("/ck_g1")).c_str());
        remove((params_dir + std::string("/ck_g2")).c_str());

        bool init_result_4 = zendoo_init_dlog_keys_test_mode(
            1 << 18,
            1 << 17,
            (path_char_t*)params_dir.c_str(),
            params_dir_len,
            &ret_code
        );
        CHECK(init_result_4 == true);
        CHECK(ret_code == CctpErrorCode::OK);

        // Check batch verification of all valid proofs fails
        auto result_6 = batch_verifier.batch_verify_subset(new_ids, 10, &ret_code);
        CHECK(ret_code == CctpErrorCode::OK);
        CHECK(result_6.result == false);
        // Hash of the key will differ, so we expect failure in the succinct part, e.g. we should
        // be able to get the index of the first failing proof
        CHECK(result_6.failing_proof != -1);

        // Delete files
        remove((pk_path + std::string("/darlin_csw_test_pk")).c_str());
        remove((vk_path + std::string("/darlin_csw_test_vk")).c_str());
        remove((pk_path + std::string("/darlin_cert_test_pk")).c_str());
        remove((vk_path + std::string("/darlin_cert_test_vk")).c_str());
        remove((pk_path + std::string("/cob_marlin_csw_test_pk")).c_str());
        remove((vk_path + std::string("/cob_marlin_csw_test_vk")).c_str());
        remove((pk_path + std::string("/cob_marlin_cert_test_pk")).c_str());
        remove((vk_path + std::string("/cob_marlin_cert_test_vk")).c_str());
        remove((params_dir + std::string("/ck_g1")).c_str());
        remove((params_dir + std::string("/ck_g2")).c_str());

        // Destructor of ZendooBatchVerifier will be automatically called once
        // out of scope and the memory Rust-side will be automatically freed.
    }
}