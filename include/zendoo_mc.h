#ifndef ZENDOO_MC_INCLUDE_H_
#define ZENDOO_MC_INCLUDE_H_

#include <stdint.h>
#include <stdlib.h>

static const size_t FIELD_SIZE = 32;
static const size_t MC_PK_SIZE = 20;

extern "C" {

    #ifdef WIN32
        typedef uint16_t path_char_t;
    #else
        typedef uint8_t path_char_t;
    #endif

    typedef struct backward_transfer{
        unsigned char pk_dest[20];
        uint64_t amount;
    } backward_transfer_t;

    typedef enum eCctpErrorCode {
            OK,
            NullPtr,
            InvalidValue,
            InvalidBufferData,
            InvalidBufferLength,
            InvalidListLength,
            InvalidFile,
            HashingError,
            MerkleTreeError,
            ProofVerificationFailure,
            BatchVerifierFailure,
            FailedBatchProofVerification,
            CompressError,
            UncompressError,
            MerkleRootBuildError,
            GenericError,
            TestProofCreationFailure,
    } CctpErrorCode;

    //Field related functions
    /* Note: Functions panic if input pointers are NULL.*/

    typedef struct field field_t;

    /* Get the number of bytes needed to serialize/deserialize a field. */
    size_t zendoo_get_field_size_in_bytes(void);

    /*
     * Serialize a field into `field_bytes` given an opaque pointer `field` to it.
     * It's caller's responsibility to ensure that `field_bytes` size is equal to the one
     * returned by `zendoo_get_field_size_in_bytes`.
     * Return true if the operation was successfull, false otherwise.
     */
    bool zendoo_serialize_field(
        const field_t*  field,
        unsigned char*  field_bytes,
        CctpErrorCode*  ret_code
    );

    /*
     * Deserialize a field from `field_bytes` and return an opaque pointer to it.
     * It's caller's responsibility to ensure that `field_bytes` size is equal to the one
     * returned by `zendoo_get_field_size_in_bytes`. Return NULL if deserialization fails.
     */
    field_t* zendoo_deserialize_field(const unsigned char* field_bytes, CctpErrorCode* ret_code);

    /*
     * Free the memory from the field pointed by `field`. It's caller responsibility
     * to set `field` to NULL afterwards. If `field` was already null, the function does
     * nothing.
     */
    void zendoo_field_free(field_t* field);

    /*
     * Print field bytes
     */
    void zendoo_print_field(field_t* field);

    struct BufferWithSize {
        const unsigned char* data;
        size_t len;

        BufferWithSize(): data(NULL), len(0) {}
        BufferWithSize(const unsigned char* dataIn, size_t lenIn): data(dataIn), len(lenIn) {}
    };

    /* Free a BufferWithSize allocated Rust-side */
    void zendoo_free_bws(BufferWithSize* buf);

    // Commitment Tree related declarations

    typedef enum ProvingSystem {
        Undefined,
        Darlin,
        CoboundaryMarlin
    } ProvingSystem;

    struct BitVectorElementsConfig {
        uint32_t bit_vector_size_bits;
        uint32_t max_compressed_byte_size;

        BitVectorElementsConfig(): bit_vector_size_bits(0), max_compressed_byte_size(0) {}
        BitVectorElementsConfig(uint32_t bit_vector_size_bits, uint32_t max_compressed_byte_size):
            bit_vector_size_bits(bit_vector_size_bits), max_compressed_byte_size(max_compressed_byte_size) {}
    };

    size_t zendoo_get_sc_custom_data_size_in_bytes(void);

    typedef struct CommitmentTree commitment_tree_t;

    commitment_tree_t *zendoo_commitment_tree_create();

    void zendoo_commitment_tree_delete(commitment_tree_t *ptr);

    field_t* zendoo_compute_sc_id(
        const BufferWithSize* tx_hash,
        uint32_t pos,
        CctpErrorCode* ret_code
    );

    /*
     * Adds a Sidechain Creation to the commitment tree. Returns true if operation was successful, false otherwise.
     * NOTE: `custom_field_elements_config`, `custom_bv_elements_config`, `custom_creation_data`, `constant` and `csw_vk`
     *       can be NULL.
     */
    bool zendoo_commitment_tree_add_scc(
        commitment_tree_t *ptr,
        const field_t* sc_id,
        uint64_t amount,
        const BufferWithSize* pub_key,
        const BufferWithSize* tx_hash,
        uint32_t out_idx,
        uint32_t withdrawal_epoch_length,
        uint8_t mc_btr_request_data_length,
        const BufferWithSize* custom_field_elements_config,
        const BitVectorElementsConfig* custom_bv_elements_config,
        size_t custom_bv_elements_config_len,
        uint64_t btr_fee,
        uint64_t ft_min_amount,
        const BufferWithSize* custom_creation_data,
        const field_t* constant,
        const BufferWithSize* cert_vk,
        const BufferWithSize* csw_vk,
        CctpErrorCode* ret_code
    );

    /*
     * Adds a Forward Transfer to the commitment tree. Returns true if operation was successful, false otherwise.
     */
    bool zendoo_commitment_tree_add_fwt(
        commitment_tree_t *ptr,
        const field_t* sc_id,
        uint64_t amount,
        const BufferWithSize* pub_key,
        const BufferWithSize* tx_hash,
        uint32_t out_idx,
        CctpErrorCode* ret_code
    );

    /*
     * Adds a Backward Transfer Request to the commitment tree. Returns true if operation was successful, false otherwise.
     */
    bool zendoo_commitment_tree_add_bwtr(
        commitment_tree_t *ptr,
        const field_t* sc_id,
        uint64_t sc_fee,
        const field_t** sc_req_data,
        size_t sc_req_data_len,
        const BufferWithSize* mc_dest_addr,
        const BufferWithSize* tx_hash,
        uint32_t out_idx,
        CctpErrorCode *ret_code
    );

    /*
     * Adds a Ceased Sidechain Withdrawal to the commitment tree. Returns true if operation was successful, false otherwise.
     */
    bool zendoo_commitment_tree_add_csw(
        commitment_tree_t *ptr,
        const field_t* sc_id,
        uint64_t amount,
        const field_t* nullifier,
        const BufferWithSize* mc_pk_hash,
        CctpErrorCode *ret_code
    );

    /*
     * Adds a Certificate to the commitment tree. Returns true if operation was successful, false otherwise.
     * NOTE: `bt_list` and `custom_fields` can be NULL.
     */
    bool zendoo_commitment_tree_add_cert(
        commitment_tree_t *ptr,
        const field_t* sc_id,
        uint32_t epoch_number,
        uint64_t quality,
        const backward_transfer_t* bt_list,
        size_t bt_list_len,
        const field_t** custom_fields,
        size_t custom_fields_len,
        const field_t* end_cum_comm_tree_root,
        uint64_t btr_fee,
        uint64_t ft_min_amount,
        CctpErrorCode* ret_code
    );

    field_t* zendoo_commitment_tree_get_commitment(
        commitment_tree_t *ptr,
        CctpErrorCode* ret_code
    );

    // Bit Vectors related declarations

    typedef enum eCompressionAlgorithm {
        Uncompressed,
        Bzip2,
        Gzip
    } CompressionAlgorithm; 

    BufferWithSize* zendoo_compress_bit_vector(
        const BufferWithSize* buf,
        CompressionAlgorithm algorithm,
        CctpErrorCode* ret_code
    );

    BufferWithSize* zendoo_decompress_bit_vector(
        const BufferWithSize* buf,
        size_t expected_decomp_len,
        CctpErrorCode* ret_code
    );

    field_t* zendoo_merkle_root_from_compressed_bytes(
        const BufferWithSize* compressed_data,
        size_t expected_decomp_len,
        CctpErrorCode* ret_code
    );

    //Poseidon hash related functions

    typedef struct poseidon_hash poseidon_hash_t;

    /*
     * Gets a new constant input length instance of poseidon_hash, specifying the exact input_size.
     * It's possible to customize the initial Poseidon state given a vector of field elements
     * as `personalization`; this is not mandatory and `personalization` can be NULL.
     */
    poseidon_hash_t* zendoo_init_poseidon_hash_constant_length(
        size_t input_size,
        const field_t** personalization,
        size_t personalization_len,
        CctpErrorCode* ret_code
    );

    /*
     * Gets a new variable input length instance of poseidon_hash, specifying (if known a priori)
     * if the input length will be mod rate of the hash function or not.
     * It's possible to customize the initial Poseidon state given a vector of field elements
     * as `personalization`; this is not mandatory and `personalization` can be NULL.
     */
    poseidon_hash_t* zendoo_init_poseidon_hash_variable_length(
        bool mod_rate,
        const field_t** personalization,
        size_t personalization_len,
        CctpErrorCode* ret_code
    );

    /*
     * Updates `digest` with a new field element `fe` given an opaque pointer to it.
     * Return true if the operation was successfull, false otherwise.
     * NOTE: The function will perform a copy of the FieldElement pointed by `fe` in order to store
     * it as its internal state, therefore it's possible to free `fe` immediately afterwards.
     */
    bool zendoo_update_poseidon_hash(const field_t* fe, poseidon_hash_t* digest, CctpErrorCode* ret_code);


    /*
     * Updates `digest` with a new field element `fe` given a byte array from which deserializing it.
     * Return true if the operation was successfull, false otherwise.
     * NOTE: The function will deserialize a FieldElement out of BufferWithSize and store it in its
     *       internal state, therefore it's possibile to destroy `fe` immediately after having called
     *       this function.
     */
    bool zendoo_update_poseidon_hash_from_raw(const BufferWithSize* fe, poseidon_hash_t* digest, CctpErrorCode* ret_code);

    /*
     * Returns the final digest.
     * NOTE: This method is idempotent, and calling it multiple times will give the same result.
     * If `digest` instance is constant length, this function will return error if `digest` was
     * not updated with the specified number of field elements;
     * If `digest` instance is variable length and `mod_rate` was set to true, this function
     * will return error if digest was not updated with a number of field elements that is
     * multiple of its rate.
     */
    field_t* zendoo_finalize_poseidon_hash(const poseidon_hash_t* digest, CctpErrorCode* ret_code);

    /*
     * Restore digest to its initial state, allowing to change `personalization` too if needed.
     * Return true if operation was successfull, false otherwise.
     */
    bool zendoo_reset_poseidon_hash(
        poseidon_hash_t* digest,
        const field_t** personalization,
        size_t personalization_len,
        CctpErrorCode* ret_code
    );

    /*
     * Free the memory from the poseidon_hash pointed by `digest`.
     * It's caller responsibility to set `digest` to NULL afterwards.
     * If `digest` was already null, the function does nothing.
     */
    void zendoo_free_poseidon_hash(poseidon_hash_t* digest);

    /*
     *   Support struct to enhance and make easier the usage of poseidon_hash, by
     *   making poseidon_hash a member of the struct and wrapping the functions
     *   above. Note the definition of the destructor: when an instance of this struct
     *   will go out of scope, the memory Rust-side will be automatically freed.
     */
    struct ZendooPoseidonHash {
        poseidon_hash_t* digest;

        ZendooPoseidonHash(poseidon_hash_t* digest): digest(digest) {}

        bool update(const BufferWithSize* fe, CctpErrorCode* ret_code) {
            return zendoo_update_poseidon_hash_from_raw(fe, digest, ret_code);
        }

        bool update(field_t* fe, CctpErrorCode* ret_code) {
            return zendoo_update_poseidon_hash(fe, digest, ret_code);
        }

        field_t* finalize(CctpErrorCode* ret_code){
            return zendoo_finalize_poseidon_hash(digest, ret_code);
        }

        bool reset(const field_t** personalization, size_t personalization_len, CctpErrorCode* ret_code) {
            return zendoo_reset_poseidon_hash(digest, personalization, personalization_len, ret_code);
        }

        ~ZendooPoseidonHash() {
            zendoo_free_poseidon_hash(digest);
            digest = nullptr;
        }
    };

    /*
     * Specialization for constant length instances of PoseidonHash.
     * The constructor requires to pass the input size.
     * When finalizing the hash, a error will be thrown if this instance has
     * not been updated with exactly the same number of inputs specified at
     * creation time.
     */
    struct ZendooPoseidonHashConstantLength: ZendooPoseidonHash {

        ZendooPoseidonHashConstantLength(size_t input_size, CctpErrorCode* ret_code):
            ZendooPoseidonHash(zendoo_init_poseidon_hash_constant_length(input_size, NULL, 0, ret_code)) {}

        ZendooPoseidonHashConstantLength(size_t input_size, const field_t** personalization, size_t personalization_len, CctpErrorCode* ret_code):
            ZendooPoseidonHash(zendoo_init_poseidon_hash_constant_length(input_size, personalization, personalization_len, ret_code)) {}
    };

    /*
     * Specialization for variable length instances of PoseidonHash.
     * The constructor requires to know (if known a priori), whether the input
     * size will be modulus the rate of the hash function or not.
     * When finalizing the hash, a error will be thrown if this instance was
     * created with mod_rate = true but it has not been updated with a number
     * of inputs which is effectively multiple of the rate.
     */
    struct ZendooPoseidonHashVariableLength: ZendooPoseidonHash {

        ZendooPoseidonHashVariableLength(bool mod_rate, CctpErrorCode* ret_code):
            ZendooPoseidonHash(zendoo_init_poseidon_hash_variable_length(mod_rate, NULL, 0, ret_code)) {}

        ZendooPoseidonHashVariableLength(bool mod_rate, const field_t** personalization, size_t personalization_len, CctpErrorCode* ret_code):
            ZendooPoseidonHash(zendoo_init_poseidon_hash_variable_length(mod_rate, personalization, personalization_len, ret_code)) {}
    };

    // Merkle Path related functions

    typedef struct ginger_merkle_path ginger_merkle_path_t;

    /*
     * Verify the Merkle Path `path` from `leaf' to `root` for a Merkle Tree of height `height`.
     */
    bool zendoo_verify_ginger_merkle_path(
        const ginger_merkle_path_t* path,
        size_t height,
        const field_t* leaf,
        const field_t* root,
        CctpErrorCode* ret_code
    );

    /*
     * Free the memory from the Ginger Merkle Path pointed by `path`.
     * It's caller responsibility to set `path` to NULL afterwards.
     * If `path` was already null, the function does nothing.
     */
    void zendoo_free_ginger_merkle_path(ginger_merkle_path_t* path);


    //Poseidon-based Merkle Tree related functions

    typedef struct ginger_mht ginger_mht_t;

    /*
     * Gets a new instance of a Ginger Merkle Tree, of height `height`.
     * `processing_step` is used to tune the memory usage of the tree.
     */
    ginger_mht_t* zendoo_new_ginger_mht(size_t height, size_t processing_step);

    /*
     * Appends `leaf` to `tree` given an opaque FieldElement pointer to it.
     * Return true if the operation was successfull, false otherwise.
     * NOTE: The function will perform a copy of the FieldElement pointed by `leaf` in order to store
     * it as its internal state, therefore it's possible to free `leaf` immediately afterwards.
     */
    bool zendoo_append_leaf_to_ginger_mht(const field_t* leaf, ginger_mht_t* tree, CctpErrorCode* ret_code);

    /*
     * Appends `leaf` to `tree` given a byte array from which deserializing a FieldElement.
     * Return true if the operation was successfull, false otherwise.
     * NOTE: The function will deserialize a FieldElement out of BufferWithSize and store it in its
     *       internal state, therefore it's possibile to destroy `fe` immediately after having called
     *       this function.
     */
    bool zendoo_append_leaf_to_ginger_mht_from_raw(const BufferWithSize* leaf, ginger_mht_t* tree, CctpErrorCode* ret_code);

    /*
     * This function finalizes the computation of the Merkle tree and returns an updated
     * copy of it. This method is idempotent, and calling it multiple times will
     * give the same result. It's also possible to `update` with more inputs in between.
     */
    ginger_mht_t* zendoo_finalize_ginger_mht(const ginger_mht_t* tree, CctpErrorCode* ret_code);

    /*
     * This function finalizes the computation of the Merkle tree
     * Once this function is called, it is not possible to further update the tree.
     * Return true if the operation was successfull, false otherwise.
     */
    bool zendoo_finalize_ginger_mht_in_place(ginger_mht_t* tree, CctpErrorCode* ret_code);

    /*
     * Returns the root of the Merkle Tree. This function must be called on a finalized tree.
     * If not, the function returns null.
     */
    field_t* zendoo_get_ginger_mht_root(const ginger_mht_t* tree, CctpErrorCode* ret_code);

    /*
     * Returns the path from the leaf at `leaf_index` to the root of `tree`.
     * This function must be called on a finalized tree.
     * If not, the function returns null.
     */
    ginger_merkle_path_t* zendoo_get_ginger_merkle_path(
        const ginger_mht_t* tree,
        size_t leaf_index,
        CctpErrorCode* ret_code
    );

    /*
     * Returns the value of a node at height h assuming that all its children
     * are recursively empty, starting from a pre-defined empty leaf.
     */
    field_t* zendoo_get_ginger_empty_node(size_t height);

    /*
     * Restores the tree to its initial state.
     */
    bool zendoo_reset_ginger_mht(ginger_mht_t* tree, CctpErrorCode* ret_code);

    /*
     * Free the memory from the Ginger Random Access Merkle Tree pointed by `tree`.
     * It's caller responsibility to set `tree` to NULL afterwards.
     * If `tree` was already null, the function does nothing.
     */
    void zendoo_free_ginger_mht(ginger_mht_t* tree);

    /*
     *   Support struct to enhance and make easier the usage of ginger_mht, by
     *   making ginger_mht a member of the struct and wrapping the functions
     *   above. Note the definition of the destructor: when an instance of this struct
     *   will go out of scope, the memory Rust-side will be automatically freed.
     */
    struct ZendooGingerMerkleTree {
        ginger_mht_t* tree;

        ZendooGingerMerkleTree(ginger_mht_t* tree): tree(tree) {}

        ZendooGingerMerkleTree(size_t height, size_t processing_step){
            tree = zendoo_new_ginger_mht(height, processing_step);
        }

        bool append(const field_t* leaf, CctpErrorCode* ret_code) {
            return zendoo_append_leaf_to_ginger_mht(leaf, tree, ret_code);
        }

        bool append(const BufferWithSize* leaf, CctpErrorCode* ret_code) {
            return zendoo_append_leaf_to_ginger_mht_from_raw(leaf, tree, ret_code);
        }

        ZendooGingerMerkleTree finalize(CctpErrorCode* ret_code){
            return ZendooGingerMerkleTree(zendoo_finalize_ginger_mht(tree, ret_code));
        }

        bool finalize_in_place(CctpErrorCode* ret_code){
            return zendoo_finalize_ginger_mht_in_place(tree, ret_code);
        }

        field_t* root(CctpErrorCode* ret_code){
            return zendoo_get_ginger_mht_root(tree, ret_code);
        }

        ginger_merkle_path_t* get_merkle_path(size_t leaf_index, CctpErrorCode* ret_code) {
            return zendoo_get_ginger_merkle_path(tree, leaf_index, ret_code);
        }

        bool reset(CctpErrorCode* ret_code){
            return zendoo_reset_ginger_mht(tree, ret_code);
        }

        static field_t* get_empty_node(size_t height) {
            return zendoo_get_ginger_empty_node(height);
        }

        ~ZendooGingerMerkleTree() {
            zendoo_free_ginger_mht(tree);
            tree = nullptr;
        }
    };

    /* Get an opaque pointer to a random field element */
    field_t* zendoo_get_random_field(void);

    /* Get a field element given `value` */
    field_t* zendoo_get_field_from_long(uint64_t value);

    /* Return `true` if the fields pointed by `field_1` and `field_2` are
     * equal, and `false` otherwise.
     */
    bool zendoo_field_assert_eq(
        const field_t* field_1,
        const field_t* field_2
    );

    //SC SNARK related functions

    /*
     * Returns the ProvingSystem instance for which `type_bytes` encodes for.
     */
    ProvingSystem zendoo_get_proving_system_type(
        unsigned char type_byte,
        CctpErrorCode* ret_code
    );

    /*
     * Initialize DLOG keys of specified `segment_size` in memory .
     */
    bool zendoo_init_dlog_keys(
        size_t segment_size,
        CctpErrorCode* ret_code
    );

    /*
     * Initialize DLOG keys of specified `supported_segment_size` in memory, derived from keys of size `max_segment_size` .
     */
    bool zendoo_init_dlog_keys_test_mode(
        size_t max_segment_size,
        size_t supported_segment_size,
        CctpErrorCode* ret_code
    );

    typedef struct sc_proof sc_proof_t;

    /*
     * Serialize a proof, in compressed or uncompressed form, depending on the value of `compressed` flag,
     * given an opaque pointer `sc_proof` to it. Instantiate and return a BufferWithSize containing the proof bytes.
     */
    BufferWithSize* zendoo_serialize_sc_proof(
        const sc_proof_t* proof,
        CctpErrorCode* ret_code,
        bool compressed = true
    );

    /*
     * Deserialize a proof, in compressed or uncompressed form, depending on the value of `compressed` flag,
     * from `sc_proof_bytes` and return an opaque pointer to it.
     * If `semantic_checks` flag is set, semantic checks on the proof will be performed.
     */
    sc_proof_t* zendoo_deserialize_sc_proof(
        const BufferWithSize* sc_proof_bytes,
        bool semantic_checks,
        CctpErrorCode* ret_code,
        bool compressed = true
    );

    /*
     * Get the ProvingSystem of `sc_proof`.
     */
    ProvingSystem zendoo_get_sc_proof_proving_system_type(
        const sc_proof_t* sc_proof,
        CctpErrorCode* ret_code
    );

    /*
     * Get the ProvingSystem of the sc_proof serialized to `sc_proof_bytes` BufferWithSize.
     */
    ProvingSystem zendoo_get_sc_proof_proving_system_type_from_buffer(
        const BufferWithSize* sc_proof_bytes,
        CctpErrorCode* ret_code
    );

    /*
     * Get the ProvingSystem of the sc_proof serialized to file at `proof_path`.
     */
    ProvingSystem zendoo_get_sc_proof_proving_system_type_from_file(
        const path_char_t* proof_path,
        size_t proof_path_len,
        CctpErrorCode* ret_code
    );

    /*
     * Free the memory from the sc_proof pointed by `sc_proof`. It's caller responsibility
     * to set `sc_proof` to NULL afterwards. If `sc_proof` was already NULL, the function does
     * nothing.
     */
    void zendoo_sc_proof_free(sc_proof_t* proof);

    typedef struct sc_vk sc_vk_t;

    /* Deserialize a sc_vk, in compressed or uncompressed form, depending on the value of `compressed` flag,
     * from a file at path `vk_path` and return an opaque pointer to it.
     * If `semantic_checks` flag is set, semantic checks on vk will be performed.
     */
    sc_vk_t* zendoo_deserialize_sc_vk_from_file(
        const path_char_t* vk_path,
        size_t vk_path_len,
        bool semantic_checks,
        CctpErrorCode* ret_code,
        bool compressed = true
    );

    /*
     * Deserialize a sc_vk, in compressed or uncompressed form, depending on the value of `compressed` flag,
     * from `sc_vk_bytes` and return an opaque pointer to it.
     * If `semantic_checks` flag is set, semantic checks on vk will be performed.
     */
    sc_vk_t* zendoo_deserialize_sc_vk(
        const BufferWithSize* sc_vk_bytes,
        bool semantic_checks,
        CctpErrorCode* ret_code,
        bool compressed = true
    );

    /*
     * Get the ProvingSystem of `sc_vk`.
     */
    ProvingSystem zendoo_get_sc_vk_proving_system_type(
        const sc_vk_t* sc_vk,
        CctpErrorCode* ret_code
    );

    /*
     * Get the ProvingSystem of the sc_vk serialized to `sc_vk_bytes` BufferWithSize.
     */
    ProvingSystem zendoo_get_sc_vk_proving_system_type_from_buffer(
        const BufferWithSize* sc_vk_bytes,
        CctpErrorCode* ret_code
    );

    /*
     * Get the ProvingSystem of the sc_vk serialized to file at `vk_path`.
     */
    ProvingSystem zendoo_get_sc_vk_proving_system_type_from_file(
        const path_char_t* vk_path,
        size_t vk_path_len,
        CctpErrorCode* ret_code
    );

    /*
     * Free the memory from the sc_vk pointed by `sc_vk`. It's caller responsibility
     * to set `sc_vk` to NULL afterwards. If `sc_vk` was already null, the function does
     * nothing.
     */
    void zendoo_sc_vk_free(sc_vk_t* vk);

    /*  Verify a certificate proof sc_proof `sc_proof` given its corresponding sc_vk `sc_vk`
     *  and all the data needed to construct proof's public inputs. Return true if
     *  proof verification was successful, false otherwise.
     *  NOTE: `constant`, `custom_fields` and 'bt_list' can be NULL.
     */
    bool zendoo_verify_certificate_proof(
        const field_t* constant,
        const field_t* sc_id,
        uint32_t epoch_number,
        uint64_t quality,
        const backward_transfer_t* bt_list,
        size_t bt_list_len,
        const field_t** custom_fields,
        size_t custom_fields_len,
        const field_t* end_cum_comm_tree_root,
        uint64_t btr_fee,
        uint64_t ft_min_amount,
        const sc_proof_t* sc_proof,
        const sc_vk_t*    sc_vk,
        CctpErrorCode* ret_code
    );

    /*
     * Return a field element to be used as `cert_data_hash` input for
     * `zendoo_verify_csw_proof()` and `zendoo_add_csw_proof_to_batch_verifier()`
     * when no `cert_data_hash` is present.
     */
    field_t* zendoo_get_phantom_cert_data_hash();

    /*
     * Compute cert data hash.
     */
    field_t* zendoo_get_cert_data_hash(
        const field_t* sc_id,
        uint32_t epoch_number,
        uint64_t quality,
        const backward_transfer_t* bt_list,
        size_t bt_list_len,
        const field_t** custom_fields,
        size_t custom_fields_len,
        const field_t* end_cum_comm_tree_root,
        uint64_t btr_fee,
        uint64_t ft_min_amount,
        CctpErrorCode* ret_code
    );

    /*  Verify a CSW proof sc_proof `sc_proof` given its corresponding sc_vk `sc_vk`
     *  and all the data needed to construct proof's public inputs. Return true if
     *  proof verification was successful, false otherwise.
     *  `cert_data_hash` can be NULL and, if so, it will be replaced with a phantom value.
     */
    bool zendoo_verify_csw_proof(
        uint64_t amount,
        const field_t* sc_id,
        const field_t* nullifier,
        const BufferWithSize* mc_pk_hash,
        const field_t* cert_data_hash,
        const field_t* end_cum_comm_tree_root,
        const sc_proof_t* sc_proof,
        const sc_vk_t*    sc_vk,
        CctpErrorCode* ret_code
    );

    typedef struct sc_batch_proof_verifier sc_batch_proof_verifier_t;

    /*
     * Return an instance of sc_batch_proof_verifier
     */
    sc_batch_proof_verifier_t* zendoo_create_batch_proof_verifier();

    /* Add a certificate proof to the batch of proofs to be verified, given
     * all the data required to reconstruct the public inputs, the proof
     * `sc_proof` and the verification key `sc_vk`.
     *  NOTE:
     *      - `constant`, `custom_fields` and 'bt_list' can be NULL;
     *      -  proof, vk and the public input derived from the other data
     *         will be copied in order to store them in `batch_verifier`
     *         state, so they can be immediately freed afterwards.
     */
    bool zendoo_add_certificate_proof_to_batch_verifier(
        sc_batch_proof_verifier_t* batch_verifier,
        uint32_t proof_id,
        const field_t* constant,
        const field_t* sc_id,
        uint32_t epoch_number,
        uint64_t quality,
        const backward_transfer_t* bt_list,
        size_t bt_list_len,
        const field_t** custom_fields,
        size_t custom_fields_len,
        const field_t* end_cum_comm_tree_root,
        uint64_t btr_fee,
        uint64_t ft_min_amount,
        const sc_proof_t* sc_proof,
        const sc_vk_t*    sc_vk,
        CctpErrorCode* ret_code
    );

    /*  Verify a CSW proof sc_proof `sc_proof` given its corresponding sc_vk `sc_vk`
     *  and all the data needed to construct proof's public inputs. Return true if
     *  proof verification was successful, false otherwise.
     *  `cert_data_hash` can be NULL and, if so, it will be replaced with a phantom value.
     *  NOTE: proof, vk and the public input derived from the other data will be
     *        copied in order to store them in `batch_verifier` state, so they
     *        can be immediately freed afterwards.
     */
    bool zendoo_add_csw_proof_to_batch_verifier(
        sc_batch_proof_verifier_t* batch_verifier,
        uint32_t proof_id,
        uint64_t amount,
        const field_t* sc_id,
        const field_t* nullifier,
        const BufferWithSize* mc_pk_hash,
        const field_t* cert_data_hash,
        const field_t* end_cum_comm_tree_root,
        const sc_proof_t* sc_proof,
        const sc_vk_t*    sc_vk,
        CctpErrorCode* ret_code
    );

    /* Wraps the result of a batch verification.
     * If result == true, failing_proof should be set to -1;
     * If result == false, failing proof should be set to the id of the failing proof,
     * if it's possibile to estabilish it, to -1 otherwise.
     */
    struct ZendooBatchProofVerifierResult {
        bool            result;
        const uint32_t* failing_proofs;
        size_t          failing_proofs_len;

        ZendooBatchProofVerifierResult(): failing_proofs(NULL), failing_proofs_len(0) {}
        ZendooBatchProofVerifierResult(const uint32_t* failing_proofs, size_t failing_proofs_len):
            failing_proofs(failing_proofs), failing_proofs_len(failing_proofs_len) {}
    };

    /* Free a BufferWithSize allocated Rust-side */
    void zendoo_free_batch_proof_verifier_result(ZendooBatchProofVerifierResult* result);

    /*
     * Pause all running low priority threads (currently is possible only for the batch verifier threads).
     */
    void zendoo_pause_low_priority_threads();

    /*
     * Unpause all running low priority threads (currently is possible only for the batch verifier threads).
     */
    void zendoo_unpause_low_priority_threads();

    /*
     * Perform batch verification of all the proofs added to `batch_verifier`.
     * If `prioritize` is set to true, pauses other NON high priority batch
     * verifications (if any) happening in other threads as soon as possible;
     * this means also that a high priority verification cannot be paused.
     */
    ZendooBatchProofVerifierResult* zendoo_batch_verify_all_proofs(
        const sc_batch_proof_verifier_t* batch_verifier,
        bool prioritize,
        CctpErrorCode* ret_code
    );

    /*
     * Perform batch verification of the proofs added to `batch_verifier`
     * whose id is contained in `ids_list`. If `prioritize` is set to true,
     * pauses other NON high priority batch verifications (if any) happening
     * in other threads as soon as possible; this means also that a high priority
     * verification cannot be paused.
     */
    ZendooBatchProofVerifierResult* zendoo_batch_verify_proofs_by_id(
        const sc_batch_proof_verifier_t* batch_verifier,
        const uint32_t* ids_list,
        size_t ids_list_len,
        bool prioritize,
        CctpErrorCode* ret_code
    );

    /*
     * Free the memory pointed by `batch_verifier`,
    */
    void zendoo_free_batch_proof_verifier(sc_batch_proof_verifier_t* batch_verifier);

    /*
     *   Support struct to enhance and make easier the usage of sc_batch_proof_verifier, by
     *   making batch_verifier a member of the struct and wrapping the functions
     *   above. Note the definition of the destructor: when an instance of this struct
     *   will go out of scope, the memory Rust-side will be automatically freed.
     */
    struct ZendooBatchProofVerifier {
        sc_batch_proof_verifier_t* batch_verifier;
        bool highPriorityVerification;

        ZendooBatchProofVerifier(sc_batch_proof_verifier_t* batch_verifier, bool highPriorityVerification):
         batch_verifier(batch_verifier), highPriorityVerification(highPriorityVerification) {}

        ZendooBatchProofVerifier(bool highPriorityVerification): highPriorityVerification(highPriorityVerification) {
            batch_verifier = zendoo_create_batch_proof_verifier();
        }

        ZendooBatchProofVerifier() {
            batch_verifier = zendoo_create_batch_proof_verifier();
            highPriorityVerification = false;
        }

        bool add_certificate_proof(
            uint32_t proof_id,
            const field_t* constant,
            const field_t* sc_id,
            uint32_t epoch_number,
            uint64_t quality,
            const backward_transfer_t* bt_list,
            size_t bt_list_len,
            const field_t** custom_fields,
            size_t custom_fields_len,
            const field_t* end_cum_comm_tree_root,
            uint64_t btr_fee,
            uint64_t ft_min_amount,
            const sc_proof_t* sc_proof,
            const sc_vk_t*    sc_vk,
            CctpErrorCode* ret_code
        )
        {
            return zendoo_add_certificate_proof_to_batch_verifier(
                batch_verifier, proof_id, constant, sc_id, epoch_number, quality,
                bt_list, bt_list_len, custom_fields, custom_fields_len,
                end_cum_comm_tree_root, btr_fee, ft_min_amount,
                sc_proof, sc_vk, ret_code
            );
        }

        bool add_csw_proof(
            uint32_t proof_id,
            uint64_t amount,
            const field_t* sc_id,
            const field_t* nullifier,
            const BufferWithSize* mc_pk_hash,
            const field_t* cert_data_hash,
            const field_t* end_cum_comm_tree_root,
            const sc_proof_t* sc_proof,
            const sc_vk_t*    sc_vk,
            CctpErrorCode* ret_code
        )
        {
            return zendoo_add_csw_proof_to_batch_verifier(
                batch_verifier, proof_id, amount, sc_id, nullifier, mc_pk_hash,
                cert_data_hash, end_cum_comm_tree_root, sc_proof, sc_vk, ret_code
            );
        }

        ZendooBatchProofVerifierResult* batch_verify_all(CctpErrorCode* ret_code) {
            return zendoo_batch_verify_all_proofs(batch_verifier, highPriorityVerification, ret_code);
        }

        ZendooBatchProofVerifierResult* batch_verify_subset(const uint32_t* ids_list, size_t ids_list_len, CctpErrorCode* ret_code) {
            return zendoo_batch_verify_proofs_by_id(batch_verifier, ids_list, ids_list_len, highPriorityVerification, ret_code);
        }
        
        ~ZendooBatchProofVerifier() {
            zendoo_free_batch_proof_verifier(batch_verifier);
            batch_verifier = nullptr;
        }
    };

    //Test functions

    typedef struct sc_pk sc_pk_t;

    /* Deserialize a sc_pk, in compressed or uncompressed form, depending on the value of `compressed` flag,
     * from a file at path `pk_path` and return an opaque pointer to it.
     * If `semantic_checks` flag is set, group membership test for curve points will be performed.
     * Return NULL if the file doesn't exist, if deserialization fails or validity checks fail.
     */
    sc_pk_t* zendoo_deserialize_sc_pk_from_file(
        const path_char_t* pk_path,
        size_t pk_path_len,
        bool semantic_checks,
        CctpErrorCode* ret_code,
        bool compressed = true
    );

    /*
     * Get the ProvingSystem of `sc_pk`.
     */
    ProvingSystem zendoo_get_sc_pk_proving_system_type(
        const sc_pk_t* pk,
        CctpErrorCode* ret_code
    );

    /*
     * Get the ProvingSystem of the sc_pk serialized to `sc_pk_bytes` BufferWithSize.
     */
    ProvingSystem zendoo_get_sc_pk_proving_system_type_from_buffer(
        const BufferWithSize* sc_pk_bytes,
        CctpErrorCode* ret_code
    );

    /*
     * Get the ProvingSystem of the sc_pk serialized to file at `pk_path`.
     */
    ProvingSystem zendoo_get_sc_pk_proving_system_type_from_file(
        const path_char_t* pk_path,
        size_t pk_path_len,
        CctpErrorCode* ret_code
    );

    /*
     * Free the memory from the sc_pk pointed by `sc_pk`. It's caller responsibility
     * to set `sc_pk` to NULL afterwards. If `sc_pk` was already null, the function does
     * nothing.
     */
    void zendoo_sc_pk_free(sc_pk_t* pk);

    /* Deserialize a sc_proof, in compressed or uncompressed form, depending on the value of `compressed` flag,
     * from a file at path `proof_path` and return an opaque pointer to it.
     * If `semantic_checks` flag is set, group membership test for curve points will be performed.
     * Return NULL if the file doesn't exist, if deserialization fails or validity checks fail.
     */
    sc_proof_t* zendoo_deserialize_sc_proof_from_file(
        const path_char_t* proof_path,
        size_t proof_path_len,
        bool semantic_checks,
        CctpErrorCode* ret_code,
        bool compressed = true
    );

    typedef enum TestCircuitType {
        Certificate,
        CSW,
    } TestCircuitType;

    /*
     * Generates and saves at specified path `params_dir` the proving key and verification key,
     * in compressed or uncompressed form, depending on the value of `compress_` flags, for the
     * specified `circ_type`.
     */
    bool zendoo_generate_mc_test_params(
        TestCircuitType circ_type,
        ProvingSystem ps_type,
        uint32_t num_constraints,
        const path_char_t* params_dir,
        size_t params_dir_len,
        CctpErrorCode* ret_code,
        bool compress_vk = true,
        bool compress_pk = true
    );

    /*
     * Generates, given the required witnesses and the proving key, a CertTestCircuit proof, and saves it,
     * in compressed or uncompressed form, depending on the value of `compress_proof` flag, at specified path.
     * Return true if operation was successful, false otherwise.
     * NOTE: `constant`, `bt_list` and `custom_fields` can be null.
     */
    bool zendoo_create_cert_test_proof(
        bool zk,
        const field_t* constant,
        const field_t* sc_id,
        uint32_t epoch_number,
        uint64_t quality,
        const backward_transfer_t* bt_list,
        size_t bt_list_len,
        const field_t** custom_fields,
        size_t custom_fields_len,
        const field_t* end_cum_comm_tree_root,
        uint64_t btr_fee,
        uint64_t ft_min_amount,
        const sc_pk_t* pk,
        const path_char_t* proof_path,
        size_t proof_path_len,
        uint32_t num_constraints,
        CctpErrorCode* ret_code,
        bool compress_proof = true
    );

    /*
     * Generates, given the required witnesses and the proving key, a CSWTestCircuit proof and saves it,
     * in compressed or uncompressed form, depending on the value of `compress_proof` flag, at specified path.
     * Return true if operation was successful, false otherwise.
     * `cert_data_hash` can be NULL and, if so, it will be replaced with a phantom value.
     */
     bool zendoo_create_csw_test_proof(
        bool zk,
        uint64_t amount,
        const field_t* sc_id,
        const field_t* nullifier,
        const BufferWithSize* mc_pk_hash,
        const field_t* cert_data_hash,
        const field_t* end_cum_comm_tree_root,
        const sc_pk_t* pk,
        const path_char_t* proof_path,
        size_t proof_path_len,
        uint32_t num_constraints,
        CctpErrorCode* ret_code,
        bool compress_proof = true
    );

    /*
     * Generates, given the required witnesses and the proving key, a CertTestCircuit proof, and saves it,
     * in compressed or uncompressed form, depending on the value of `compress_proof` flag, at specified path.
     * NOTE: `constant`, `bt_list` and `custom_fields` can be null.
     * Return true if operation was successful, false otherwise.
     */
    BufferWithSize* zendoo_create_return_cert_test_proof(
        bool zk,
        const field_t* constant,
        const field_t* sc_id,
        uint32_t epoch_number,
        uint64_t quality,
        const backward_transfer_t* bt_list,
        size_t bt_list_len,
        const field_t** custom_fields,
        size_t custom_fields_len,
        const field_t* end_cum_comm_tree_root,
        uint64_t btr_fee,
        uint64_t ft_min_amount,
        const sc_pk_t* pk,
        uint32_t num_constraints,
        CctpErrorCode* ret_code,
        bool compress_proof = true
    );

    /*
     * Generates, given the required witnesses and the proving key, a CSWTestCircuit proof, and saves it,
     * in compressed or uncompressed form, depending on the value of `compress_proof` flag, at specified path.
     * Return true if operation was successful, false otherwise.
     * `cert_data_hash` can be NULL and, if so, it will be replaced with a phantom value.
     */
     BufferWithSize* zendoo_create_return_csw_test_proof(
        bool zk,
        uint64_t amount,
        const field_t* sc_id,
        const field_t* nullifier,
        const BufferWithSize* mc_pk_hash,
        const field_t* cert_data_hash,
        const field_t* end_cum_comm_tree_root,
        const sc_pk_t* pk,
        uint32_t num_constraints,
        CctpErrorCode* ret_code,
        bool compress_proof = true
    );

     /* Return `true` if the proofs pointed by `sc_proof_1` and `sc_proof_2` are
      * equal, and `false` otherwise.
      */
     bool zendoo_sc_proof_assert_eq(
         const sc_proof_t* sc_proof_1,
         const sc_proof_t* sc_proof_2
     );

}

#endif // ZENDOO_MC_INCLUDE_H_
