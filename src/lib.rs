use algebra::{UniformRand, CanonicalSerialize};
use libc::{c_uchar, c_uint};
use rand::rngs::OsRng;
use std::{
    convert::TryInto,
    ptr::null_mut,
    path::Path,
    slice,
    fmt::Write,
};

#[cfg(not(target_os = "windows"))]
use std::{ffi::OsStr, os::unix::ffi::OsStrExt};

#[cfg(target_os = "windows")]
use std::{ffi::OsString, os::windows::ffi::OsStringExt};

use cctp_primitives::{
    bit_vector::{compression::*, merkle_tree::*},
    commitment_tree::CommitmentTree,
    proving_system::{
        *, error::ProvingSystemError,
        verifier::{
            certificate::CertificateProofUserInputs,
            verify_zendoo_proof, batch_verifier::ZendooBatchVerifier,
            ceased_sidechain_withdrawal::CSWProofUserInputs,
        }
    },
    utils::{
        data_structures::{BitVectorElementsConfig, BackwardTransfer},
        poseidon_hash::*, mht::*, serialization::{deserialize_from_buffer, serialize_to_buffer},
        compute_sc_id,
    },
};

pub mod type_mapping;
use type_mapping::*;

#[macro_use]
pub mod macros;
use macros::*;

#[cfg(feature = "mc-test-circuit")]
pub mod mc_test_circuits;

#[cfg(feature = "mc-test-circuit")]
use cctp_primitives::utils::serialization::write_to_file;
use cctp_primitives::utils::get_cert_data_hash;

//#[cfg(test)]
//pub mod tests;

pub(crate) fn free_pointer<T> (ptr: *mut T) {
    if ptr.is_null() { return };

    unsafe { drop( Box::from_raw(ptr)) }
}

pub(crate) fn get_hex<T: CanonicalSerialize>(elem: &T) -> String {
    let mut hex_string = String::from("0x");
    let elem_bytes = serialize_to_buffer(elem).unwrap();

    for byte in elem_bytes {
        write!(hex_string, "{:02x}", byte).unwrap();
    }

    hex_string
}

#[cfg(not(target_os = "windows"))]
fn parse_path<'a>(
    path:       *const u8,
    path_len:   usize,
) -> &'a Path
{
    Path::new(OsStr::from_bytes(unsafe {
        slice::from_raw_parts(path, path_len)
    }))
}

#[no_mangle]
pub extern "C" fn zendoo_free_bws(buffer: *mut BufferWithSize) {
    free_buffer_with_size(buffer)
}

//*********** Commitment Tree functions ****************

#[no_mangle]
pub extern "C" fn zendoo_commitment_tree_create() -> *mut CommitmentTree {
    Box::into_raw(Box::new(CommitmentTree::create()))
}

#[no_mangle]
pub extern "C" fn zendoo_commitment_tree_delete(ptr : *mut CommitmentTree) {
    free_pointer(ptr)
}

#[no_mangle]
pub extern "C" fn zendoo_get_sc_custom_data_size_in_bytes() -> c_uint {
    CUSTOM_DATA_MAX_SIZE as u32
}

#[no_mangle]
pub extern "C" fn zendoo_compute_sc_id(
    tx_hash:    *const BufferWithSize,
    pos:        u32,
    ret_code:   &mut CctpErrorCode,
) -> *mut FieldElement
{
    let rs_tx_hash = try_get_buffer_constant_size!("tx_hash", tx_hash, UINT_256_SIZE, ret_code, null_mut());
    match compute_sc_id(rs_tx_hash, pos) {
        Ok(sc_id) => Box::into_raw(Box::new(sc_id)),
        Err(e) => {
            *ret_code = CctpErrorCode::HashingError;
            println!("{:?}", format!("Error computing sc_id: {:?}", e));
            null_mut()
        }
    }
}

#[no_mangle]
pub extern "C" fn zendoo_commitment_tree_add_scc(
    ptr :                           *mut CommitmentTree,
    sc_id:                          *const FieldElement,
    amount:                         u64,
    pub_key:                        *const BufferWithSize,
    tx_hash:                        *const BufferWithSize,
    out_idx:                        u32,
    withdrawal_epoch_length:        u32,
    mc_btr_request_data_length:     u8,
    custom_field_elements_config:   *const BufferWithSize,
    custom_bv_elements_config:      *const BitVectorElementsConfig,
    custom_bv_elements_config_len:  usize,
    btr_fee:                        u64,
    ft_min_amount:                  u64,
    ccd:                            *const BufferWithSize,
    constant:                       *const FieldElement,
    cert_vk:                        *const BufferWithSize,
    csw_vk:                         *const BufferWithSize,
    ret_code:                       &mut CctpErrorCode
)-> bool
{

    // Get commitment tree pointer
    let cmt = try_read_mut_raw_pointer!("commitment_tree", ptr, ret_code, false);

    // Mandatory and constant size parameters
    let rs_sc_id        = try_read_raw_pointer!("sc_id", sc_id, ret_code, false);
    let rs_pub_key      = try_get_buffer_constant_size!("pub_key", pub_key, UINT_256_SIZE, ret_code, false);
    let rs_tx_hash      = try_get_buffer_constant_size!("tx_hash", tx_hash, UINT_256_SIZE, ret_code, false);

    // Mandatory and variable size parameters
    let rs_cert_vk = try_get_buffer_variable_size!("cert_vk", cert_vk, ret_code, false);

    // optional parameters
    let rs_custom_bv_elements_config = try_get_optional_obj_list!(
        "custom_bit_vector_elements",
        custom_bv_elements_config,
        custom_bv_elements_config_len,
        ret_code,
        false
    );
    let rs_custom_fe_conf = try_get_optional_buffer_variable_size!("custom_field_elements_config", custom_field_elements_config, ret_code, false);
    let rs_ccd            = try_get_optional_buffer_variable_size!("custom_creation_data",         ccd,                          ret_code, false);
    let rs_csw_vk         = try_get_optional_buffer_variable_size!("csw_vk",                       csw_vk,                       ret_code, false);
    let rs_constant       = try_read_optional_raw_pointer!("constant", constant, ret_code, false);

    // Add SidechainCreation to the CommitmentTree
    let ret = cmt.add_scc(
        rs_sc_id, amount, rs_pub_key, rs_tx_hash, out_idx, withdrawal_epoch_length,
        mc_btr_request_data_length, rs_custom_fe_conf, rs_custom_bv_elements_config,
        btr_fee, ft_min_amount, rs_ccd, rs_constant, rs_cert_vk, rs_csw_vk
    );

    if !ret {
        *ret_code = CctpErrorCode::GenericError;
        println!("{:?}", "add_scc() failed!");
    }
    ret
}

#[no_mangle]
pub extern "C" fn zendoo_commitment_tree_add_fwt(
    ptr :       *mut CommitmentTree,
    sc_id:      *const FieldElement,
    amount:     u64,
    pub_key:    *const BufferWithSize,
    tx_hash:    *const BufferWithSize,
    out_idx:    u32,
    ret_code:   &mut CctpErrorCode
)-> bool
{

    // Get commitment tree pointer
    let cmt = try_read_mut_raw_pointer!("commitment_tree", ptr, ret_code, false);

    // Mandatory and constant size parameters
    let rs_sc_id = try_read_raw_pointer!("sc_id", sc_id, ret_code, false);
    let rs_pub_key = try_get_buffer_constant_size!("pub_key", pub_key, UINT_256_SIZE, ret_code, false);
    let rs_tx_hash = try_get_buffer_constant_size!("tx_hash", tx_hash, UINT_256_SIZE, ret_code, false);

    // Add ForwardTransfer to the CommitmentTree
    let ret = cmt.add_fwt(rs_sc_id, amount, rs_pub_key, rs_tx_hash, out_idx);

    if !ret {
        *ret_code = CctpErrorCode::GenericError;
        println!("{:?}", "add_fwt() failed!");
    }
    ret
}

#[no_mangle]
pub extern "C" fn zendoo_commitment_tree_add_bwtr(
    ptr:                    *mut CommitmentTree,
    sc_id:                  *const FieldElement,
    sc_fee:                 u64,
    sc_req_data:            *const *const FieldElement,
    sc_req_data_len:        usize,
    mc_dest_addr:           *const BufferWithSize,
    tx_hash:                *const BufferWithSize,
    out_idx:                u32,
    ret_code:               &mut CctpErrorCode
)-> bool
{

    // Get commitment tree pointer
    let cmt = try_read_mut_raw_pointer!("commitment tree", ptr, ret_code, false);

    // Mandatory and constant size parameters
    let rs_sc_id = try_read_raw_pointer!("sc_id", sc_id, ret_code, false);
    let rs_mc_dest_addr = try_get_buffer_constant_size!("mc_dest_addr", mc_dest_addr, UINT_160_SIZE, ret_code, false);
    let rs_tx_hash      = try_get_buffer_constant_size!("tx_hash",      tx_hash,      UINT_256_SIZE, ret_code, false);

    // Read sc_req_data_list
    let rs_sc_req_data = try_read_double_raw_pointer!("sc_req_data", sc_req_data, sc_req_data_len, ret_code, false);

    let ret = cmt.add_bwtr(
        rs_sc_id, sc_fee, rs_sc_req_data, rs_mc_dest_addr, rs_tx_hash, out_idx);

    if !ret {
        *ret_code = CctpErrorCode::GenericError;
        println!("{:?}", "add_bwtr() failed!");
    }
    ret
}

#[no_mangle]
pub extern "C" fn zendoo_commitment_tree_add_csw(
    ptr :       *mut CommitmentTree,
    sc_id:      *const FieldElement,
    amount:     u64,
    nullifier:  *const FieldElement,
    pk_hash:    *const BufferWithSize,
    ret_code:   &mut CctpErrorCode
)-> bool
{

    // Get commitment tree pointer
    let cmt = try_read_mut_raw_pointer!("commitment_tree", ptr, ret_code, false);

    let rs_sc_id     = try_read_raw_pointer!("sc_id", sc_id, ret_code, false);
    let rs_pk_hash   = try_get_buffer_constant_size!("pk_hash",   pk_hash,   UINT_160_SIZE, ret_code, false);
    let rs_nullifier = try_read_raw_pointer!("nullifier", nullifier, ret_code, false);

    let ret = cmt.add_csw(rs_sc_id, amount, rs_nullifier, rs_pk_hash);

    if !ret {
        *ret_code = CctpErrorCode::GenericError;
        println!("{:?}", "add_csw() failed !");
    }
    ret
}

#[no_mangle]
pub extern "C" fn zendoo_commitment_tree_add_cert(
    ptr :                   *mut CommitmentTree,
    sc_id:                  *const FieldElement,
    epoch_number:           u32,
    quality:                u64,
    bt_list:                *const BackwardTransfer,
    bt_list_len:            usize,
    custom_fields:          *const *const FieldElement,
    custom_fields_len:      usize,
    end_cum_comm_tree_root: *const FieldElement,
    btr_fee:                u64,
    ft_min_amount:          u64,
    ret_code :              &mut CctpErrorCode
)-> bool
{

    // Get commitment tree pointer
    let cmt = try_read_mut_raw_pointer!("commitment_tree", ptr, ret_code, false);

    // Read mandatory, constant size data
    let rs_sc_id = try_read_raw_pointer!("sc_id", sc_id, ret_code, false);
    let rs_end_cum_comm_tree_root = try_read_raw_pointer!("end_cum_comm_tree_root", end_cum_comm_tree_root,    ret_code, false);

    // Read bt_list
    let rs_bt_list = try_get_optional_obj_list!("bt_list", bt_list, bt_list_len, ret_code, false);

    // Read custom fields list (if present)
    let rs_custom_fields = try_read_optional_double_raw_pointer!(
        "custom_fields", custom_fields, custom_fields_len, ret_code, false
    );

    // Add certificate to ScCommitmentTree
    let ret = cmt.add_cert(
        rs_sc_id, epoch_number, quality, rs_bt_list,
        rs_custom_fields, rs_end_cum_comm_tree_root, btr_fee, ft_min_amount
    );

    if !ret {
        *ret_code = CctpErrorCode::GenericError;
        println!("{:?}", "add_cert() failed");
    }
    ret
}

#[no_mangle]
pub extern "C" fn zendoo_commitment_tree_get_commitment(
    ptr:      *mut CommitmentTree,
    ret_code: &mut CctpErrorCode,
) -> *mut FieldElement
{

    // Get commitment tree pointer
    let cmt = try_read_mut_raw_pointer!("commitment_tree", ptr, ret_code, null_mut());

    match cmt.get_commitment() {
        Some(commitment) => Box::into_raw(Box::new(commitment)),
        None =>  {
            *ret_code = CctpErrorCode::GenericError;
            println!("{:?}", "get_commitment() failed!");
            null_mut()
        }
    }
}

//***********Bit Vector functions****************


#[no_mangle]
pub extern "C" fn zendoo_compress_bit_vector(
    buffer:    *const BufferWithSize,
    algorithm: CompressionAlgorithm,
    ret_code:  &mut CctpErrorCode
) -> *mut BufferWithSize
{

    let bit_vector = try_get_buffer_variable_size!("bit_vector", buffer, ret_code, null_mut());

    match compress_bit_vector(bit_vector, algorithm) {
        Ok(mut compressed_bit_vector) => {
            let data = compressed_bit_vector.as_mut_ptr();
            let len = compressed_bit_vector.len();
            assert_eq!(len, compressed_bit_vector.capacity());
            std::mem::forget(compressed_bit_vector);
            let bit_vector_buffer = BufferWithSize {data, len};

            Box::into_raw(Box::new(bit_vector_buffer))
        },
        Err(_) => {
            *ret_code = CctpErrorCode::CompressError;
            println!("{:?}", "compress_bit_vector() failed !");
            null_mut()
        }
    }
}

#[no_mangle]
pub extern "C" fn zendoo_decompress_bit_vector(
    buffer: *const BufferWithSize,
    expected_uncompressed_size: usize,
    ret_code: &mut CctpErrorCode
) -> *mut BufferWithSize
{
    let compressed_slice = try_get_buffer_variable_size!("compressed_bit_vector", buffer, ret_code, null_mut());

    match decompress_bit_vector(compressed_slice, expected_uncompressed_size) {
        Ok(mut decompressed_bit_vector) => {
            let data = decompressed_bit_vector.as_mut_ptr();
            let len = decompressed_bit_vector.len();
            std::mem::forget(decompressed_bit_vector);
            let bit_vector_buffer = BufferWithSize {data, len};

            Box::into_raw(Box::new(bit_vector_buffer))
        },
        Err(e) => {
            println!("===> {}", e);
            *ret_code = CctpErrorCode::UncompressError;
            null_mut()
        }
    }
}

#[no_mangle]
pub extern "C" fn zendoo_merkle_root_from_compressed_bytes(
    buffer: *const BufferWithSize,
    expected_uncompressed_size: usize,
    ret_code: &mut CctpErrorCode
) -> *mut FieldElement
{
    let compressed_slice = try_get_buffer_variable_size!("compressed bytes", buffer, ret_code, null_mut());

    match merkle_root_from_compressed_bytes(compressed_slice, expected_uncompressed_size)
        {
            Ok(x) =>  {

                Box::into_raw(Box::new(x))
            },
            Err(e) => {
                println!("===> {}", e);
                *ret_code = CctpErrorCode::MerkleRootBuildError;
                null_mut()
            }
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


//***********Field functions****************
#[no_mangle]
pub extern "C" fn zendoo_get_field_size_in_bytes() -> c_uint {
    FIELD_SIZE as u32
}

#[no_mangle]
pub extern "C" fn zendoo_serialize_field(
    field_element: *const FieldElement,
    result: *mut [c_uchar; FIELD_SIZE],
    ret_code: &mut CctpErrorCode
) -> bool
{
    try_serialize_from_raw_pointer!("field_element", field_element, &mut (unsafe { &mut *result })[..], ret_code, false);
    true
}

#[no_mangle]
pub extern "C" fn zendoo_deserialize_field(
    field_bytes: *const [c_uchar; FIELD_SIZE],
    ret_code: &mut CctpErrorCode
) -> *mut FieldElement
{
    try_deserialize_to_raw_pointer!("field_bytes", &(unsafe { &*field_bytes })[..], true, ret_code, null_mut())
}

#[no_mangle]
pub extern "C" fn zendoo_field_free(field: *mut FieldElement) { free_pointer(field) }

#[no_mangle]
pub extern "C" fn zendoo_print_field(field: *const FieldElement) {
    let ret_code = &mut CctpErrorCode::OK;
    let rs_field = try_read_raw_pointer!("field", field, ret_code, ());
    println!("{:?}", get_hex(rs_field));
}

////********************Sidechain SNARK functions********************

fn _zendoo_init_dlog_keys(
    max_segment_size: usize,
    supported_segment_size: usize,
    params_dir: &Path,
    ret_code: &mut CctpErrorCode
) -> bool
{
    let ck_g1_path = params_dir.join("ck_g1");
    let ck_g2_path = params_dir.join("ck_g2");

    match init_dlog_keys(
        ProvingSystem::Darlin,
        max_segment_size,
        supported_segment_size,
        &ck_g1_path,
        &ck_g2_path
    ) {
        Ok(()) => true,
        Err(e) => {
            println!("{:?}", format!("Error bootstrapping DLOG keys: {:?}", e));
            *ret_code = CctpErrorCode::GenericError;
            false
        }
    }
}

#[cfg(target_os = "windows")]
#[no_mangle]
pub extern "C" fn zendoo_init_dlog_keys(
    segment_size: usize,
    params_dir: *const u16,
    params_dir_len: usize,
    ret_code: &mut CctpErrorCode
) -> bool
{
    // Read params_dir
    let path_str = OsString::from_wide(unsafe {
        slice::from_raw_parts(params_dir, params_dir_len)
    });
    let params_dir = Path::new(&path_str);

    // Get DLOG keys
    _zendoo_init_dlog_keys(segment_size, segment_size, params_dir, ret_code)
}

#[cfg(not(target_os = "windows"))]
#[no_mangle]
pub extern "C" fn zendoo_init_dlog_keys(
    segment_size: usize,
    params_dir: *const u8,
    params_dir_len: usize,
    ret_code: &mut CctpErrorCode
) -> bool
{
    // Read params_dir
    let params_dir = parse_path(params_dir, params_dir_len);

    // Get DLOG keys
    _zendoo_init_dlog_keys(segment_size, segment_size, params_dir, ret_code)
}

#[cfg(target_os = "windows")]
#[no_mangle]
pub extern "C" fn zendoo_init_dlog_keys_test_mode(
    max_segment_size: usize,
    supported_segment_size: usize,
    params_dir: *const u16,
    params_dir_len: usize,
    ret_code: &mut CctpErrorCode
) -> bool
{
    // Read params_dir
    let path_str = OsString::from_wide(unsafe {
        slice::from_raw_parts(params_dir, params_dir_len)
    });
    let params_dir = Path::new(&path_str);

    // Get DLOG keys
    _zendoo_init_dlog_keys(max_segment_size, supported_segment_size, params_dir, ret_code)
}

#[cfg(not(target_os = "windows"))]
#[no_mangle]
pub extern "C" fn zendoo_init_dlog_keys_test_mode(
    max_segment_size: usize,
    supported_segment_size: usize,
    params_dir: *const u8,
    params_dir_len: usize,
    ret_code: &mut CctpErrorCode
) -> bool
{
    // Read params_dir
    let params_dir = parse_path(params_dir, params_dir_len);

    // Get DLOG keys
    _zendoo_init_dlog_keys(max_segment_size, supported_segment_size, params_dir, ret_code)
}

#[no_mangle]
pub extern "C" fn zendoo_serialize_sc_proof(
    sc_proof: *const ZendooProof,
    ret_code: &mut CctpErrorCode,
) -> *mut BufferWithSize
{
    let sc_proof = try_read_raw_pointer!("proof", sc_proof, ret_code, null_mut());
    match serialize_to_buffer(sc_proof) {
        Ok(mut sc_proof_bytes) => {

            let data = sc_proof_bytes.as_mut_ptr();
            let len = sc_proof_bytes.len();
            std::mem::forget(sc_proof_bytes);
            Box::into_raw(Box::new(BufferWithSize { data, len }))
        },
        Err(e) => {
            println!("{:?}", format!("Error serializing proof {:?}", e));
            *ret_code = CctpErrorCode::InvalidValue;
            null_mut()
        }
    }
}

#[no_mangle]
pub extern "C" fn zendoo_deserialize_sc_proof(
    sc_proof_bytes:  *const BufferWithSize,
    semantic_checks: bool,
    ret_code:        &mut CctpErrorCode,
) -> *mut ZendooProof
{
    let sc_proof_bytes = try_get_buffer_variable_size!("sc_proof_buffer", sc_proof_bytes, ret_code, null_mut());
    try_deserialize_to_raw_pointer!("sc_proof_bytes", sc_proof_bytes, semantic_checks, ret_code, null_mut())
}

#[no_mangle]
pub extern "C" fn zendoo_get_sc_proof_proving_system_type(
    sc_proof: *const ZendooProof,
    ret_code: &mut CctpErrorCode
) -> ProvingSystem
{
    let sc_proof = try_read_raw_pointer!("sc_proof", sc_proof, ret_code, ProvingSystem::Undefined);
    sc_proof.get_proving_system_type()
}

#[no_mangle]
pub extern "C" fn zendoo_sc_proof_free(proof: *mut ZendooProof) {
    free_pointer(proof)
}

#[cfg(not(target_os = "windows"))]
#[no_mangle]
pub extern "C" fn zendoo_deserialize_sc_vk_from_file(
    vk_path: *const u8,
    vk_path_len: usize,
    semantic_checks: bool,
    ret_code: &mut CctpErrorCode
) -> *mut ZendooVerifierKey
{
    // Read file path
    let vk_path = parse_path(vk_path, vk_path_len);

    // Deserialize vk
    try_deserialize_to_raw_pointer_from_file!("vk", vk_path, semantic_checks, ret_code, null_mut())
}

#[cfg(target_os = "windows")]
#[no_mangle]
pub extern "C" fn zendoo_deserialize_sc_vk_from_file(
    vk_path: *const u16,
    vk_path_len: usize,
    semantic_checks: bool,
    ret_code: &mut CctpErrorCode
) -> *mut ZendooVerifierKey
{
    // Read file path
    let path_str = OsString::from_wide(unsafe {
        slice::from_raw_parts(vk_path, vk_path_len)
    });
    let vk_path = Path::new(&path_str);

    // Deserialize vk
    try_deserialize_to_raw_pointer_from_file!("vk", vk_path, semantic_checks, ret_code, null_mut())
}

#[no_mangle]
pub extern "C" fn zendoo_deserialize_sc_vk(
    sc_vk_bytes:     *const BufferWithSize,
    semantic_checks: bool,
    ret_code:        &mut CctpErrorCode,
) -> *mut ZendooVerifierKey {
    let sc_vk_bytes = try_get_buffer_variable_size!("sc_vk_buffer", sc_vk_bytes, ret_code, null_mut());
    try_deserialize_to_raw_pointer!("sc_vk_bytes", sc_vk_bytes, semantic_checks, ret_code, null_mut())
}

#[no_mangle]
pub extern "C" fn zendoo_get_sc_vk_proving_system_type(
    sc_vk: *const ZendooVerifierKey,
    ret_code: &mut CctpErrorCode
) -> ProvingSystem
{
    let sc_vk = try_read_raw_pointer!("sc_vk", sc_vk, ret_code, ProvingSystem::Undefined);
    sc_vk.get_proving_system_type()
}

#[no_mangle]
pub extern "C" fn zendoo_sc_vk_free(sc_vk: *mut ZendooVerifierKey) {
    free_pointer(sc_vk)
}

fn get_cert_proof_usr_ins<'a>(
    constant:               *const FieldElement,
    epoch_number:           u32,
    quality:                u64,
    bt_list:                *const BackwardTransfer,
    bt_list_len:            usize,
    custom_fields:          *const *const FieldElement,
    custom_fields_len:      usize,
    end_cum_comm_tree_root: *const FieldElement,
    btr_fee:                u64,
    ft_min_amount:          u64,
    ret_code:               &mut CctpErrorCode
) -> Option<CertificateProofUserInputs<'a>>
{
    // Read bt_list
    let rs_bt_list = try_get_optional_obj_list!("bt_list", bt_list, bt_list_len, ret_code, None);

    // Read mandatory, constant size data
    let rs_end_cum_comm_tree_root = try_read_raw_pointer!("end_cum_comm_tree_root", end_cum_comm_tree_root, ret_code, None);

    // Read optional data
    let rs_custom_fields = try_read_optional_double_raw_pointer!(
        "custom_fields", custom_fields, custom_fields_len, ret_code, None
    );
    let rs_constant = try_read_optional_raw_pointer!("constant", constant, ret_code, None);

    // Create and return inputs
    Some(CertificateProofUserInputs {
        constant: rs_constant,
        epoch_number,
        quality,
        bt_list: rs_bt_list,
        custom_fields: rs_custom_fields,
        end_cumulative_sc_tx_commitment_tree_root: rs_end_cum_comm_tree_root,
        btr_fee,
        ft_min_amount
    })
}

#[no_mangle]
pub extern "C" fn zendoo_verify_certificate_proof(
    constant:               *const FieldElement,
    epoch_number:           u32,
    quality:                u64,
    bt_list:                *const BackwardTransfer,
    bt_list_len:            usize,
    custom_fields:          *const *const FieldElement,
    custom_fields_len:      usize,
    end_cum_comm_tree_root: *const FieldElement,
    btr_fee:                u64,
    ft_min_amount:          u64,
    sc_proof:               *const ZendooProof,
    sc_vk:                  *const ZendooVerifierKey,
    ret_code:               &mut CctpErrorCode
) -> bool
{
    // Get usr_ins
    let usr_ins = get_cert_proof_usr_ins(
        constant, epoch_number, quality, bt_list, bt_list_len, custom_fields, custom_fields_len,
        end_cum_comm_tree_root, btr_fee, ft_min_amount, ret_code
    );
    if usr_ins.is_none() { return false; }

    // Read proof and vk
    let sc_proof = try_read_raw_pointer!("sc_proof", sc_proof, ret_code, false);
    let sc_vk =    try_read_raw_pointer!("sc_vk",    sc_vk,    ret_code, false);

    // Verify proof
    match verify_zendoo_proof(usr_ins.unwrap(), sc_proof, sc_vk, Some(&mut OsRng::default())) {
        Ok(res) => res,
        Err(e) => {
            println!("{:?}", format!("Proof verification failure {:?}", e));
            match e {
                ProvingSystemError::ProofVerificationFailed(_) => *ret_code = CctpErrorCode::OK,
                _ => *ret_code = CctpErrorCode::ProofVerificationFailure,
            }
            false
        }
    }
}

fn get_csw_proof_usr_ins<'a>(
    amount:                 u64,
    sc_id:                  *const FieldElement,
    nullifier:              *const FieldElement,
    mc_pk_hash:             *const BufferWithSize,
    cert_data_hash:         *const FieldElement,
    end_cum_comm_tree_root: *const FieldElement,
    ret_code:               &mut CctpErrorCode
) -> Option<CSWProofUserInputs<'a>>
{
    // Read constant size data
    let rs_sc_id = try_read_raw_pointer!("sc_id", sc_id, ret_code, None);
    let rs_nullifier = try_read_raw_pointer!("nullifier", nullifier, ret_code, None);
    let rs_mc_pk_hash = try_get_buffer_constant_size!("mc_pk_hash", mc_pk_hash, UINT_160_SIZE, ret_code, None);

    // Read field element
    let rs_cert_data_hash =         try_read_raw_pointer!("cert_data_hash",         cert_data_hash,         ret_code, None);
    let rs_end_cum_comm_tree_root = try_read_raw_pointer!("end_cum_comm_tree_root", end_cum_comm_tree_root, ret_code, None);

    // Create and return usr ins
    Some(CSWProofUserInputs{
        amount,
        sc_id: rs_sc_id,
        nullifier: rs_nullifier,
        pub_key_hash: rs_mc_pk_hash,
        cert_data_hash: rs_cert_data_hash,
        end_cumulative_sc_tx_commitment_tree_root: rs_end_cum_comm_tree_root
    })
}

#[no_mangle]
pub extern "C" fn zendoo_get_phantom_cert_data_hash() -> *mut FieldElement {
    Box::into_raw(Box::new(cctp_primitives::proving_system::verifier::ceased_sidechain_withdrawal::PHANTOM_CERT_DATA_HASH))
}

#[no_mangle]
pub extern "C" fn zendoo_get_cert_data_hash(
    epoch_number:           u32,
    quality:                u64,
    bt_list:                *const BackwardTransfer,
    bt_list_len:            usize,
    custom_fields:          *const *const FieldElement,
    custom_fields_len:      usize,
    end_cum_comm_tree_root: *const FieldElement,
    btr_fee:                u64,
    ft_min_amount:          u64,
    ret_code :              &mut CctpErrorCode
) -> *mut FieldElement {

    // Read mandatory, constant size data
    let rs_end_cum_comm_tree_root = try_read_raw_pointer!("end_cum_comm_tree_root", end_cum_comm_tree_root, ret_code, null_mut());

    // Read bt_list
    let rs_bt_list = try_get_optional_obj_list!("bt_list", bt_list, bt_list_len, ret_code, null_mut());

    // Read custom fields list (if present)
    let rs_custom_fields = try_read_optional_double_raw_pointer!(
        "custom_fields", custom_fields, custom_fields_len, ret_code, null_mut()
    );

    match get_cert_data_hash(
        epoch_number,
        quality,
        rs_bt_list,
        rs_custom_fields,
        rs_end_cum_comm_tree_root,
        btr_fee,
        ft_min_amount
    ) {
        Ok(hash) => Box::into_raw(Box::new(hash)),
        Err(e) => {
            println!("{:?}", format!("Error computing cert_data_hash: {:?}", e));
            *ret_code = CctpErrorCode::HashingError;
            null_mut()
        }
    }
}

#[no_mangle]
pub extern "C" fn zendoo_verify_csw_proof(
    amount:                 u64,
    sc_id:                  *const FieldElement,
    nullifier:              *const FieldElement,
    mc_pk_hash:             *const BufferWithSize,
    cert_data_hash:         *const FieldElement,
    end_cum_comm_tree_root: *const FieldElement,
    sc_proof:               *const ZendooProof,
    sc_vk:                  *const ZendooVerifierKey,
    ret_code:               &mut CctpErrorCode
) -> bool
{
    // Get usr_ins
    let usr_ins = get_csw_proof_usr_ins(
        amount, sc_id, nullifier, mc_pk_hash, cert_data_hash,
        end_cum_comm_tree_root, ret_code
    );
    if usr_ins.is_none() { return false; }

    // Read proof and vk
    let sc_proof = try_read_raw_pointer!("sc_proof", sc_proof, ret_code, false);
    let sc_vk =    try_read_raw_pointer!("sc_vk",    sc_vk,    ret_code, false);

    // Verify proof
    match verify_zendoo_proof(usr_ins.unwrap(), sc_proof, sc_vk, Some(&mut OsRng::default())) {
        Ok(res) => res,
        Err(e) => {
            println!("{:?}", format!("Proof verification failure {:?}", e));
            match e {
                ProvingSystemError::ProofVerificationFailed(_) => *ret_code = CctpErrorCode::OK,
                _ => *ret_code = CctpErrorCode::ProofVerificationFailure,
            }
            false
        }
    }
}

//********************Batch verifier functions*******************

#[repr(C)]
pub struct ZendooBatchProofVerifierResult {
    pub result:         bool,
    pub failing_proof:  i64,
}

impl Default for ZendooBatchProofVerifierResult {
    fn default() -> Self {
        Self { result: false, failing_proof: -1 }
    }
}

#[no_mangle]
pub extern "C" fn zendoo_create_batch_proof_verifier() -> *mut ZendooBatchVerifier {
    Box::into_raw(Box::new(ZendooBatchVerifier::create()))
}

#[no_mangle]
pub extern "C" fn zendoo_add_certificate_proof_to_batch_verifier(
    batch_verifier:         *mut ZendooBatchVerifier,
    proof_id:               u32,
    constant:               *const FieldElement,
    epoch_number:           u32,
    quality:                u64,
    bt_list:                *const BackwardTransfer,
    bt_list_len:            usize,
    custom_fields:          *const *const FieldElement,
    custom_fields_len:      usize,
    end_cum_comm_tree_root: *const FieldElement,
    btr_fee:                u64,
    ft_min_amount:          u64,
    sc_proof:               *const ZendooProof,
    sc_vk:                  *const ZendooVerifierKey,
    ret_code:               &mut CctpErrorCode
) -> bool
{
    // Get usr_ins
    let usr_ins = get_cert_proof_usr_ins(
        constant, epoch_number, quality, bt_list, bt_list_len, custom_fields, custom_fields_len,
        end_cum_comm_tree_root, btr_fee, ft_min_amount, ret_code
    );
    if usr_ins.is_none() { return false; }

    // Read batch_verifier
    let rs_batch_verifier = try_read_mut_raw_pointer!("batch_verifier", batch_verifier, ret_code, false);

    // Read proof and vk
    let sc_proof = try_read_raw_pointer!("sc_proof", sc_proof, ret_code, false);
    let sc_vk =    try_read_raw_pointer!("sc_vk",    sc_vk,    ret_code, false);

    // Add proof to the batch
    match rs_batch_verifier.add_zendoo_proof_verifier_data(
        proof_id, usr_ins.unwrap(), sc_proof.clone(), sc_vk.clone()
    ) {
        Ok(()) => true,
        Err(e) => {
            println!("{:?}", format!("Error adding proof to the batch: {:?}", e));
            *ret_code = CctpErrorCode::BatchVerifierFailure;
            false
        }
    }
}

#[no_mangle]
pub extern "C" fn zendoo_add_csw_proof_to_batch_verifier(
    batch_verifier:         *mut ZendooBatchVerifier,
    proof_id:               u32,
    amount:                 u64,
    sc_id:                  *const FieldElement,
    nullifier:              *const FieldElement,
    mc_pk_hash:             *const BufferWithSize,
    cert_data_hash:         *const FieldElement,
    end_cum_comm_tree_root: *const FieldElement,
    sc_proof:               *const ZendooProof,
    sc_vk:                  *const ZendooVerifierKey,
    ret_code:               &mut CctpErrorCode
) -> bool
{
    // Get usr_ins
    let usr_ins = get_csw_proof_usr_ins(
        amount, sc_id, nullifier, mc_pk_hash, cert_data_hash,
        end_cum_comm_tree_root, ret_code
    );
    if usr_ins.is_none() { return false; }

    // Read batch_verifier
    let rs_batch_verifier = try_read_mut_raw_pointer!("batch_verifier", batch_verifier, ret_code, false);

    // Read proof and vk
    let sc_proof = try_read_raw_pointer!("sc_proof", sc_proof, ret_code, false);
    let sc_vk =    try_read_raw_pointer!("sc_vk",    sc_vk,    ret_code, false);

    // Add proof to the batch
    match rs_batch_verifier.add_zendoo_proof_verifier_data(
        proof_id, usr_ins.unwrap(), sc_proof.clone(), sc_vk.clone()
    ) {
        Ok(()) => true,
        Err(e) => {
            println!("{:?}", format!("Error adding proof to the batch: {:?}", e));
            *ret_code = CctpErrorCode::BatchVerifierFailure;
            false
        }
    }
}

#[no_mangle]
pub extern "C" fn zendoo_batch_verify_all_proofs(
    batch_verifier: *const ZendooBatchVerifier,
    ret_code: &mut CctpErrorCode
) -> ZendooBatchProofVerifierResult
{
    // Read batch verifier
    let rs_batch_verifier = try_read_raw_pointer!("batch_verifier", batch_verifier, ret_code, ZendooBatchProofVerifierResult::default());

    // Trigger batch verification
    match rs_batch_verifier.batch_verify_all(&mut OsRng::default()) {

        // If success, return the result (of course there will be no failing_proof so set the value to -1)
        Ok(result) => ZendooBatchProofVerifierResult { result, failing_proof: -1 },

        // Otherwise, return the index of the failing proof if it's possible to estabilish it.
        Err(e) => {
            println!("{:?}", format!("Batch proof verification failure: {:?}", e));
            let mut result = ZendooBatchProofVerifierResult { result: false, failing_proof: -1 };

            match e {
                ProvingSystemError::FailedBatchVerification(maybe_id) => {
                    *ret_code = CctpErrorCode::OK;
                    if maybe_id.is_some() {
                        result.failing_proof = maybe_id.unwrap() as i64;
                    }
                },
                _ => *ret_code = CctpErrorCode::BatchVerifierFailure
            }
            result
        }
    }
}

#[no_mangle]
pub extern "C" fn zendoo_batch_verify_proofs_by_id(
    batch_verifier: *const ZendooBatchVerifier,
    ids_list: *const u32,
    ids_list_len: usize,
    ret_code: &mut CctpErrorCode
) -> ZendooBatchProofVerifierResult
{
    // Read batch verifier
    let rs_batch_verifier = try_read_raw_pointer!("batch_verifier", batch_verifier, ret_code, ZendooBatchProofVerifierResult::default());

    // Get ids_list
    let rs_ids_list = try_get_obj_list!("ids_list", ids_list, ids_list_len, ret_code, ZendooBatchProofVerifierResult::default());

    // Trigger batch verification of the proofs with specified id
    match rs_batch_verifier.batch_verify_subset(rs_ids_list.to_vec(), &mut OsRng::default()) {

        // If success, return the result (of course there will be no failing_proof so set the value to -1)
        Ok(result) => ZendooBatchProofVerifierResult { result, failing_proof: -1 },

        // Otherwise, return the index of the failing proof if it's possible to estabilish it.
        Err(e) => {
            println!("{:?}", format!("Batch proof verification failure: {:?}", e));
            let mut result = ZendooBatchProofVerifierResult { result: false, failing_proof: -1 };

            match e {
                ProvingSystemError::FailedBatchVerification(maybe_id) => {
                    *ret_code = CctpErrorCode::OK;
                    if maybe_id.is_some() {
                        result.failing_proof = maybe_id.unwrap() as i64;
                    }
                },
                _ => *ret_code = CctpErrorCode::BatchVerifierFailure
            }
            result
        }
    }
}

#[no_mangle]
pub extern "C" fn zendoo_free_batch_proof_verifier(batch_verifier: *mut ZendooBatchVerifier) {
    free_pointer(batch_verifier)
}

//********************Poseidon hash functions********************

#[no_mangle]
pub extern "C" fn zendoo_init_poseidon_hash_constant_length(
    input_size: usize,
    personalization: *const *const FieldElement,
    personalization_len: usize,
    ret_code: &mut CctpErrorCode
) -> *mut FieldHash {

    let personalization = try_read_optional_double_raw_pointer!("personalization", personalization, personalization_len, ret_code, null_mut());
    Box::into_raw(Box::new(get_poseidon_hash_constant_length(input_size, personalization)))
}

#[no_mangle]
pub extern "C" fn zendoo_init_poseidon_hash_variable_length(
    mod_rate: bool,
    personalization: *const *const FieldElement,
    personalization_len: usize,
    ret_code: &mut CctpErrorCode
) -> *mut FieldHash
{
    let personalization = try_read_optional_double_raw_pointer!("personalization", personalization, personalization_len, ret_code, null_mut());
    Box::into_raw(Box::new(get_poseidon_hash_variable_length(mod_rate, personalization)))
}

#[no_mangle]
pub extern "C" fn zendoo_update_poseidon_hash(
    fe: *const FieldElement,
    digest: *mut FieldHash,
    ret_code: &mut CctpErrorCode,
) -> bool
{
    let input = try_read_raw_pointer!("input_fe", fe, ret_code, false);
    let digest = try_read_mut_raw_pointer!("digest", digest, ret_code, false);

    update_poseidon_hash(digest, input);
    true
}

#[no_mangle]
pub extern "C" fn zendoo_update_poseidon_hash_from_raw(
    fe: *const BufferWithSize,
    digest: *mut FieldHash,
    ret_code: &mut CctpErrorCode,
) -> bool
{
    // Read digest
    let digest = try_read_mut_raw_pointer!("digest", digest, ret_code, false);

    // Read input bytes
    let input_bytes = try_get_buffer_constant_size!("input_fe_bytes", fe, FIELD_SIZE, ret_code, false);

    // Compute hash
    match deserialize_from_buffer(input_bytes) {
        Ok(fe) => {
            update_poseidon_hash(digest, &fe);
            true
        }
        Err(e) => {
            *ret_code = CctpErrorCode::InvalidBufferData;
            println!("{:?}", format!("Error deserializing input: {:?}", e));
            false
        }
    }
}

#[no_mangle]
pub extern "C" fn zendoo_finalize_poseidon_hash(
    digest: *const FieldHash,
    ret_code: &mut CctpErrorCode,
) -> *mut FieldElement
{
    let digest = try_read_raw_pointer!("digest", digest, ret_code, null_mut());

    match finalize_poseidon_hash(digest) {
        Ok(output) => Box::into_raw(Box::new(output)),
        Err(e) => {
            println!("{:?}", format!("Error finalizing the hash: {:?}", e));
            *ret_code = CctpErrorCode::HashingError;
            null_mut()
        }
    }
}

#[no_mangle]
pub extern "C" fn zendoo_reset_poseidon_hash(
    digest: *mut FieldHash,
    personalization: *const *const FieldElement,
    personalization_len: usize,
    ret_code: &mut CctpErrorCode,
) -> bool
{
    let digest = try_read_mut_raw_pointer!("digest", digest, ret_code, false);
    let personalization = try_read_optional_double_raw_pointer!("personalization", personalization, personalization_len, ret_code, false);
    reset_poseidon_hash(digest, personalization);
    true
}

#[no_mangle]
pub extern "C" fn zendoo_free_poseidon_hash(
    digest: *mut FieldHash
) { free_pointer(digest) }


// ********************Merkle Tree functions********************
#[no_mangle]
pub extern "C" fn zendoo_new_ginger_mht(
    height: usize,
    processing_step: usize,
) -> *mut GingerMHT {

    let gmt = new_ginger_mht(height, processing_step);
    Box::into_raw(Box::new(gmt))
}

#[no_mangle]
pub extern "C" fn zendoo_append_leaf_to_ginger_mht(
    leaf: *const FieldElement,
    tree: *mut GingerMHT,
    ret_code: &mut CctpErrorCode,
) -> bool
{
    let leaf = try_read_raw_pointer!("leaf", leaf, ret_code, false);
    let tree = try_read_mut_raw_pointer!("tree", tree, ret_code, false);

    match append_leaf_to_ginger_mht(tree, &leaf) {
        Ok(_) => true,
        Err(e) => {
            *ret_code = CctpErrorCode::MerkleTreeError;
            println!("{:?}", format!("Error appending leaf: {:?}", e));
            false
        }
    }
}

#[no_mangle]
pub extern "C" fn zendoo_append_leaf_to_ginger_mht_from_raw(
    leaf: *const BufferWithSize,
    tree: *mut GingerMHT,
    ret_code: &mut CctpErrorCode,
) -> bool
{
    // Read tree
    let tree = try_read_mut_raw_pointer!("tree", tree, ret_code, false);

    // Read leaf bytes
    let leaf_bytes = try_get_buffer_constant_size!("leaf_bytes", leaf, FIELD_SIZE, ret_code, false);

    match deserialize_from_buffer(leaf_bytes) {

        // Deserialization ok
        Ok(leaf) => {

            // Append leaf
            match append_leaf_to_ginger_mht(tree, &leaf) {
                Ok(_) => true,
                Err(e) => {
                    *ret_code = CctpErrorCode::MerkleTreeError;
                    println!("{:?}", format!("Error appending leaf: {:?}", e));
                    false
                }
            }
        }

        // Deserialization failure
        Err(e) => {
            *ret_code = CctpErrorCode::InvalidBufferData;
            println!("{:?}", format!("Error deserializing leaf: {:?}", e));
            false
        }
    }
}

#[no_mangle]
pub extern "C" fn zendoo_finalize_ginger_mht(
    tree: *const GingerMHT,
    ret_code: &mut CctpErrorCode,
) -> *mut GingerMHT
{
    // Read tree
    let tree = try_read_raw_pointer!("tree", tree, ret_code, null_mut());

    // Copy the tree and finalize
    let tree_copy = finalize_ginger_mht(tree);

    // Return the updated copy
    Box::into_raw(Box::new(tree_copy))
}

#[no_mangle]
pub extern "C" fn zendoo_finalize_ginger_mht_in_place(
    tree: *mut GingerMHT,
    ret_code: &mut CctpErrorCode,
) -> bool
{
    // Read tree
    let tree = try_read_mut_raw_pointer!("tree", tree, ret_code, false);

    finalize_ginger_mht_in_place(tree);
    true
}

#[no_mangle]
pub extern "C" fn zendoo_get_ginger_mht_root(
    tree: *const GingerMHT,
    ret_code: &mut CctpErrorCode,
) -> *mut FieldElement
{
    // Read tree
    let tree = try_read_raw_pointer!("tree", tree, ret_code, null_mut());

    // Get root if tree is finalized, otherwise return error
    match get_ginger_mht_root(tree) {
        Some(root) => Box::into_raw(Box::new(root)),
        None => {
            *ret_code = CctpErrorCode::MerkleRootBuildError;
            println!("{:?}", "Error: tree not finalized");
            null_mut()
        }
    }
}

#[no_mangle]
pub extern "C" fn zendoo_get_ginger_merkle_path(
    tree: *const GingerMHT,
    leaf_index: usize,
    ret_code: &mut CctpErrorCode,
) -> *mut GingerMHTPath
{
    // Read tree
    let tree = try_read_raw_pointer!("tree", tree, ret_code, null_mut());

    // Get path if tree is finalized, otherwise return error
    match get_ginger_mht_path(tree, leaf_index as u64) {
        Some(path) => Box::into_raw(Box::new(path)),
        None => {
            *ret_code = CctpErrorCode::MerkleTreeError;
            println!("{:?}", "Error: tree not finalized");
            null_mut()
        }
    }
}

#[no_mangle]
pub extern "C" fn zendoo_get_ginger_empty_node(
    height: usize
) -> *mut FieldElement
{
    let max_height = GINGER_MHT_POSEIDON_PARAMETERS.nodes.len() - 1;
    assert!(height <= max_height, "Empty node not pre-computed for height {}", height);

    let empty_node = GINGER_MHT_POSEIDON_PARAMETERS.nodes[max_height - height].clone();

    Box::into_raw(Box::new(empty_node))
}

#[no_mangle]
pub extern "C" fn zendoo_verify_ginger_merkle_path(
    path: *const GingerMHTPath,
    height: usize,
    leaf: *const FieldElement,
    root: *const FieldElement,
    ret_code: &mut CctpErrorCode,
) -> bool
{
    let path = try_read_raw_pointer!("path", path, ret_code, false);
    let root = try_read_raw_pointer!("root", root, ret_code, false);
    let leaf = try_read_raw_pointer!("leaf", leaf, ret_code, false);

    match verify_ginger_merkle_path(path, height, leaf, root) {
        Ok(result) => result,
        Err(e) => {
            *ret_code = CctpErrorCode::MerkleTreeError;
            println!("{:?}", format!("Error verifying merkle path: {:?}", e));
            false
        }
    }
}

#[no_mangle]
pub extern "C" fn zendoo_verify_ginger_merkle_path_from_raw(
    path: *const GingerMHTPath,
    height: usize,
    leaf: *const FieldElement,
    root: *const FieldElement,
    ret_code: &mut CctpErrorCode,
) -> bool
{
    let path = try_read_raw_pointer!("path", path, ret_code, false);
    let root = try_read_raw_pointer!("root", root, ret_code, false);
    let leaf = try_read_raw_pointer!("leaf", leaf, ret_code, false);

    // Verify path
    match verify_ginger_merkle_path(path, height, leaf, root) {
        Ok(result) => result,
        Err(e) => {
            *ret_code = CctpErrorCode::MerkleTreeError;
            println!("{:?}", format!("Error verifying merkle path: {:?}", e));
            false
        }
    }
}

#[no_mangle]
pub extern "C" fn zendoo_free_ginger_merkle_path(
    path: *mut GingerMHTPath
) { free_pointer(path) }

#[no_mangle]
pub extern "C" fn zendoo_reset_ginger_mht(
    tree: *mut GingerMHT,
    ret_code: &mut CctpErrorCode,
) -> bool
{
    // Read tree
    let tree = try_read_mut_raw_pointer!("tree", tree, ret_code, false);

    reset_ginger_mht(tree);
    true
}

#[no_mangle]
pub extern "C" fn zendoo_free_ginger_mht(
    tree: *mut GingerMHT
) { free_pointer(tree) }

//***************Test functions*******************

#[repr(C)]
pub enum TestCircuitType {
    Certificate,
    CSW
}

#[cfg(all(feature = "mc-test-circuit", not(target_os = "windows")))]
#[no_mangle]
pub extern "C" fn zendoo_deserialize_sc_proof_from_file(
    proof_path:         *const u8,
    proof_path_len:     usize,
    semantic_checks:    bool,
    ret_code:           &mut CctpErrorCode,
) -> *mut ZendooProof
{
    // Read file path
    let proof_path = parse_path(proof_path, proof_path_len);
    try_deserialize_to_raw_pointer_from_file!("sc_proof", proof_path, semantic_checks, ret_code, null_mut())
}

#[cfg(all(feature = "mc-test-circuit", target_os = "windows"))]
#[no_mangle]
pub extern "C" fn zendoo_deserialize_sc_proof_from_file(
    proof_path:         *const u16,
    proof_path_len:     usize,
    semantic_checks:    bool,
    ret_code:           &mut CctpErrorCode,
) -> *mut ZendooProof
{
    // Read file path
    let path_str = OsString::from_wide(unsafe {
        slice::from_raw_parts(proof_path, proof_path_len)
    });
    let proof_path = Path::new(&path_str);

    try_deserialize_to_raw_pointer_from_file!("sc_proof", proof_path, semantic_checks, ret_code, null_mut())
}

#[cfg(all(feature = "mc-test-circuit", not(target_os = "windows")))]
#[no_mangle]
pub extern "C" fn zendoo_deserialize_sc_pk_from_file(
    pk_path:            *const u8,
    pk_path_len:        usize,
    semantic_checks:    bool,
    ret_code:           &mut CctpErrorCode,
) -> *mut ZendooProverKey
{
    // Read file path
    let pk_path = parse_path(pk_path, pk_path_len);
    try_deserialize_to_raw_pointer_from_file!("sc_pk", pk_path, semantic_checks, ret_code, null_mut())
}

#[cfg(all(feature = "mc-test-circuit", target_os = "windows"))]
#[no_mangle]
pub extern "C" fn zendoo_deserialize_sc_pk_from_file(
    pk_path:            *const u16,
    pk_path_len:        usize,
    semantic_checks:    bool,
    ret_code:           &mut CctpErrorCode,
) -> *mut ZendooProverKey
{
    // Read file path
    let path_str = OsString::from_wide(unsafe {
        slice::from_raw_parts(pk_path, pk_path_len)
    });
    let pk_path = Path::new(&path_str);

    try_deserialize_to_raw_pointer_from_file!("sc_pk", pk_path, semantic_checks, ret_code, null_mut())
}

#[cfg(feature = "mc-test-circuit")]
#[no_mangle]
pub extern "C" fn zendoo_get_sc_pk_proving_system_type(
    sc_pk:    *const ZendooProverKey,
    ret_code: &mut CctpErrorCode
) -> ProvingSystem
{
    let sc_pk = try_read_raw_pointer!("sc_pk", sc_pk, ret_code, ProvingSystem::Undefined);
    sc_pk.get_proving_system_type()
}

#[cfg(feature = "mc-test-circuit")]
#[no_mangle]
pub extern "C" fn zendoo_sc_pk_free(
    sc_pk:    *mut ZendooProverKey,
)
{
    free_pointer(sc_pk)
}

#[cfg(feature = "mc-test-circuit")]
fn _zendoo_generate_mc_test_params(
    circ_type:      TestCircuitType,
    ps_type:        ProvingSystem,
    params_dir:     &Path,
    ret_code:       &mut CctpErrorCode,
) -> bool
{
    let mut params_path = "".to_owned();

    match ps_type {
        ProvingSystem::Darlin => params_path.push_str("darlin_"),
        ProvingSystem::CoboundaryMarlin => params_path.push_str("cob_marlin_"),
        ProvingSystem::Undefined => {
            println!("Error: Undefined proving system");
            *ret_code = CctpErrorCode::InvalidValue;
            return false;
        }
    }

    // Generate params
    let params = match circ_type {
        TestCircuitType::Certificate => {
            params_path.push_str("cert_");
            mc_test_circuits::cert::generate_parameters(ps_type)
        },
        TestCircuitType::CSW => {
            params_path.push_str("csw_");
            mc_test_circuits::csw::generate_parameters(ps_type)
        }
    };

    match params {
        Ok((pk, vk)) => {

            let pk_path_raw = {
                let mut t = params_path.clone();
                t.push_str("test_pk");
                t
            };

            let vk_path_raw = {
                params_path.push_str("test_vk");
                params_path
            };

            let pk_path = params_dir.join(pk_path_raw.as_str());
            let vk_path = params_dir.join(vk_path_raw.as_str());

            let pk_ser_res = write_to_file(&pk, &pk_path);
            if pk_ser_res.is_err() {
                println!("{:?}", format!("Error writing pk to file: {:?}", pk_ser_res.unwrap_err()));
                *ret_code = CctpErrorCode::InvalidFile;
                return false;
            }

            let vk_ser_res = write_to_file(&vk, &vk_path);
            if vk_ser_res.is_err() {
                println!("{:?}", format!("Error writing vk to file: {:?}", vk_ser_res.unwrap_err()));
                *ret_code = CctpErrorCode::InvalidFile;
                return false;
            }

            true
        }
        Err(e) => {
            println!("{:?}", format!("Error generating test params: {:?}", e));
            *ret_code = CctpErrorCode::GenericError;
            false
        }
    }
}

#[cfg(all(feature = "mc-test-circuit", target_os = "windows"))]
#[no_mangle]
pub extern "C" fn zendoo_generate_mc_test_params(
    circ_type:      TestCircuitType,
    ps_type:        ProvingSystem,
    params_dir:     *const u16,
    params_dir_len: usize,
    ret_code:       &mut CctpErrorCode,
) -> bool
{
    // Read params_dir
    let path_str = OsString::from_wide(unsafe {
        slice::from_raw_parts(params_dir, params_dir_len)
    });
    let params_dir = Path::new(&path_str);

    _zendoo_generate_mc_test_params(circ_type, ps_type, params_dir, ret_code)
}

#[cfg(all(feature = "mc-test-circuit", not(target_os = "windows")))]
#[no_mangle]
pub extern "C" fn zendoo_generate_mc_test_params(
    circ_type:      TestCircuitType,
    ps_type:        ProvingSystem,
    params_dir:     *const u8,
    params_dir_len: usize,
    ret_code:       &mut CctpErrorCode,
) -> bool
{
    let params_dir = parse_path(params_dir, params_dir_len);
    _zendoo_generate_mc_test_params(circ_type, ps_type, params_dir, ret_code)
}

#[cfg(feature = "mc-test-circuit")]
fn _zendoo_create_cert_test_proof(
    zk:                     bool,
    constant:               *const FieldElement,
    epoch_number:           u32,
    quality:                u64,
    bt_list:                *const BackwardTransfer,
    bt_list_len:            usize,
    custom_fields:          *const *const FieldElement,
    custom_fields_len:      usize,
    end_cum_comm_tree_root: *const FieldElement,
    btr_fee:                u64,
    ft_min_amount:          u64,
    sc_pk:                  *const ZendooProverKey,
    ret_code:               &mut CctpErrorCode
) -> Result<ZendooProof, ProvingSystemError>
{
    // Read bt_list
    let rs_bt_list = try_get_optional_obj_list!("bt_list", bt_list, bt_list_len, ret_code, Err(ProvingSystemError::Other("".to_owned())));

    // Read mandatory, constant size data
    let rs_end_cum_comm_tree_root = try_read_raw_pointer!("end_cum_comm_tree_root", end_cum_comm_tree_root, ret_code, Err(ProvingSystemError::Other("".to_owned())));
    let rs_pk = try_read_raw_pointer!("sc_pk", sc_pk, ret_code, Err(ProvingSystemError::Other("".to_owned())));

    // Read optional data
    let rs_constant = try_read_raw_pointer!("constant", constant, ret_code, Err(ProvingSystemError::Other("".to_owned())));
    let rs_custom_fields = try_read_optional_double_raw_pointer!(
        "custom_fields", custom_fields, custom_fields_len, ret_code, Err(ProvingSystemError::Other("".to_owned()))
    );

    // Create proof
    mc_test_circuits::cert::generate_proof(
        rs_pk,
        zk,
        rs_constant,
        epoch_number,
        quality,
        rs_custom_fields,
        rs_bt_list,
        rs_end_cum_comm_tree_root,
        btr_fee,
        ft_min_amount
    )
}

#[cfg(all(feature = "mc-test-circuit", not(target_os = "windows")))]
#[no_mangle]
pub extern "C" fn zendoo_create_cert_test_proof(
    zk:                     bool,
    constant:               *const FieldElement,
    epoch_number:           u32,
    quality:                u64,
    bt_list:                *const BackwardTransfer,
    bt_list_len:            usize,
    custom_fields:          *const *const FieldElement,
    custom_fields_len:      usize,
    end_cum_comm_tree_root: *const FieldElement,
    btr_fee:                u64,
    ft_min_amount:          u64,
    sc_pk:                  *const ZendooProverKey,
    proof_path:             *const u8,
    proof_path_len:         usize,
    ret_code:               &mut CctpErrorCode
) -> bool
{
    match _zendoo_create_cert_test_proof(
        zk, constant, epoch_number, quality, bt_list, bt_list_len, custom_fields, custom_fields_len,
        end_cum_comm_tree_root, btr_fee, ft_min_amount, sc_pk, ret_code
    ){
        Ok(proof) => {
            let proof_path = parse_path(proof_path, proof_path_len);

            // Write proof to file
            let proof_ser_res = write_to_file(&proof, &proof_path);
            if proof_ser_res.is_err() {
                println!("{:?}", format!("Error writing proof to file {:?}", proof_ser_res.unwrap_err()));
                *ret_code = CctpErrorCode::InvalidFile;
                return false;
            }

            true
        },
            Err(e) => {
            println!("{:?}", format!("Error creating proof {:?}", e));
            *ret_code = CctpErrorCode::TestProofCreationFailure;
            false
        }
    }
}

#[cfg(all(feature = "mc-test-circuit", target_os = "windows"))]
#[no_mangle]
pub extern "C" fn zendoo_create_cert_test_proof(
    zk:                     bool,
    constant:               *const FieldElement,
    epoch_number:           u32,
    quality:                u64,
    bt_list:                *const BackwardTransfer,
    bt_list_len:            usize,
    custom_fields:          *const *const FieldElement,
    custom_fields_len:      usize,
    end_cum_comm_tree_root: *const FieldElement,
    btr_fee:                u64,
    ft_min_amount:          u64,
    sc_pk:                  *const ZendooProverKey,
    proof_path:             *const u16,
    proof_path_len:         usize,
    ret_code:               &mut CctpErrorCode
) -> bool
{
    match _zendoo_create_cert_test_proof(
        zk, constant, epoch_number, quality, bt_list, bt_list_len, custom_fields, custom_fields_len,
        end_cum_comm_tree_root, btr_fee, ft_min_amount, sc_pk, ret_code
    ){
        Ok(proof) => {
            let path_str = OsString::from_wide(unsafe {
                slice::from_raw_parts(proof_path, proof_path_len)
            });
            let proof_path = Path::new(&path_str);

            // Write proof to file
            let proof_ser_res = write_to_file(&proof, &proof_path);
            if proof_ser_res.is_err() {
                println!("{:?}", format!("Error writing proof to file {:?}", proof_ser_res.unwrap_err()));
                *ret_code = CctpErrorCode::InvalidFile;
                return false;
            }

            true
        },
        Err(e) => {
            println!("{:?}", format!("Error creating proof {:?}", e));
            *ret_code = CctpErrorCode::TestProofCreationFailure;
            false
        }
    }
}

#[cfg(feature = "mc-test-circuit")]
fn _zendoo_create_csw_test_proof(
    zk:                     bool,
    amount:                 u64,
    sc_id:                  *const FieldElement,
    nullifier:              *const FieldElement,
    mc_pk_hash:             *const BufferWithSize,
    cert_data_hash:         *const FieldElement,
    end_cum_comm_tree_root: *const FieldElement,
    sc_pk:                  *const ZendooProverKey,
    ret_code:               &mut CctpErrorCode
) -> Result<ZendooProof, ProvingSystemError>
{
    let rs_sc_id                  = try_read_raw_pointer!("sc_id",                  sc_id,                  ret_code, Err(ProvingSystemError::Other("".to_owned())));
    let rs_nullifier              = try_read_raw_pointer!("nullifier",              nullifier,              ret_code, Err(ProvingSystemError::Other("".to_owned())));
    let rs_cert_data_hash         = try_read_raw_pointer!("cert_data_hash",         cert_data_hash,         ret_code, Err(ProvingSystemError::Other("".to_owned())));
    let rs_end_cum_comm_tree_root = try_read_raw_pointer!("end_cum_comm_tree_root", end_cum_comm_tree_root, ret_code, Err(ProvingSystemError::Other("".to_owned())));
    let rs_pk                     = try_read_raw_pointer!("sc_pk",                  sc_pk,                  ret_code, Err(ProvingSystemError::Other("".to_owned())));

    let rs_mc_pk_hash   = try_get_buffer_constant_size!("mc_pk_hash", mc_pk_hash, UINT_160_SIZE, ret_code, Err(ProvingSystemError::Other("".to_owned())));

    // Create proof
    mc_test_circuits::csw::generate_proof(
        rs_pk,
        zk,
        amount,
        rs_sc_id,
        rs_nullifier,
        rs_mc_pk_hash,
        rs_cert_data_hash,
        rs_end_cum_comm_tree_root
    )
}

#[cfg(all(feature = "mc-test-circuit", not(target_os = "windows")))]
#[no_mangle]
pub extern "C" fn zendoo_create_csw_test_proof(
    zk:                     bool,
    amount:                 u64,
    sc_id:                  *const FieldElement,
    nullifier:              *const FieldElement,
    mc_pk_hash:             *const BufferWithSize,
    cert_data_hash:         *const FieldElement,
    end_cum_comm_tree_root: *const FieldElement,
    sc_pk:                  *const ZendooProverKey,
    proof_path:             *const u8,
    proof_path_len:         usize,
    ret_code:               &mut CctpErrorCode
) -> bool
{
    match _zendoo_create_csw_test_proof(
        zk, amount, sc_id, nullifier, mc_pk_hash, cert_data_hash,
        end_cum_comm_tree_root, sc_pk, ret_code
    ){
        Ok(proof) => {
            let proof_path = parse_path(proof_path, proof_path_len);

            // Write proof to file
            let proof_ser_res = write_to_file(&proof, &proof_path);
            if proof_ser_res.is_err() {
                println!("{:?}", format!("Error writing proof to file {:?}", proof_ser_res.unwrap_err()));
                *ret_code = CctpErrorCode::InvalidFile;
                return false;
            }

            true
        },
        Err(e) => {
            println!("{:?}", format!("Error creating proof {:?}", e));
            *ret_code = CctpErrorCode::TestProofCreationFailure;
            false
        }
    }
}

#[cfg(all(feature = "mc-test-circuit", target_os = "windows"))]
#[no_mangle]
pub extern "C" fn zendoo_create_csw_test_proof(
    zk:                     bool,
    amount:                 u64,
    sc_id:                  *const FieldElement,
    nullifier:              *const FieldElement,
    mc_pk_hash:             *const BufferWithSize,
    cert_data_hash:         *const FieldElement,
    end_cum_comm_tree_root: *const FieldElement,
    sc_pk:                  *const ZendooProverKey,
    proof_path:             *const u16,
    proof_path_len:         usize,
    ret_code:               &mut CctpErrorCode
) -> bool
{
    match _zendoo_create_csw_test_proof(
        zk, amount, sc_id, nullifier, mc_pk_hash, cert_data_hash,
        end_cum_comm_tree_root, sc_pk, ret_code
    ){
        Ok(proof) => {
            let path_str = OsString::from_wide(unsafe {
                slice::from_raw_parts(proof_path, proof_path_len)
            });
            let proof_path = Path::new(&path_str);

            // Write proof to file
            let proof_ser_res = write_to_file(&proof, &proof_path);
            if proof_ser_res.is_err() {
                println!("{:?}", format!("Error writing proof to file {:?}", proof_ser_res.unwrap_err()));
                *ret_code = CctpErrorCode::InvalidFile;
                return false;
            }

            true
        },
        Err(e) => {
            println!("{:?}", format!("Error creating proof {:?}", e));
            *ret_code = CctpErrorCode::TestProofCreationFailure;
            false
        }
    }
}

#[cfg(feature = "mc-test-circuit")]
#[no_mangle]
pub extern "C" fn zendoo_create_return_cert_test_proof(
    zk:                     bool,
    constant:               *const FieldElement,
    epoch_number:           u32,
    quality:                u64,
    bt_list:                *const BackwardTransfer,
    bt_list_len:            usize,
    custom_fields:          *const *const FieldElement,
    custom_fields_len:      usize,
    end_cum_comm_tree_root: *const FieldElement,
    btr_fee:                u64,
    ft_min_amount:          u64,
    sc_pk:                  *const ZendooProverKey,
    ret_code:               &mut CctpErrorCode
) -> *mut BufferWithSize
{
    match _zendoo_create_cert_test_proof(
        zk, constant, epoch_number, quality, bt_list, bt_list_len, custom_fields, custom_fields_len,
        end_cum_comm_tree_root, btr_fee, ft_min_amount, sc_pk, ret_code
    ){
        Ok(sc_proof) => {
            match serialize_to_buffer(&sc_proof) {
                Ok(mut sc_proof_bytes) => {

                    let data = sc_proof_bytes.as_mut_ptr();
                    let len = sc_proof_bytes.len();
                    std::mem::forget(sc_proof_bytes);
                    Box::into_raw(Box::new(BufferWithSize { data, len }))
                },
                Err(e) => {
                    println!("{:?}", format!("Error serializing proof {:?}", e));
                    *ret_code = CctpErrorCode::InvalidValue;
                    null_mut()
                }
            }
        },
        Err(e) => {
            println!("{:?}", format!("Error creating proof {:?}", e));
            *ret_code = CctpErrorCode::TestProofCreationFailure;
            null_mut()
        }
    }
}


#[cfg(feature = "mc-test-circuit")]
#[no_mangle]
pub extern "C" fn zendoo_create_return_csw_test_proof(
    zk:                     bool,
    amount:                 u64,
    sc_id:                  *const FieldElement,
    nullifier:              *const FieldElement,
    mc_pk_hash:             *const BufferWithSize,
    cert_data_hash:         *const FieldElement,
    end_cum_comm_tree_root: *const FieldElement,
    sc_pk:                  *const ZendooProverKey,
    ret_code:               &mut CctpErrorCode
) -> *mut BufferWithSize
{
    match _zendoo_create_csw_test_proof(
        zk, amount, sc_id, nullifier, mc_pk_hash, cert_data_hash,
        end_cum_comm_tree_root, sc_pk, ret_code
    ){
        Ok(sc_proof) => {
            match serialize_to_buffer(&sc_proof) {
                Ok(mut sc_proof_bytes) => {

                    let data = sc_proof_bytes.as_mut_ptr();
                    let len = sc_proof_bytes.len();
                    std::mem::forget(sc_proof_bytes);
                    Box::into_raw(Box::new(BufferWithSize { data, len }))
                },
                Err(e) => {
                    println!("{:?}", format!("Error serializing proof {:?}", e));
                    *ret_code = CctpErrorCode::InvalidValue;
                    null_mut()
                }
            }
        },
        Err(e) => {
            println!("{:?}", format!("Error creating proof {:?}", e));
            *ret_code = CctpErrorCode::TestProofCreationFailure;
            null_mut()
        }
    }
}

fn check_equal<T: PartialEq>(val_1: *const T, val_2: *const T) -> bool {
    let val_1 = unsafe { &*val_1 };
    let val_2 = unsafe { &*val_2 };
    val_1 == val_2
}

#[no_mangle]
pub extern "C" fn zendoo_get_random_field() -> *mut FieldElement {
    let mut rng = OsRng;
    let random_f = FieldElement::rand(&mut rng);
    Box::into_raw(Box::new(random_f))
}

#[no_mangle]
pub extern "C" fn zendoo_get_field_from_long(value: u64) -> *mut FieldElement {
    let fe = FieldElement::from(value);
    Box::into_raw(Box::new(fe))
}

#[no_mangle]
pub extern "C" fn zendoo_field_assert_eq(
    field_1: *const FieldElement,
    field_2: *const FieldElement,
) -> bool {
    check_equal(field_1, field_2)
}

#[no_mangle]
pub extern "C" fn zendoo_sc_proof_assert_eq(
    sc_proof_1: *const ZendooProof,
    sc_proof_2: *const ZendooProof,
) -> bool {
    let proof_1 = unsafe { &*sc_proof_1 };
    let proof_2 = unsafe { &*sc_proof_2 };
    match (proof_1, proof_2) {
        (ZendooProof::CoboundaryMarlin(cob_marlin_proof_1), ZendooProof::CoboundaryMarlin(cob_marlin_proof_2)) => cob_marlin_proof_1 == cob_marlin_proof_2,
        (ZendooProof::Darlin(darlin_proof_1), ZendooProof::Darlin(darlin_proof_2)) => darlin_proof_1 == darlin_proof_2,
        _ => false
    }
}