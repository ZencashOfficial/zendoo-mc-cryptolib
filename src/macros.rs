use algebra::{CanonicalSerialize, CanonicalDeserialize, SemanticallyValid};
use cctp_primitives::{
    utils::serialization::{deserialize_from_buffer, read_from_file},
};
use std::{
    slice, path::Path
};

#[allow(unused_macros)]
macro_rules! log {
    ($msg: expr) => {{
        eprintln!("[{}:{}] {:?}", file!(), line!(), $msg)
    }};
}

#[allow(unused_macros)]
#[cfg(debug_assertions)]
macro_rules! log_dbg {
    ($msg: expr) => {{
        eprintln!("[{}:{}] {:?}", file!(), line!(), $msg)
    }};
}

#[allow(unused_macros)]
#[cfg(not(debug_assertions))]
macro_rules! log_dbg {
    ($msg: expr) => {{ () }};
}

#[derive(Debug, Copy, Clone, PartialEq)]
#[repr(C)]
pub enum CctpErrorCode {
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
}

#[repr(C)]
pub struct BufferWithSize {
    pub data: *mut u8,
    pub len: usize,
}

/// Check that `buffer` it's a valid buffer with non-zero data
pub(crate) fn check_buffer(buffer: *const BufferWithSize) -> (bool, CctpErrorCode)
{
    if buffer.is_null() {
        //eprintln!("===> ERR CODE {:?}", CctpErrorCode::NullPtr);
        return (false, CctpErrorCode::NullPtr)
    }

    let data_attr = unsafe { (*buffer).data };
    if data_attr.is_null() {
        //eprintln!("===> ERR CODE {:?}", CctpErrorCode::InvalidBufferData);
        return (false, CctpErrorCode::InvalidBufferData)
    }

    let len_attr = unsafe { (*buffer).len };
    if len_attr == 0 {
        //eprintln!("===> ERR CODE {:?}", CctpErrorCode::InvalidBufferLength);
        return (false, CctpErrorCode::InvalidBufferLength)
    }

    (true, CctpErrorCode::OK)
}

/// Check that `buffer` it's a valid buffer with non-zero data
/// whose length must be equal to `len`.
pub(crate) fn check_buffer_length(buffer: *const BufferWithSize, len: usize) -> (bool, CctpErrorCode)
{
    let (is_ok, err) = check_buffer(buffer);
    if !is_ok { return (false, err) }

    let len_attr = unsafe { (*buffer).len };
    if len_attr != len {
        eprintln!("===> ERR: buf_len={}, expected={}", len_attr, len);
        return (false, CctpErrorCode::InvalidBufferLength)
    }

    (true, CctpErrorCode::OK)
}


pub(crate) fn free_buffer_with_size(buffer: *mut BufferWithSize) {
    if buffer.is_null() { return };
    unsafe {
        let buffer = Box::from_raw(buffer);
        Vec::from_raw_parts((*buffer).data, (*buffer).len, (*buffer).len);
    };
}


/// Convert a BufferWithSize to a &[u8], considering that `in_buffer`
/// and enforces that its length is equal to `checked_len`.
pub(crate) fn get_buffer_constant_size<'a>(in_buffer: *const BufferWithSize, checked_len: usize) -> (Option<&'a [u8]>, CctpErrorCode) {
    let (is_ok, ret_code) = check_buffer_length(in_buffer, checked_len);
    if !is_ok {
        return (None, ret_code);
    }
    let data = Some(unsafe { slice::from_raw_parts((*in_buffer).data, (*in_buffer).len)});
    (data, CctpErrorCode::OK)
}

macro_rules! try_get_buffer_constant_size {
    ($param_name: expr, $in_buffer:expr, $checked_len:expr, $ret_code:expr, $err_ret:expr) => {{
        let (data, ret_code) = get_buffer_constant_size($in_buffer, $checked_len);
        *$ret_code = ret_code;

        match data {
            Some(x) => {x.try_into().unwrap()}
            None => {
                eprintln!("Error with param: {:?}: {:?}", $param_name, ret_code);
                return $err_ret;
            }
        }
    }};
}

/// Convert a BufferWithSize to a &[u8].
pub(crate) fn get_buffer_variable_size<'a>(in_buffer: *const BufferWithSize) -> (Option<&'a [u8]>, CctpErrorCode) {
    let (is_ok, ret_code) = check_buffer(in_buffer);
    if !is_ok {
        return (None, ret_code);
    }
    let data = Some(unsafe { slice::from_raw_parts((*in_buffer).data, (*in_buffer).len)});
    (data, CctpErrorCode::OK)
}

macro_rules! try_get_buffer_variable_size {
    ($param_name:expr, $in_buffer:expr, $ret_code:expr, $err_ret:expr) => {{
        let (data, ret_code) = get_buffer_variable_size($in_buffer);
        *$ret_code = ret_code;

        match data {
            Some(x) => {x}
            None => {
                eprintln!("Error with param: {:?}: {:?}", $param_name, ret_code);
                return $err_ret;
            }
        }
    }};
}

/// Convert a BufferWithSize to a &[u8], considering that `in_buffer` might be null
pub(crate) fn get_optional_buffer_variable_size<'a>(in_buffer: *const BufferWithSize) -> (Option<&'a [u8]>, CctpErrorCode) {
    if in_buffer.is_null() {
        return (None, CctpErrorCode::OK);
    }
    get_buffer_variable_size(in_buffer)
}

macro_rules! try_get_optional_buffer_variable_size {
    ($param_name: expr, $in_buffer:expr, $ret_code:expr, $err_ret:expr) => {{
        let (optional_data, ret_code) = get_optional_buffer_variable_size($in_buffer);
        *$ret_code = ret_code;
        if ret_code != CctpErrorCode::OK {
            eprintln!("Error with param: {:?}: {:?}", $param_name, ret_code);
            return $err_ret;
        }
        optional_data
    }};
}

/// Convert a *const T to a &[T].
pub(crate) fn get_obj_list<'a, T>(in_list: *const T, in_list_size: usize) -> (Option<&'a [T]>, CctpErrorCode) {

    if in_list.is_null() {
        return (None, CctpErrorCode::NullPtr)
    }

    if in_list_size == 0 {
        return (None, CctpErrorCode::InvalidListLength)
    }

    let data = Some(unsafe { slice::from_raw_parts(in_list, in_list_size)});
    (data, CctpErrorCode::OK)
}

macro_rules! try_get_obj_list {
    ($param_name: expr, $in_list:expr, $in_list_size:expr, $ret_code: expr, $err_ret:expr) => {{
        let (data, ret_code) = get_obj_list($in_list, $in_list_size);
        *$ret_code = ret_code;

        match data {
            Some(x) => {x}
            None => {
                eprintln!("Error with param: {:?}: {:?}", $param_name, ret_code);
                return $err_ret;
            }
        }
    }};
}

/// Convert a *const T to a &[T].
pub(crate) fn get_optional_obj_list<'a, T>(in_list: *const T, in_list_size: usize) -> (Option<&'a [T]>, CctpErrorCode) {

    if in_list.is_null() {
        return (None, CctpErrorCode::OK)
    }

    if in_list_size == 0 {
        return (None, CctpErrorCode::InvalidListLength)
    }

    let data = Some(unsafe { slice::from_raw_parts(in_list, in_list_size)});
    (data, CctpErrorCode::OK)
}

macro_rules! try_get_optional_obj_list {
    ($param_name: expr, $in_list:expr, $in_list_size:expr, $ret_code: expr, $err_ret:expr) => {{
        let (optional_data, ret_code) = get_optional_obj_list($in_list, $in_list_size);
        *$ret_code = ret_code;

        if ret_code != CctpErrorCode::OK {
            eprintln!("Error with param: {:?}: {:?}", $param_name, ret_code);
            return $err_ret;
        }

        optional_data
    }};
}

pub(crate) fn read_raw_pointer<'a, T>(input: *const T) -> (Option<&'a T>, CctpErrorCode) {
    if input.is_null() {
        return (None, CctpErrorCode::NullPtr);
    }
    (Some(unsafe { &*input }), CctpErrorCode::OK)
}

macro_rules! try_read_raw_pointer {
    ($param_name: expr, $input:expr, $ret_code:expr, $err_ret:expr) => {{
        let (data, ret_code) = read_raw_pointer($input);
        *$ret_code = ret_code;

        match data {
            Some(x) => {x}
            None => {
                eprintln!("Error with param: {:?}: {:?}", $param_name, ret_code);
                return $err_ret;
            }
        }
    }};
}

pub(crate) fn read_optional_raw_pointer<'a, T>(input: *const T) -> (Option<&'a T>, CctpErrorCode) {
    let (ret, _) = read_raw_pointer(input);
    (ret, CctpErrorCode::OK)
}

macro_rules! try_read_optional_raw_pointer {
    ($param_name: expr, $input:expr, $ret_code:expr, $err_ret:expr) => {{
        let (data, ret_code) = read_optional_raw_pointer($input);
        *$ret_code = ret_code;

        if ret_code != CctpErrorCode::OK {
            eprintln!("Error with param: {:?}: {:?}", $param_name, ret_code);
            return $err_ret;
        }

        data
    }};
}

pub(crate) fn read_mut_raw_pointer<'a, T>(input: *mut T) -> (Option<&'a mut T>, CctpErrorCode) {
    if input.is_null() {
        return (None, CctpErrorCode::NullPtr);
    }
    (Some(unsafe { &mut *input }), CctpErrorCode::OK)
}

macro_rules! try_read_mut_raw_pointer {
    ($param_name: expr, $input:expr, $ret_code:expr, $err_ret:expr) => {{
        let (data, ret_code) = read_mut_raw_pointer($input);
        *$ret_code = ret_code;

        match data {
            Some(x) => {x}
            None => {
                eprintln!("Error with param: {:?}: {:?}", $param_name, ret_code);
                return $err_ret;
            }
        }
    }};
}

pub(crate) fn serialize_from_raw_pointer<T: CanonicalSerialize>(
    to_write: *const T,
    buffer: &mut [u8],
    compressed: Option<bool>
) -> CctpErrorCode
{
    // Read &T from raw_pointer `to_write`
    let (to_write, ret_code) = read_raw_pointer(to_write);
    if to_write.is_none() {
        return ret_code;
    }

    // Serialize to `buffer`
    let to_write = to_write.unwrap();
    let compressed = compressed.unwrap_or(false);
    let result = if compressed {
        CanonicalSerialize::serialize(to_write, buffer)
    } else {
        CanonicalSerialize::serialize_uncompressed(to_write, buffer)
    };

    if result.is_err() { CctpErrorCode::InvalidValue } else { CctpErrorCode::OK }
}

macro_rules! try_serialize_from_raw_pointer {
    ($param_name: expr, $to_write:expr, $buffer:expr, $compressed:expr, $ret_code:expr, $err_ret:expr) => {{
        let ret_code = serialize_from_raw_pointer($to_write, $buffer, $compressed);
        *$ret_code = ret_code;

        if ret_code != CctpErrorCode::OK {
            eprintln!("Error with param: {:?}: {:?}", $param_name, ret_code);
            return $err_ret;
        }
    }};
}

pub(crate) fn deserialize_to_raw_pointer<T: CanonicalDeserialize + SemanticallyValid>(
    buffer: &[u8],
    checked: Option<bool>,
    compressed: Option<bool>,
) -> (Option<*mut T>, CctpErrorCode)
{
    match deserialize_from_buffer(buffer, checked, compressed){
        Ok(t) => (Some(Box::into_raw(Box::new(t))), CctpErrorCode::OK),
        Err(_) => {
            (None, CctpErrorCode::InvalidValue)
        }
    }
}

macro_rules! try_deserialize_to_raw_pointer {
    ($param_name: expr, $buffer:expr, $checked:expr, $compressed:expr, $ret_code:expr, $err_ret:expr) => {{
        let (data, ret_code) = deserialize_to_raw_pointer($buffer, $checked, $compressed);
        *$ret_code = ret_code;

        match data {
            Some(x) => {x}
            None => {
                eprintln!("Error with param: {:?}: {:?}", $param_name, ret_code);
                return $err_ret;
            }
        }
    }};
}

pub(crate) fn deserialize_to_raw_pointer_from_file<T: CanonicalDeserialize + SemanticallyValid>(
    path: &Path,
    checked: Option<bool>,
    compressed: Option<bool>,
) -> (Option<*mut T>, CctpErrorCode)
{
    match read_from_file(path, checked, compressed){
        Ok(t) => (Some(Box::into_raw(Box::new(t))), CctpErrorCode::OK),
        Err(_) => {
            (None, CctpErrorCode::InvalidFile)
        }
    }
}

macro_rules! try_deserialize_to_raw_pointer_from_file {
    ($param_name: expr, $file_path:expr, $checked:expr, $compressed:expr, $ret_code:expr, $err_ret:expr) => {{
        let (data, ret_code) = deserialize_to_raw_pointer_from_file($file_path, $checked, $compressed);
        *$ret_code = ret_code;

        match data {
            Some(x) => {x}
            None => {
                eprintln!("Error with param: {:?}: {:?}", $param_name, ret_code);
                return $err_ret;
            }
        }
    }};
}

pub(crate) fn read_double_raw_pointer<'a, T>(
    input: *const *const T,
    input_len: usize,
) -> (Option<Vec<&'a T>>, CctpErrorCode) {

    //Read *const T from *const *const T
    if input.is_null() {
        return (None, CctpErrorCode::NullPtr);
    }

    if input_len == 0 {
        return (None, CctpErrorCode::InvalidListLength)
    }

    let input_raw = unsafe { slice::from_raw_parts(input, input_len) };

    //Read &T from *const T
    let mut input = vec![];
    for ptr in input_raw.iter() {
        let (input_ref, ret_code) = read_raw_pointer(*ptr);
        if ret_code != CctpErrorCode::OK {
            return (None, ret_code);
        }
        input.push(input_ref.unwrap());
    }

    (Some(input), CctpErrorCode::OK)
}

macro_rules! try_read_double_raw_pointer {
    ($param_name: expr, $input:expr, $input_len:expr, $ret_code:expr, $err_ret:expr) => {{
        let (data, ret_code) = read_double_raw_pointer($input, $input_len);
        *$ret_code = ret_code;

        match data {
            Some(x) => {x}
            None => {
                eprintln!("Error with param: {:?}: {:?}", $param_name, ret_code);
                return $err_ret;
            }
        }
    }};
}

pub(crate) fn read_optional_double_raw_pointer<'a, T>(
    input: *const *const T,
    input_len: usize,
) -> (Option<Vec<&'a T>>, CctpErrorCode) {

    //Read *const T from *const *const T
    if input.is_null() {
        return (None, CctpErrorCode::OK);
    }

    if input_len == 0 {
        return (None, CctpErrorCode::InvalidListLength)
    }

    let input_raw = unsafe { slice::from_raw_parts(input, input_len) };

    //Read &T from *const T
    let mut input = vec![];
    for ptr in input_raw.iter() {
        let (input_ref, ret_code) = read_raw_pointer(*ptr);
        if ret_code != CctpErrorCode::OK {
            return (None, ret_code);
        }
        input.push(input_ref.unwrap());
    }

    (Some(input), CctpErrorCode::OK)
}

macro_rules! try_read_optional_double_raw_pointer {
    ($param_name: expr, $input:expr, $input_len:expr, $ret_code:expr, $err_ret:expr) => {{
        let (data, ret_code) = read_optional_double_raw_pointer($input, $input_len);
        *$ret_code = ret_code;

        if ret_code != CctpErrorCode::OK {
            eprintln!("Error with param: {:?}: {:?}", $param_name, ret_code);
            return $err_ret;
        }

        data
    }};
}