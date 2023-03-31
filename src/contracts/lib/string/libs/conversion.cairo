%lang starknet

from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.math import unsigned_div_rem, assert_le
from starkware.cairo.common.math_cmp import is_le

from src.contracts.lib.array.array import invert_felt_arr
from src.contracts.lib.string.string import String
from src.contracts.lib.string.constants import  STRING_MAX_LEN

// felt to String
func conversion_felt_to_string{range_check_ptr, codec_numerical_offset}(elem: felt) -> (
    str: String
) {
    alloc_locals;
    let (local str_seed: felt*) = alloc();
    let (str_len) = _loop_felt_to_inverted_string(elem, str_seed, 0);

    let (_, str) = invert_felt_arr(str_len, str_seed);
    return (String(str_len, str),);
}

func _loop_felt_to_inverted_string{range_check_ptr, codec_numerical_offset}(
    elem: felt, str_seed: felt*, index: felt
) -> (str_len: felt) {
    alloc_locals;
    with_attr error_message("felt_to_string: exceeding max String length 2^15") {
        assert_le(index, STRING_MAX_LEN);
    }

    let (rem_elem, unit) = unsigned_div_rem(elem, 10);
    assert str_seed[index] = unit + codec_numerical_offset;
    if (rem_elem == 0) {
        return (index + 1,);
    }

    let is_lower = is_le(elem, rem_elem);
    if (is_lower != 0) {
        return (index + 1,);
    }

    return _loop_felt_to_inverted_string(rem_elem, str_seed, index + 1);
}

