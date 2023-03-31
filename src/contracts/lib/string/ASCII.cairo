%lang starknet

from src.contracts.lib.string.string import String

from src.contracts.lib.string.libs.conversion import (
    conversion_felt_to_string,
)

namespace StringCodec {
    //
    // Constants
    //

    // @dev Characters encoded in ASCII so 8 bits
    const CHAR_SIZE = 256;

    // @dev Mask to retreive the last character (= 0b00...0011111111 = 0x00...00ff)
    const LAST_CHAR_MASK = CHAR_SIZE - 1;

    // @dev add 48 to a number in range [0, 9] for ASCII character code
    const NUMERICAL_OFFSET = 48;

  

    //
    // Conversion
    //

    // @dev Converts a felt to its ASCII String value
    // @implicit range_check_ptr (felt)
    // @param elem (felt): The felt value to convert
    // @return str (String): The String
    func felt_to_string{range_check_ptr}(elem: felt) -> (str: String) {
        let codec_numerical_offset = NUMERICAL_OFFSET;
        with codec_numerical_offset {
            let (str) = conversion_felt_to_string(elem);
        }
        return (str,);
    }
}
