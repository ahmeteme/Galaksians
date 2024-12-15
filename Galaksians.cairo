// SPDX-License-Identifier: MIT

%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.uint256 import Uint256,uint256_le,uint256_mul_div_mod,uint256_mul
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.math import  assert_lt_felt,split_felt,assert_le
from starkware.cairo.common.math_cmp import is_not_zero
from starkware.starknet.common.syscalls import (
    get_caller_address,
    get_contract_address
)
from starkware.cairo.common.hash import hash2

from starkware.cairo.common.bool import TRUE, FALSE
from openzeppelin.access.ownable.library import Ownable
from openzeppelin.introspection.erc165.library import ERC165
from openzeppelin.security.pausable.library import Pausable
from openzeppelin.token.erc721.library import ERC721
from openzeppelin.token.erc20.IERC20 import IERC20
from src.contracts.lib.string.ASCII import StringCodec
from src.contracts.lib.array.array import concat_arr
from src.contracts.lib.merkle.merkle import (
    merkle_verify,
    _hash_sorted
)

// CONSTANT
const MAX_SUPPLY = 444;
const PER_PUBLIC_ADDRESS = 1;

@storage_var
func Base_Uri(index: felt) -> (value: felt) {}

@storage_var
func Base_Uri_Len() -> (value: felt) {}

@storage_var
func Base_Uri_Extension() -> (value: felt) {}

@storage_var
func Public_Mint_Price() -> (value: Uint256) {}

@storage_var
func Public_Mint_State() -> (value: felt) {}

@storage_var
func Whitelist_Mint_State() -> (value: felt) {}

@storage_var
func Currency_Address() -> (value: felt) {}

@storage_var
func Wl_Address_Has_Minted(address: felt) -> (value: felt) {}

@storage_var
func Total_Supply() -> (value: felt) {}

@storage_var
func WL_Merkle_Root() -> (value: felt) {}

@storage_var
func Address_Mint_Count(address: felt) -> (value: felt) {}

@storage_var
func Reentrancy_Lock() -> (value: felt) {}

@constructor
func constructor{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    name: felt,
    symbol: felt,
    owner: felt,
    base_uri_len: felt,
    base_uri: felt*,
    json_extension: felt,
    currency_address: felt,
    public_mint_price: Uint256,
    wl_root: felt
) {
    ERC721.initializer(name, symbol);
    Ownable.initializer(owner);
    Base_Uri_Extension.write(json_extension);
    Currency_Address.write(currency_address);
    Public_Mint_Price.write(public_mint_price);
    WL_Merkle_Root.write(wl_root);
    _set_base_uri(base_uri_len, base_uri);
    Base_Uri_Len.write(base_uri_len);
    return ();
}

// Internal Functions
func _lock() {
    let (lock_state) = Reentrancy_Lock.read();
    with_attr error_message("Reentrancy detected") {
        assert lock_state = FALSE;
    }
    Reentrancy_Lock.write(TRUE);
}

func _unlock() {
    Reentrancy_Lock.write(FALSE);
}

func _mint{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    to: felt, start_token_id: felt, amount: felt
) {
    alloc_locals;
    let mut token_id = start_token_id;
    let mut counter = amount;
    while counter > 0 {
        ERC721._mint(to, Uint256(token_id, 0));
        token_id += 1;
        counter -= 1;
    }
    return ();
}

func _set_base_uri{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    uri_len: felt, uri: felt*
) {
    alloc_locals;
    let mut index = 0;
    while index < uri_len {
        Base_Uri.write(index, uri[index]);
        index += 1;
    }
    return ();
}

// External Functions
@external
func withdraw{
    syscall_ptr: felt*,
    pedersen_ptr: HashBuiltin*,
    range_check_ptr
}(receiver: felt) {
    alloc_locals;
    Ownable.assert_only_owner();

    _lock();

    let (this_address) = get_contract_address();
    let (currency_address) = Currency_Address.read();
    let (balance: Uint256) = IERC20.balanceOf(
        contract_address=currency_address,
        account=this_address
    );

    with_attr error_message("Transfer failed") {
        let (success: felt) = IERC20.transfer(
            contract_address=currency_address,
            recipient=receiver,
            amount=balance
        );
        assert success = 1;
    }

    _unlock();
    return ();
}

@external
func publicMint{pedersen_ptr: HashBuiltin*, syscall_ptr: felt*, range_check_ptr}() {
    alloc_locals;

    let (mint_price) = Public_Mint_Price.read();
    let (caller) = get_caller_address();
    let (supply) = Total_Supply.read();
    let (public_mint_state) = Public_Mint_State.read();
    let (address_mint_count) = Address_Mint_Count.read(caller);

    with_attr error_message("Mint not started") {
        assert public_mint_state = TRUE;
    }

    with_attr error_message("Max mint exceeded (Max: 1)") {
        assert_le(address_mint_count, PER_PUBLIC_ADDRESS);
    }

    with_attr error_message("MAX SUPPLY EXCEEDED") {
        assert_le(supply, MAX_SUPPLY);
    }

    let (this_address) = get_contract_address();
    let (currency_address) = Currency_Address.read();
    let (success: felt) = IERC20.transferFrom(
        contract_address=currency_address,
        sender=caller,
        recipient=this_address,
        amount=mint_price
    );

    with_attr error_message("ERC20 transfer failed") {
        assert success = 1;
    }

    _mint(caller, supply + 1, 1);
    Total_Supply.write(supply + 1);
    Address_Mint_Count.write(caller, 1);

    return ();
}
