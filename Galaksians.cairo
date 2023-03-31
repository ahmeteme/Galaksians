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
from starkware.cairo.common.memcpy import memcpy

from openzeppelin.access.ownable.library import Ownable
from openzeppelin.introspection.erc165.library import ERC165
from openzeppelin.security.pausable.library import Pausable
from openzeppelin.token.erc721.library import ERC721
from openzeppelin.token.erc20.IERC20 import IERC20
from src.contracts.lib.string.ASCII import StringCodec
from src.contracts.lib.array.array import concat_arr
from src.contracts.lib.merkle.merkle import (
    merkle_verify,
    addresses_to_leafs,
    merkle_build,
    _hash_sorted,
)

// CONSTANT
const MAX_SUPPLY = 444;
const PER_PUBLIC_ADDRESS = 1;

// Base uri
@storage_var
func Base_Uri(_id) -> (token_uri: felt) {
}
// Base uri len
@storage_var
func Base_Uri_Len() -> (token_uri_len: felt) {
}
// Base uri extension
@storage_var
func Base_Uri_Extension() -> (extension: felt) {
}
// Mint price
@storage_var
func Public_Mint_Price() -> (price: Uint256) {
}
// Public Mint state if true mint started, false mint not started 
@storage_var
func Public_Mint_State() -> (p_state: felt) {
}
// Whitelist Mint state if true mint started, false mint not started 
@storage_var
func Whitelist_Mint_State() -> (wl_state: felt) {
}
// Currency address
@storage_var
func Currency_Address() -> (address: felt) {
}
// Address has minted
@storage_var
func Wl_Address_Has_Minted(address: felt) -> (state: felt) {
}
// Total supply 
@storage_var
func Total_Supply() -> (supply: felt) {
}
// Merkle root of whitelisted address  
@storage_var
func WL_Merkle_Root() -> (root: felt) {
}

@storage_var
func Address_Mint_Count(address:felt) -> (count: felt) {
}

//
// Constructor
//

@constructor
func constructor{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    name: felt,
    symbol: felt,
    owner: felt,
    base_uri_len: felt,
    base_uri: felt*,
    json_extension: felt,
    currency_address: felt,
    public_mint_price:Uint256,
    wl_root: felt,

) {
    ERC721.initializer(name, symbol);
    Ownable.initializer(owner);
    Base_Uri_Extension.write(json_extension);
    Currency_Address.write(currency_address);
    Public_Mint_Price.write(public_mint_price);
    WL_Merkle_Root.write(wl_root);
    _set_base_uri(0,base_uri_len,base_uri);
    Base_Uri_Len.write(base_uri_len);
    return ();
}

//
// Getters
//

@view
func supportsInterface{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    interfaceId: felt
) -> (success: felt) {
    return ERC165.supports_interface(interfaceId);
}

@view
func name{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() -> (name: felt) {
    return ERC721.name();
}

@view
func symbol{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() -> (symbol: felt) {
    return ERC721.symbol();
}

@view
func balanceOf{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(owner: felt) -> (
    balance: Uint256
) {
    return ERC721.balance_of(owner);
}

@view
func ownerOf{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(tokenId: Uint256) -> (
    owner: felt
) {
    return ERC721.owner_of(tokenId);
}

@view
func getApproved{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    tokenId: Uint256
) -> (approved: felt) {
    return ERC721.get_approved(tokenId);
}

@view
func isApprovedForAll{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    owner: felt, operator: felt
) -> (isApproved: felt) {
    let (is_approved: felt) = ERC721.is_approved_for_all(owner, operator);
    return (isApproved=is_approved);
}

@view
func totalSupply{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() -> (supply: felt) {
    return Total_Supply.read();
}

@view
func tokenURI{
        syscall_ptr : felt*,
        pedersen_ptr : HashBuiltin*,
        range_check_ptr : felt
    }(token_id: Uint256) -> (token_uri_len: felt, token_uri: felt*){

    alloc_locals;
    let exists = _exists(token_id);
    with_attr error_message("ERC721_Metadata: token URI for nonexistent token") {
        assert exists = TRUE;
    }
    let (uri_count) = Base_Uri_Len.read();

    let (local token_uri: felt*) = alloc();
    let (json_extension) = Base_Uri_Extension.read();
    _tokenUri(
        uri_count=uri_count,
        token_uri_len=0,
        token_uri=token_uri
    );
    let (token_id_str) = StringCodec.felt_to_string(token_id.low);
    let (tokenUri_len, tokenUri) = concat_arr(uri_count, token_uri, token_id_str.len, token_id_str.data, 1);
    assert tokenUri[tokenUri_len] = json_extension;
    return (tokenUri_len+1, tokenUri);
}

@view
func owner{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() -> (owner: felt) {
    return Ownable.owner();
}

@view
func paused{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() -> (paused: felt) {
    return Pausable.is_paused();
}

@view
func publicMintPrice{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() -> (price: Uint256) {
    return Public_Mint_Price.read();
}

@view
func currencyAddress{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() -> (address: felt) {
    return Currency_Address.read();
}

@view
func baseUri{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() -> (uri_len: felt, uri: felt*) {
    alloc_locals;
    let (uri_count) = Base_Uri_Len.read();
    let (local token_uri: felt*) = alloc();
    _tokenUri(
        uri_count=uri_count,
        token_uri_len=0,
        token_uri=token_uri
    );
    return (uri_count, token_uri);
}

@view
func isPublicMintActive{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() -> (p_state: felt) {
    return Public_Mint_State.read();
}

@view
func isWhitelistMintActive{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() -> (wl_state: felt) {
    return Whitelist_Mint_State.read();
}

@view
func wlMerkleRoot{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() -> (root: felt) {
    return WL_Merkle_Root.read();
}

//
// Externals
//

@external
func approve{pedersen_ptr: HashBuiltin*, syscall_ptr: felt*, range_check_ptr}(
    to: felt, tokenId: Uint256
) {
    Pausable.assert_not_paused();
    ERC721.approve(to, tokenId);
    return ();
}

@external
func setApprovalForAll{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    operator: felt, approved: felt
) {
    Pausable.assert_not_paused();
    ERC721.set_approval_for_all(operator, approved);
    return ();
}

@external
func transferFrom{pedersen_ptr: HashBuiltin*, syscall_ptr: felt*, range_check_ptr}(
    from_: felt, to: felt, tokenId: Uint256
) {
    Pausable.assert_not_paused();
    ERC721.transfer_from(from_, to, tokenId);
    return ();
}

@external
func safeTransferFrom{pedersen_ptr: HashBuiltin*, syscall_ptr: felt*, range_check_ptr}(
    from_: felt, to: felt, tokenId: Uint256, data_len: felt, data: felt*
) {
    Pausable.assert_not_paused();
    ERC721.safe_transfer_from(from_, to, tokenId, data_len, data);
    return ();
}


@external
func wlMint{pedersen_ptr: HashBuiltin*, syscall_ptr: felt*, range_check_ptr}(
    proof_len: felt,
    proof: felt*
) {
    alloc_locals;
    let (caller) = get_caller_address();
    let (thisAddress) = get_contract_address();
    let (supply) = Total_Supply.read();
    let (wlMintState) = Whitelist_Mint_State.read();
    let (address_has_minted) = Wl_Address_Has_Minted.read(caller);
    let (currencyAddress) = Currency_Address.read();
    let (owner) = Ownable.owner();

    with_attr error_message("Mint not started") {
        assert wlMintState = TRUE;
    }

    let (root) = WL_Merkle_Root.read();
    let whitelistEnabled = is_not_zero(root);
    let (leaf) = _hash_sorted{hash_ptr=pedersen_ptr}(caller, caller);
    let (isWhiteList) = merkle_verify(leaf, root, proof_len, proof);
 

    with_attr error_message("Proof is not valid"){
        assert isWhiteList = whitelistEnabled;
    }

    with_attr error_message("Already minted") {
        assert address_has_minted = FALSE;
    }    
    _mint(caller, supply + 1, 1);
    Total_Supply.write(supply + 1);
    Wl_Address_Has_Minted.write(caller, TRUE);
    return ();
}


@external
func publicMint{pedersen_ptr: HashBuiltin*, syscall_ptr: felt*, range_check_ptr}() {
    alloc_locals;
    let (mintPrice) = Public_Mint_Price.read();
    let (caller) = get_caller_address();
    let (thisAddress) = get_contract_address();
    let (supply) = Total_Supply.read();
    let (publicMintState) = Public_Mint_State.read();
    let (currencyAddress) = Currency_Address.read();
    let (owner) = Ownable.owner();
    let (address_mint_count) = Address_Mint_Count.read(caller);

    with_attr error_message("Mint not started") {
        assert publicMintState = TRUE;
    }

    with_attr error_message("Max mint exceeded(Max: 1)") {
        assert_le(address_mint_count, PER_PUBLIC_ADDRESS);
    }

    with_attr error_message("MAX SUPPLY EXCEEDED") {
        assert_le(supply , MAX_SUPPLY);
    }


    let (success: felt) = IERC20.transferFrom(
        contract_address=currencyAddress,
        sender=caller,
        recipient=thisAddress,
        amount=mintPrice
    );
    with_attr error_message("ERC20 transfer failed"){
        assert success = 1;
    }

    _mint(caller,supply + 1, 1);
    Total_Supply.write(supply + 1);
    Address_Mint_Count.write(caller,1);
    return ();
}


@external
func transferOwnership{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    newOwner: felt
) {
    Ownable.assert_only_owner();
    Ownable.transfer_ownership(newOwner);
    return ();
}

@external
func renounceOwnership{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() {
    Ownable.assert_only_owner();
    Ownable.renounce_ownership();
    return ();
}

@external
func pause{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() {
    Ownable.assert_only_owner();
    Pausable._pause();
    return ();
}

@external
func unpause{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() {
    Ownable.assert_only_owner();
    Pausable._unpause();
    return ();
}

@external
func set_base_uri{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    ipfs_uri_len:felt,ipfs_uri: felt*
) {
    Ownable.assert_only_owner();
    Base_Uri_Len.write(ipfs_uri_len);
    _set_base_uri(0,ipfs_uri_len,ipfs_uri);
    return ();
}

@external
func setTokenUriExtension{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    extension: felt
) {
    Ownable.assert_only_owner();
    Base_Uri_Extension.write(extension);
    return ();
}


@external
func setPublicMintPrice{pedersen_ptr: HashBuiltin*, syscall_ptr: felt*, range_check_ptr}(
    _price: Uint256
) {
    Ownable.assert_only_owner();
    Public_Mint_Price.write(_price);
    return ();
}

@external
func setCurrencyAddress{pedersen_ptr: HashBuiltin*, syscall_ptr: felt*, range_check_ptr}(
    address: felt
) {
    Ownable.assert_only_owner();
    Currency_Address.write(address);
    return ();
}

@external
func startPublicMint{pedersen_ptr: HashBuiltin*, syscall_ptr: felt*, range_check_ptr}(
    
) {
    Ownable.assert_only_owner();
    Public_Mint_State.write(TRUE);
    return ();
}

@external
func stopPublicMint{pedersen_ptr: HashBuiltin*, syscall_ptr: felt*, range_check_ptr}(
) {
    Ownable.assert_only_owner();
    Public_Mint_State.write(FALSE);
    return ();
}

@external
func startWlMint{pedersen_ptr: HashBuiltin*, syscall_ptr: felt*, range_check_ptr}(
    
) {
    Ownable.assert_only_owner();
    Whitelist_Mint_State.write(TRUE);
    return ();
}

@external
func stopWlMint{pedersen_ptr: HashBuiltin*, syscall_ptr: felt*, range_check_ptr}(
) {
    Ownable.assert_only_owner();
    Whitelist_Mint_State.write(FALSE);
    return ();
}


@external
func burn{pedersen_ptr: HashBuiltin*, syscall_ptr: felt*, range_check_ptr}(token_id: Uint256
) {
    ERC721.assert_only_token_owner(token_id);
    ERC721._burn(token_id);
    return ();
}

@external
func setWlMerkleRoot{pedersen_ptr: HashBuiltin*, syscall_ptr: felt*, range_check_ptr}(root: felt
) {
    Ownable.assert_only_owner();
    WL_Merkle_Root.write(root);
    return ();
}

@external
func withdraw{
    syscall_ptr: felt*,
    pedersen_ptr: HashBuiltin*,
    range_check_ptr
}(receiver: felt){
    alloc_locals;
    Ownable.assert_only_owner();

    let (this_address) = get_contract_address();
    let (caller_address) = get_caller_address();
    let (currencyAddress) = Currency_Address.read();
    let (balance: Uint256) = IERC20.balanceOf(
        contract_address=currencyAddress,
        account=this_address);

     with_attr error_message("Transfer failed"){
        let (success_owner: felt) = IERC20.transfer(
            contract_address=currencyAddress,
            recipient=receiver,
            amount=balance);
        assert success_owner = 1;
    }

    return ();
}


func _exists{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    token_id: Uint256
) -> felt {
    let (exists) = ERC721.owner_of(token_id);
    if (exists == FALSE) {
        return FALSE;
    }

    return TRUE;
}

func _mint{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    to:felt, _tokenId:felt, amount: felt,
) {
    if (amount == 0) {
        return ();
    }
    ERC721._mint(to,Uint256(_tokenId, 0));
    _mint(to,_tokenId +1, amount -1);
    return ();
}

func _set_base_uri{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(index:felt, ipfs_uri_len: felt,ipfs_uri:felt*) {

    if (ipfs_uri_len == index){
        return ();
    }
    Base_Uri.write(index+1,ipfs_uri[index]);
    _set_base_uri(index = index+1, ipfs_uri_len =ipfs_uri_len ,ipfs_uri = ipfs_uri); 
    return ();
}

func _tokenUri{
        syscall_ptr : felt*,
        pedersen_ptr : HashBuiltin*,
        range_check_ptr : felt
    }(uri_count: felt,token_uri_len: felt,token_uri: felt*){

    if (token_uri_len == uri_count){
        return ();
    }

    let (ipfsUri) = Base_Uri.read(token_uri_len+1);

    assert [token_uri] = ipfsUri;

    _tokenUri(
        uri_count=uri_count,
        token_uri_len=token_uri_len + 1,
        token_uri=token_uri +1
    );

    return ();
}


func _uint_to_felt{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    value: Uint256
) -> (value: felt) {
    assert_lt_felt(value.high, 2 ** 123);
    return (value.high * (2 ** 128) + value.low,);
}
