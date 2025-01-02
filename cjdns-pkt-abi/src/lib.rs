use alloy::primitives::Address;

pub mod assign {
    alloy::sol!(
        #[allow(missing_docs)]
        #[sol(rpc)]
        #[sol(all_derives)]
        Assign,
        "abi/Assign.json"
    );
}
pub use assign::{Assign,IAssign};

pub mod yieldvault {
    alloy::sol!(
        #[allow(missing_docs)]
        #[sol(rpc)]
        #[sol(all_derives)]
        YieldVault,
        "abi/YieldVault.json"
    );
}
pub use yieldvault::YieldVault;

pub mod token {
    alloy::sol!(
        #[allow(missing_docs)]
        #[sol(rpc)]
        #[sol(all_derives)]
        Token,
        "abi/Token.json"
    );
}
pub use token::Token;

pub mod infra {
    alloy::sol!(
        #[allow(missing_docs)]
        #[sol(rpc)]
        #[sol(all_derives)]
        Infra,
        "abi/Infra.json"
    );
}
pub use infra::{Infra,IInfra};

pub mod lockbox {
    alloy::sol!(
        #[allow(missing_docs)]
        #[sol(rpc)]
        #[sol(all_derives)]
        Lockbox,
        "abi/Lockbox.json"
    );
}
pub use lockbox::{Lockbox,ILockBox};

pub mod lockboxtools {
    alloy::sol!(
        #[allow(missing_docs)]
        #[sol(rpc)]
        #[sol(all_derives)]
        LockboxTools,
        "abi/LockboxTools.json"
    );
}
pub use lockboxtools::LockboxTools;

pub mod airdrop {
    alloy::sol!(
        #[allow(missing_docs)]
        #[sol(rpc)]
        #[sol(all_derives)]
        Airdrop,
        "abi/Airdrop.json"
    );
}
pub use airdrop::Airdrop;

pub mod lp {
    alloy::sol!(
        #[allow(missing_docs)]
        #[sol(rpc)]
        #[sol(all_derives)]
        Lp,
        "abi/Lp.json"
    );
}
pub use lp::Lp;

pub mod multipay {
    alloy::sol!(
        #[allow(missing_docs)]
        #[sol(rpc)]
        #[sol(all_derives)]
        Multipay,
        "abi/Multipay.json"
    );
}
pub use multipay::Multipay;

pub mod pns {
    alloy::sol!(
        #[allow(missing_docs)]
        #[sol(rpc)]
        #[sol(all_derives)]
        Pns,
        "abi/PNS.json"
    );
}
pub use pns::{Pns,IPNS};

// 0x917F39Bb33B2483Dd19546b1E8D2f09ce481ee44
pub const TOKEN_ADDR: Address = Address::new(
    *b"\x91\x7f\x39\xbb\x33\xb2\x48\x3d\xd1\x95\x46\xb1\xe8\xd2\xf0\x9c\xe4\x81\xee\x44");

// 0x4200000000000000000000000000000000000006
pub const WETH_ADDR: Address = Address::new(
    *b"\x42\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x06");

// 0xB8bbA9A4f1ea4f987CB42Afb632aF812A9c41530
pub const AIRDROP_ADDR: Address = Address::new(
    *b"\xb8\xbb\xa9\xa4\xf1\xea\x4f\x98\x7c\xb4\x2a\xfb\x63\x2a\xf8\x12\xa9\xc4\x15\x30");

// 0x6183e613DDA1fa146c90bE6E1757AEf15baCAd9d
pub const LP_ADDR: Address = Address::new(
    *b"\x61\x83\xe6\x13\xdd\xa1\xfa\x14\x6c\x90\xbe\x6e\x17\x57\xae\xf1\x5b\xac\xad\x9d");

// 0x88A43bbDF9D098eEC7bCEda4e2494615dfD9bB9C
pub const LP_USDC_ADDR: Address = Address::new(
    *b"\x88\xa4\x3b\xbd\xf9\xd0\x98\xee\xc7\xbc\xed\xa4\xe2\x49\x46\x15\xdf\xd9\xbb\x9c");

// 0x731d54713e91234B9ac8005AB6Eed53F554B0c78
pub const MULTIPAY_ADDR: Address = Address::new(
    *b"\x73\x1d\x54\x71\x3e\x91\x23\x4b\x9a\xc8\x00\x5a\xb6\xee\xd5\x3f\x55\x4b\x0c\x78");

// 0x79B322f41A4A262f06cEE3d6a581574fF4F5322c
pub const ASSIGN_ADDR: Address = Address::new(
    *b"\x79\xb3\x22\xf4\x1a\x4a\x26\x2f\x06\xce\xe3\xd6\xa5\x81\x57\x4f\xf4\xf5\x32\x2c");

// 0x14D15765c66e8f0C7f8757d1D19137B714dfCC60
pub const LOCKBOX_ADDR: Address = Address::new(
    *b"\x14\xd1\x57\x65\xc6\x6e\x8f\x0c\x7f\x87\x57\xd1\xd1\x91\x37\xb7\x14\xdf\xcc\x60");

// 0xFDc0c296A6DafBA5D43af49ffC08741d197B7485
pub const INFRA_ADDR: Address = Address::new(
    *b"\xFD\xc0\xc2\x96\xA6\xDa\xfB\xA5\xD4\x3a\xf4\x9f\xfC\x08\x74\x1d\x19\x7B\x74\x85");

// 0xDc8eb1D1052a2078B33dd188201eAf3F080E0258
pub const PNS_ADDR: Address = Address::new(
    *b"\xDc\x8e\xb1\xd1\x05\x2a\x20\x78\xB3\x3d\xd1\x88\x20\x1e\xAf\x3F\x08\x0E\x02\x58");

// 0xea3c14F74e16E8462925f82Ad8d528a5d804617D
pub const LOCKBOX_TOOLS_ADDR: Address = Address::new(
    *b"\xea\x3c\x14\xf7\x4e\x16\xe8\x46\x29\x25\xf8\x2a\xd8\xd5\x28\xa5\xd8\x04\x61\x7d");

// 0x7b7736df7dEA509105bdBd3Bf9A4c5a9eA4b9E08
pub const YIELD_VAULT_ADDR: Address = Address::new(
    *b"\x7b\x77\x36\xdf\x7d\xea\x50\x91\x05\xbd\xbd\x3b\xf9\xa4\xc5\xa9\xea\x4b\x9e\x08");

#[cfg(test)]
mod tests {
    #[test]
    fn test() {
        assert_eq!(&super::TOKEN_ADDR.to_string(), "0x917F39Bb33B2483Dd19546b1E8D2f09ce481ee44");
        assert_eq!(&super::WETH_ADDR.to_string(), "0x4200000000000000000000000000000000000006");
        assert_eq!(&super::AIRDROP_ADDR.to_string(), "0xB8bbA9A4f1ea4f987CB42Afb632aF812A9c41530");
        assert_eq!(&super::LP_ADDR.to_string(), "0x6183e613DDA1fa146c90bE6E1757AEf15baCAd9d");
        assert_eq!(&super::LP_USDC_ADDR.to_string(), "0x88A43bbDF9D098eEC7bCEda4e2494615dfD9bB9C");
        assert_eq!(&super::MULTIPAY_ADDR.to_string(), "0x731d54713e91234B9ac8005AB6Eed53F554B0c78");
        assert_eq!(&super::ASSIGN_ADDR.to_string(), "0x79B322f41A4A262f06cEE3d6a581574fF4F5322c");
        assert_eq!(&super::LOCKBOX_ADDR.to_string(), "0x14D15765c66e8f0C7f8757d1D19137B714dfCC60");
        assert_eq!(&super::INFRA_ADDR.to_string(), "0xFDc0c296A6DafBA5D43af49ffC08741d197B7485");
        assert_eq!(&super::PNS_ADDR.to_string(), "0xDc8eb1D1052a2078B33dd188201eAf3F080E0258");
        assert_eq!(&super::LOCKBOX_TOOLS_ADDR.to_string(), "0xea3c14F74e16E8462925f82Ad8d528a5d804617D");
        assert_eq!(&super::YIELD_VAULT_ADDR.to_string(), "0x7b7736df7dEA509105bdBd3Bf9A4c5a9eA4b9E08");
    }
}