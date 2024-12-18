use alloy::sol;

pub mod assign {
    alloy::sol!(
        #[allow(missing_docs)]
        #[sol(rpc)]
        #[sol(all_derives)]
        Assign,
        "abi/Assign.json"
    );
}

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    YieldVault,
    "abi/YieldVault.json"
);

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    Token,
    "abi/Token.json"
);

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    #[sol(all_derives)]
    Infra,
    "abi/Infra.json"
);

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    #[sol(all_derives)]
    Lockbox,
    "abi/Lockbox.json"
);

pub const LOCKBOX_TOOLS_ADDR: &str = "0xea3c14F74e16E8462925f82Ad8d528a5d804617D";
sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    #[sol(all_derives)]
    LockboxTools,
    "abi/LockboxTools.json"
);

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    Airdrop,
    "abi/Airdrop.json"
);

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    Lp,
    "abi/Lp.json"
);

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    Multipay,
    "abi/Multipay.json"
);

pub const PNS_ADDR: &str = "0xDc8eb1D1052a2078B33dd188201eAf3F080E0258";
sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    Pns,
    "abi/PNS.json"
);