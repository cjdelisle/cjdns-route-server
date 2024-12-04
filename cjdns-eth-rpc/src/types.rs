use alloy::{
    contract::Event,
    network::EthereumWallet,
    providers::{
        fillers::{
            BlobGasFiller, ChainIdFiller, FillProvider, GasFiller, JoinFill, NonceFiller, WalletFiller
        }, Identity, Provider
    },
};

pub const RPC_MAX_TRIES: i32 = 5;

pub type AlloyTransport = alloy::transports::http::Http<alloy::transports::http::Client>;
pub type AlloyProvider = alloy::providers::RootProvider<AlloyTransport>;
pub type AlloyNetwork = alloy::network::Ethereum;

pub type AlloyTransportWs = alloy::pubsub::PubSubFrontend;
pub type AlloyProviderWs = alloy::providers::RootProvider<AlloyTransportWs>;

pub type AlloyEvent<'a,X> = Event<AlloyTransportWs,&'a AlloyProviderWs,X,AlloyNetwork>;

pub trait GenericProvider: Provider<AlloyTransport, AlloyNetwork> + Clone {}
impl<X> GenericProvider for X where X: Provider<AlloyTransport, AlloyNetwork> + Clone {}

pub type AlloyFilledProvider = FillProvider<
    JoinFill<
        Identity,
        JoinFill<
            GasFiller,
            JoinFill<
                BlobGasFiller,
                JoinFill<
                    NonceFiller,
                    ChainIdFiller
                >
            >
        >
    >,
    AlloyProvider,
    AlloyTransport,
    AlloyNetwork
>;

pub type WalletExecutorProvider = FillProvider<
    JoinFill<
        JoinFill<
            Identity,
            JoinFill<
                GasFiller,
                JoinFill<
                    BlobGasFiller,
                    JoinFill<NonceFiller, ChainIdFiller>,
                >
            >
        >,
        WalletFiller<EthereumWallet>,
    >,
    AlloyProvider,
    AlloyTransport,
    AlloyNetwork
>;