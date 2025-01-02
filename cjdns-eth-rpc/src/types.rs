use alloy::{
    contract::Event,
    network::EthereumWallet,
    providers::{
        fillers::{
            BlobGasFiller, ChainIdFiller, FillProvider, GasFiller, JoinFill, NonceFiller, WalletFiller
        }, Identity, Provider
    }, transports::http::reqwest::Url,
};

pub type AlloyTransport = alloy::transports::http::Http<alloy::transports::http::Client>;
pub type AlloyProvider = alloy::providers::RootProvider<AlloyTransport>;
pub type AlloyNetwork = alloy::network::Ethereum;

pub type AlloyTransportWs = alloy::pubsub::PubSubFrontend;
pub type AlloyProviderWs = alloy::providers::RootProvider<AlloyTransportWs>;

pub type AlloyEvent<'a,X> = Event<AlloyTransportWs,&'a AlloyProviderWs,X,AlloyNetwork>;

pub trait GenericProvider: 'static + Provider<AlloyTransport, AlloyNetwork> + Clone {}
impl<X> GenericProvider for X where X: 'static + Provider<AlloyTransport, AlloyNetwork> + Clone {}

type DefaultFillers = JoinFill<
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
>;

pub type AlloyFilledProvider = FillProvider<
    DefaultFillers,
    AlloyProvider,
    AlloyTransport,
    AlloyNetwork
>;

pub type AlloyWalletFilledProvider = FillProvider<
    JoinFill<
        DefaultFillers,
        WalletFiller<EthereumWallet>
    >,
    AlloyProvider,
    AlloyTransport,
    AlloyNetwork
>;

pub trait MkProvider<X: GenericProvider> {
    fn mk_provider(&self, url: Url) -> X;
}