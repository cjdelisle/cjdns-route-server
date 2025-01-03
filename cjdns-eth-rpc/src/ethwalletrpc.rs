use std::{future::IntoFuture, ops::Deref, sync::Arc, time::Duration};

use alloy::{network::EthereumWallet, providers::ProviderBuilder, transports::http::reqwest::Url};
use eyre::{bail,Result};

use crate::{
    types::{AlloyWalletFilledProvider, MkProvider},
    ethrpc::EthRpc,
};

pub struct EthWalletRpc {
    rpc: Arc<EthRpc>,
    wallet: EthereumWallet,
    rpc_max_tries: i32,
    rpc_timeout_seconds: u8,
}
impl EthWalletRpc {
    pub fn new(rpc: Arc<EthRpc>, wallet: EthereumWallet, rpc_max_tries: u8, rpc_timeout_seconds: u8) -> Self {
        Self {
            rpc,
            wallet,
            rpc_max_tries: rpc_max_tries as i32,
            rpc_timeout_seconds,
        }
    }
    pub async fn do_eth<Y,FY,F>(
        &self,
        f: F,
    ) -> Result<Y>
        where
            F: Fn(AlloyWalletFilledProvider) -> FY,
            FY: IntoFuture<Output=eyre::Result<Y>>,
    {
        let mut i = 0;
        loop {
            i += 1;
            let (rpc, rpc_info) = self.rpc.rpc(self).await?;
            let _provider = rpc.provider.clone();
            tokio::select! {
                res = f(rpc.provider).into_future() => {
                    match res {
                        Err(e) => {
                            crate::error::handle_generic_error(e.into(), i, &rpc_info, self.rpc_max_tries).await?;
                        }
                        Ok(res) => {
                            rpc_info.set_alive().await;
                            return Ok(res);
                        }
                    }
                }
                _ = tokio::time::sleep(Duration::from_secs(self.rpc_timeout_seconds as _)) => {
                    if i > self.rpc_max_tries {
                        bail!("do_eth() Failed after {} tries to create transaction", self.rpc_max_tries);
                    } else {
                        println!("do_eth() timed out attempt ({} sec) {}/{}, retry...",
                            self.rpc_timeout_seconds, i, self.rpc_max_tries);
                    }
                }
            }
        }
    }
}
impl Deref for EthWalletRpc {
    type Target = Arc<EthRpc>;
    fn deref(&self) -> &Self::Target {
        &self.rpc
    }
}
impl MkProvider<AlloyWalletFilledProvider> for &EthWalletRpc {
    fn mk_provider(&self, url: Url) -> AlloyWalletFilledProvider {
        ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(self.wallet.clone())
            .on_http(url)
    }
}