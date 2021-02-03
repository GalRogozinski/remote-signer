#[macro_use] extern crate log;

use std::convert::TryFrom;
use std::error::Error;
use std::net::SocketAddr;
use async_std::sync::{Arc, Mutex};

use clap::{App, Arg};
use ed25519_zebra::{Signature, VerificationKey};
use futures::{future, TryFutureExt};
use futures::join;
use itertools::Itertools;
use log::LevelFilter;
use simple_logger::SimpleLogger;
use tokio::signal::unix::{signal, SignalKind};
use tonic::{Request, Response, Status, transport::Server};
use tonic::transport::Channel;

use dispatcher::{SignMilestoneRequest, SignMilestoneResponse};
use dispatcher::signature_dispatcher_server::{SignatureDispatcher, SignatureDispatcherServer};
use remote_signer::common::config;
use remote_signer::common::config::{BytesKeySigner, DispatcherConfig};
use signer::signer_client::SignerClient;
use signer::SignWithKeyRequest;
use remote_signer::RemoteSignerError;

pub mod dispatcher {
    tonic::include_proto!("dispatcher");
}

pub mod signer {
    tonic::include_proto!("signer");
}

#[derive(Debug)]
pub struct Ed25519SignatureDispatcher {
    keysigners: Arc<Mutex<Vec<config::BytesKeySigner>>>
}

impl Ed25519SignatureDispatcher {
    async fn connect_signer(&self, endpoint: String) -> Result<Channel, Box<dyn Error>>
    {
        Ok(
            Channel::from_shared(endpoint)?
                .connect()
                .await?
        )
    }
}

#[tonic::async_trait]
impl SignatureDispatcher for Ed25519SignatureDispatcher {
    async fn sign_milestone(
        &self,
        request: Request<SignMilestoneRequest>,
    ) -> Result<Response<SignMilestoneResponse>, Status> {

        debug!("Got Request: {:?}", request);

        let r = request.get_ref();
        // Check that the pubkeys do not repeat
        let mut pub_keys_unique = r.pub_keys.iter().unique();
        // We do not need to check for the lexicographical sorting of the keys, it is not our job

        let mut matched_signers: Vec<Option<BytesKeySigner>> = Vec::new();
        {
            let keysigners_guard = self.keysigners.lock().await;
            for signer in keysigners_guard.iter() {
                if pub_keys_unique.any(|key| signer.pubkey.eq(key)) {
                    matched_signers.push(Some(signer.to_owned()));
                }
            }
        }


        // Clone the iterator to avoid consuming it for the next map
        if matched_signers.is_empty() {
            warn!("Requested public key is not known!");
            warn!("Request: {:?}", request);
            warn!("Available Signers: {:?}", self.keysigners);
            return Err(Status::invalid_argument("I don't know the signer for one or more of the provided public keys."))
        }

        let confirmed_signers = matched_signers.iter().map(|signer| signer.as_ref().unwrap());

        info!("Got Request that matches signers: {:?}", confirmed_signers);

        let signatures = future::join_all(
            // map of Futures<Output=Result<SignWithKeyResponse, Error>>
            confirmed_signers.clone().map(|signer|
                async move {
                     let channel = match self.connect_signer(signer.endpoint.clone()).await {
                        Ok(channel) => channel,
                        Err(e) => {
                            error!("Error connecting to Signer!");
                            error!("Signer: {:?}", signer);
                            error!("Error: {:?}", e);
                            return Err(Status::internal(format!("Could not connect to the Signer `{}`, {}", signer.endpoint, e)))
                        }
                    };

                    let mut client = SignerClient::new(channel);

                    let req = tonic::Request::new(SignWithKeyRequest {
                        pub_key: signer.pubkey.to_owned(),
                        ms_essence: r.ms_essence.to_owned()
                    });

                    debug!("Sending request to Signer `{}`: {:?}", signer.endpoint, req);
                    let res = client.sign_with_key(req).await;
                    if res.is_err() {
                        error!("Error getting response from Signer `{}`: {:?}", signer.endpoint, res);
                    }
                    debug!("Got Response from Signer `{}`: {:?}", signer.endpoint, res);

                    let verification_key = VerificationKey::try_from(signer.pubkey.as_slice()).unwrap();
                    let signature = match Signature::try_from(res.as_ref().unwrap().get_ref().signature.as_slice()) {
                        Ok(signature) => signature,
                        Err(e) => {
                            error!("Invalid signature format returned by Signer!");
                            error!("Signer: {:?}", signer);
                            error!("Error: {:?}", e);
                            return Err(Status::internal(format!("Invalid signature format returned by signer `{}`, {:?}", signer.endpoint, e)))
                        }
                    };
                    if verification_key.verify(&signature, r.ms_essence.as_slice()).is_err() {
                        error!("Invalid signature returned by Signer!");
                        error!("Signer: {:?}", signer);
                        error!("Signature: {:?}", signature);
                        return Err(Status::internal(format!("Invalid signature returned by signer `{}`", signer.endpoint)))
                    }

                    res
                }
            )
        );

        let signatures = signatures.await;
        if let Some(e) = signatures.iter().find(|signature| signature.is_err()) {
            return Err(e.as_ref().unwrap_err().to_owned());
        }

        let reply = SignMilestoneResponse {
            signatures: signatures.iter().map(|signature| signature.as_ref().unwrap().get_ref().to_owned().signature).collect()
        };

        info!("Successfully signed.");
        info!("MS Essence: {:?}", r.ms_essence);
        info!("Used Signers: {:?}", confirmed_signers.collect::<Vec<_>>());
        info!("Signatures: {:?}", reply.signatures);

        Ok(Response::new(reply))
    }
}

#[tokio::main]
async fn main() -> remote_signer::Result<()> {
    SimpleLogger::from_env().with_level(LevelFilter::Info).init().unwrap();
    let config_arg = App::new("Remote Signer Dispatcher")
        .arg(Arg::with_name("config")
             .short("c")
             .long("config")
             .takes_value(true)
             .value_name("FILE")
             .default_value("dispatcher_config.json")
             .help("Dispatcher .json configuration file")
        ).get_matches();

    info!("Start");

    let conf_path = config_arg.value_of("config").unwrap();
    let (addr, dispatcher) = create_dispatcher(conf_path).await?;
    debug!("Initialized Dispatcher server: {:?}", dispatcher);

    let key_signers = Arc::clone(&dispatcher.keysigners);


    let mut server = Server::builder();
    let serv = server
        .add_service(SignatureDispatcherServer::new(dispatcher))
        .serve(addr)
        .map_err(|err| RemoteSignerError::from(err));

    info!("Serving on {}...", addr);

    let signal = reload_configs_upon_signal(&conf_path, key_signers);

    info!("listening for sighup");

    let result = future::try_join(serv, signal).await;

    match result {
        Ok(_) => Ok(()),
        Err(e) => Err(e),
    }
}

async fn create_dispatcher(conf_path: &str) -> remote_signer::Result<(SocketAddr, Ed25519SignatureDispatcher)> {
    let (_, keysigners, addr) = parse_confs(conf_path).await?;
    let dispatcher = Ed25519SignatureDispatcher {
        keysigners: Arc::new(Mutex::new(keysigners))
    };
    Ok((addr, dispatcher))
}

async fn parse_confs(conf_path: &str) -> remote_signer::Result<(DispatcherConfig, Vec<BytesKeySigner>, SocketAddr)> {
    info!("Parsing configuration file `{}`.", conf_path);
    let (config, keysigners) = config::parse_dispatcher(conf_path)?;
    let addr = config.bind_addr.parse()?;
    Ok((config, keysigners, addr))
}

async fn reload_configs_upon_signal(conf_path : &str, key_signers_a: Arc<Mutex<Vec<BytesKeySigner>>>) -> remote_signer::Result<()> {
    let mut stream = signal(SignalKind::hangup())
        .expect("Problems receiving signal");

    // Print whenever a HUP signal is received
    loop {
        stream.recv().await;
        let conf = parse_confs(conf_path).await;
        if conf.is_err() {
            error!("Can't parse configs. {:?}", conf.err().unwrap());
            continue;
        }
        let (_, keysigners, _) = conf.unwrap();
        let mut signers = key_signers_a.lock().await;
        signers.clear();
        for signer in keysigners {
            signers.push(signer);
        }
    }
}