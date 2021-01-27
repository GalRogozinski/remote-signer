#[macro_use] extern crate log;

use std::borrow::{BorrowMut, Borrow};
use std::convert::TryFrom;
use std::error::Error;
use std::net::SocketAddr;
use std::ops::{DerefMut, Deref};
use async_std::sync::{Arc, Mutex};

use clap::{App, Arg, ArgMatches};
use ed25519_zebra::{Signature, VerificationKey};
use futures::{future, TryFutureExt};
use futures::join;
use itertools::Itertools;
use log::LevelFilter;
use simple_logger::SimpleLogger;
use tokio::signal::unix::{signal, SignalKind};
use tonic::{Request, Response, Status, transport::Server};
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity};

use dispatcher::{SignMilestoneRequest, SignMilestoneResponse};
use dispatcher::signature_dispatcher_server::{SignatureDispatcher, SignatureDispatcherServer};
use remote_signer::common::config;
use remote_signer::common::config::{BytesKeySigner, DispatcherConfig};
use signer::signer_client::SignerClient;
use signer::SignWithKeyRequest;

pub mod dispatcher {
    tonic::include_proto!("dispatcher");
}

pub mod signer {
    tonic::include_proto!("signer");
}

#[derive(Debug)]
pub struct Ed25519SignatureDispatcher {
    config: DispatcherConfig,
    tls_auth: ClientTlsConfig,
    keysigners: Vec<config::BytesKeySigner>,
    config_path: String,
}

impl Ed25519SignatureDispatcher {
    async fn connect_signer_tls(&self, endpoint: String) -> Result<Channel, Box<dyn Error>>
    {
        let tls_config = self.tls_auth.clone();
        Ok(
            Channel::from_shared(endpoint)?
                .tls_config(tls_config)?
                .connect()
                .await?
        )
    }

    // fn set_config(&mut self, config: DispatcherConfig) {
    //     self.config = config;
    // }
    //
    // fn set_tls_auth(&mut self, tls_auth: ClientTlsConfig) {
    //     self.tls_auth = tls_auth;
    // }
    //
    // fn set_key_signers(&mut self, key_signers: Vec<config::BytesKeySigner>) {
    //     self.keysigners = key_signers;
    // }
    //
    // fn set_config_path(&mut self, config_path: String) {
    //     self.config_path = config_path;
    // }
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
        let pub_keys_unique = r.pub_keys.iter().unique();
        // We do not need to check for the lexicographical sorting of the keys, it is not our job

        let matched_signers = pub_keys_unique.map(|pubkey| {
            self.keysigners.iter().find(
                |keysigner| keysigner.pubkey == *pubkey
            )
        });

        // Clone the iterator to avoid consuming it for the next map
        if matched_signers.clone().any(|signer| signer.is_none()) {
            warn!("Requested public key is not known!");
            warn!("Request: {:?}", request);
            warn!("Available Signers: {:?}", self.keysigners);
            return Err(Status::invalid_argument("I don't know the signer for one or more of the provided public keys."))
        }

        let confirmed_signers = matched_signers.map(|signer| signer.unwrap());

        info!("Got Request that matches signers: {:?}", confirmed_signers);

        let signatures = future::join_all(
            // map of Futures<Output=Result<SignWithKeyResponse, Error>>
            confirmed_signers.clone().map(|signer|
                async move {
                    let channel = match self.connect_signer_tls(signer.endpoint.clone()).await {
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
async fn main() -> Result<(), Box<dyn std::error::Error>> {
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
    let (addr, mut dispatcher) = create_dispatcher(conf_path).await?;
    debug!("Initialized Dispatcher server: {:?}", dispatcher);

    let conf_path = dispatcher.config_path.clone();
    let mut conf = &dispatcher.config;
    let mut key_signers = &dispatcher.keysigners;
    let mut tls_auth = &dispatcher.tls_auth;


    let mut server = Server::builder();
    let serv = server.add_service(SignatureDispatcherServer::new(dispatcher))
        .serve(addr);
    info!("Serving on {}...", addr);

    let signal = reload_configs_upon_signal(conf_path, conf, &mut key_signers, tls_auth);

    info!("listening for sighup");

    futures::join!(serv, signal);
    Ok(())
}

async fn create_dispatcher(conf_path: &str) -> Result<(SocketAddr, Ed25519SignatureDispatcher), Box<dyn std::error::Error>> {
    let (config, keysigners, addr, tls_auth) = parse_confs(conf_path).await?;
    let config_path = conf_path.to_string();
    let mut dispatcher = Ed25519SignatureDispatcher {
        config: config,
        tls_auth: tls_auth,
        keysigners: keysigners,
        config_path: config_path
    };
    Ok((addr, dispatcher))
}

async fn parse_confs(conf_path: &str) -> Result<(DispatcherConfig, Vec<BytesKeySigner>, SocketAddr, ClientTlsConfig), Box<dyn std::error::Error>> {
    info!("Parsing configuration file `{}`.", conf_path);
    let (config, keysigners) = config::parse_dispatcher(conf_path)?;
    debug!("Parsed configuration file: {:?}", config);
    let addr = config.bind_addr.parse()?;
    let server_root_ca_cert = tokio::fs::read(&config.tlsauth.ca).await?;
    let server_root_ca_cert = Certificate::from_pem(server_root_ca_cert);
    let client_cert = tokio::fs::read(&config.tlsauth.client_cert).await?;
    let client_key = tokio::fs::read(&config.tlsauth.client_key).await?;
    let client_identity = Identity::from_pem(client_cert, client_key);
    let tls_auth = ClientTlsConfig::new()
        .ca_certificate(server_root_ca_cert)
        .identity(client_identity);
    Ok((config, keysigners, addr, tls_auth))
}

async fn reload_configs_upon_signal(conf_path : String, mut config_a: &DispatcherConfig, mut key_signers_a: &mut Vec<BytesKeySigner>,
mut tls_auth_a: &ClientTlsConfig) -> Result<(), Box<dyn std::error::Error>> {
    let mut stream = signal(SignalKind::hangup())?;

    // Print whenever a HUP signal is received
    loop {
        stream.recv().await;
        info!("got signal HUP");
        let (config, keysigners, _, tls_auth) = parse_confs(&conf_path).await?;
        // config_a.clone_from(&Arc::new(config));
        key_signers_a.clear();
        for bk in keysigners  {
            key_signers_a.push(bk)
        }
        // tls_auth_a.clone_from(&&tls_auth);
    }
}