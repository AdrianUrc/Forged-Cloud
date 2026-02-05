use crate::server::client::Client;
use crate::server::files::FileManager;
use crate::server::security::Security;
use crate::server::state::State;
use crate::server::token_store::TokenStore;
use rustls_pemfile::{certs, pkcs8_private_keys};
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::{Certificate, PrivateKey, RootCertStore, ServerConfig};
use tracing::{error, info};
use uuid::Uuid;

pub struct Listener {
    address: String,
    state: Arc<State>,
    security: Arc<Security>,
    file_manager: Arc<FileManager>,
    token_store: Arc<TokenStore>,
}

impl Listener {
    pub fn new(
        address: String,
        state: Arc<State>,
        security: Arc<Security>,
        file_manager: Arc<FileManager>,
        token_store: Arc<TokenStore>,
    ) -> Self {
        Self {
            address,
            state,
            security,
            file_manager,
            token_store,
        }
    }
    pub async fn run(&self) {
        let listener = TcpListener::bind(&self.address)
            .await
            .expect("[ERROR] Failed starting the server.");
        tracing::info!("[*] Starting TCP Listener on tcp://{}...", self.address);
        // TLS Config
        let tls_config = load_tls_config();
        tracing::info!("[*] Loaded mTLS config on TCP Listener module.");
        let acceptor = TlsAcceptor::from(Arc::new(tls_config));

        // Loop to handle each connection separately
        loop {
            match listener.accept().await {
                Ok((mut socket, addr)) => {
                    // Connection stabblished
                    let client_ipv4 = match addr.ip() {
                        core::net::IpAddr::V4(v4) => v4,
                        core::net::IpAddr::V6(v6) => {
                            tracing::warn!("[SERVER] IPv6 client not supported yet: {}", v6);
                            continue;
                        }
                    };
                    // Check if server can afford more sessions
                    if self.state.get_clients_count().await >= self.state.max_connections() {
                        if let Err(e) = socket.write_all(b"[SERVER] Access denied.\n").await {
                            error!("[ERROR] Cannot send data to client: {}", e);
                        }
                        drop(socket);
                        continue;
                    }
                    // Check if address is banned
                    if self.security.is_banned(client_ipv4).await {
                        if let Err(e) = socket.write_all(b"[SERVER] Your IP is banned.\n").await {
                            error!("[ERROR] Cannot send data to client: {}", e);
                        }
                        drop(socket);
                        continue;
                    }
                    let client_uuid: Uuid = Uuid::new_v4();
                    let state_clone = self.state.clone();
                    let security_clone = self.security.clone();
                    let acceptor = acceptor.clone();
                    let token_store_clone = self.token_store.clone();
                    let file_manager_clone = self.file_manager.clone();
                    // Handle clients on different tasks
                    tokio::spawn(async move {
                        // Timeout (10 secs) for TLS Handshake
                        let handshake =
                            timeout(Duration::from_secs(10), acceptor.accept(socket)).await;
                        match handshake {
                            Ok(Ok(tls_socket)) => {
                                // Register client in state
                                state_clone.add_session(client_uuid).await;
                                state_clone.increase_clients_count().await;
                                info!("[SERVER] Client connected on: {}", client_ipv4.to_string());
                                info!(
                                    "[SYSTEM] Total clients connected: {}",
                                    state_clone.get_clients_count().await
                                );
                                let client = Client::new(
                                    client_uuid,
                                    tls_socket,
                                    client_ipv4,
                                    state_clone.clone(),
                                    security_clone,
                                    file_manager_clone,
                                    token_store_clone,
                                );
                                client.run().await;
                                state_clone.remove_session(client_uuid).await;
                                state_clone.decrease_clients_count().await;
                                info!("[SERVER] Session removed from server: {}", client_uuid);
                            }
                            Ok(Err(e)) => {
                                error!("[TLS] Failed handshake with {}: {}", client_ipv4, e);
                            }
                            Err(_) => {
                                error!("[TLS] Timeout waiting for handshake with: {}", client_ipv4);
                            }
                        }
                    });
                }
                Err(e) => {
                    // Cannot resolve connection
                    error!("[ERROR] Failed to accept connection: {}", e);
                }
            }
        }
    }
}
fn load_tls_config() -> ServerConfig {
    let cert_file = &mut BufReader::new(File::open("cert.pem").expect("cannot open cert.pem"));
    let key_file = &mut BufReader::new(File::open("key.pem").expect("cannot open key.pem"));

    // Load server public certificate
    let cert_chain: Vec<Certificate> = certs(cert_file)
        .expect("failed to read certificate")
        .into_iter()
        .map(Certificate)
        .collect();

    // Load private key (PKCS#8)
    let mut keys: Vec<PrivateKey> = pkcs8_private_keys(key_file)
        .expect("failed to read private key")
        .into_iter()
        .map(PrivateKey)
        .collect();

    assert!(!keys.is_empty(), "no private keys found in key.pem");

    let ca_file = &mut BufReader::new(File::open("ca.pem").expect("cannot open ca.pem"));
    let mut root_store = RootCertStore::empty();
    root_store.add_parsable_certificates(&certs(ca_file).expect("failed to read CA certificate"));
    let verifier = rustls::server::AllowAnyAuthenticatedClient::new(root_store);

    ServerConfig::builder()
        .with_safe_defaults()
        .with_client_cert_verifier(Arc::new(verifier)) // .with_no_client_auth() -> FOR only server tls
        .with_single_cert(cert_chain, keys.remove(0))
        .expect("invalid certificate or key")
}
