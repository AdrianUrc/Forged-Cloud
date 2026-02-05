use crate::server::{files::FileManager, token_store::TokenStore};
use hyper::{Body, Request, Response, StatusCode, service::service_fn};
use rustls_pemfile::{certs, pkcs8_private_keys};
use std::{fs::File, io::BufReader, sync::Arc, time::SystemTime};
use tokio::net::TcpListener;
use tokio::time::timeout;
use tokio_rustls::{
    TlsAcceptor,
    rustls::{Certificate, PrivateKey, ServerConfig},
};
use tracing::error;
use uuid::Uuid;

pub struct HttpServer {
    address: String,
    file_manager: Arc<FileManager>,
    token_store: Arc<TokenStore>,
}

impl HttpServer {
    pub fn new(
        address: String,
        file_manager: Arc<FileManager>,
        token_store: Arc<TokenStore>,
    ) -> Self {
        Self {
            address,
            file_manager,
            token_store,
        }
    }

    pub async fn run(&self) {
        let listener = TcpListener::bind(&self.address)
            .await
            .expect("[ERROR] Failed starting HTTPS server");
        tracing::info!("[*] Starting HTTPS Listener on https://{}", self.address);
        let tls_config = load_tls_config();
        tracing::info!("[*] Loaded TLS config on HTTPS Listener module.");
        let acceptor = TlsAcceptor::from(Arc::new(tls_config));

        loop {
            let (socket, addr) = match listener.accept().await {
                Ok(x) => x,
                Err(e) => {
                    error!("[HTTP] Failed to accept connection: {}", e);
                    continue;
                }
            };

            let acceptor = acceptor.clone();
            let file_manager = self.file_manager.clone();
            let token_store = self.token_store.clone();

            tokio::spawn(async move {
                let handshake =
                    timeout(std::time::Duration::from_secs(15), acceptor.accept(socket)).await;

                match handshake {
                    Ok(Ok(tls_stream)) => {
                        if let Err(e) = hyper::server::conn::Http::new()
                            .serve_connection(
                                tls_stream,
                                service_fn(move |req| {
                                    handle_request(req, file_manager.clone(), token_store.clone())
                                }),
                            )
                            .await
                        {
                            error!("[HTTP] Connection error with {}: {}", addr, e);
                        }
                    }
                    Ok(Err(e)) => error!("[TLS] Handshake failed with {}: {}", addr, e),
                    Err(_) => error!("[TLS] Timeout waiting for handshake with {}", addr),
                }
            });
        }
    }
}

async fn handle_request(
    req: Request<Body>,
    file_manager: Arc<FileManager>,
    token_store: Arc<TokenStore>,
) -> Result<Response<Body>, hyper::Error> {
    let path = req.uri().path().to_string();

    // Path -> /download/<uuid>
    if let Some(uuid_str) = path.strip_prefix("/download/") {
        if let Ok(uuid) = Uuid::parse_str(uuid_str) {
            // Buscar el token en el TokenStore
            if let Some(token) = token_store.consume(uuid).await {
                // Verificar expiración
                if token.expiration() <= SystemTime::now() {
                    return Ok(response_text(StatusCode::FORBIDDEN, "Token expired"));
                }

                // Read file
                match file_manager.read_file(&token.filename()) {
                    Ok(content) => {
                        let resp = Response::builder()
                            .status(StatusCode::OK)
                            .header("Content-Type", "application/octet-stream")
                            .header(
                                "Content-Disposition",
                                format!("attachment; filename=\"{}\"", token.filename()),
                            )
                            .body(Body::from(content))
                            .unwrap();
                        return Ok(resp);
                    }
                    Err(e) => {
                        error!("[HTTP] Failed to read file {}: {}", token.filename(), e);
                        return Ok(response_text(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "Error reading file",
                        ));
                    }
                }
            }
        }
        return Ok(response_text(
            StatusCode::FORBIDDEN,
            "Invalid or expired token",
        ));
    }

    Ok(response_text(StatusCode::NOT_FOUND, "Not found"))
}

fn response_text(status: StatusCode, text: &str) -> Response<Body> {
    Response::builder()
        .status(status)
        .header("Content-Type", "text/plain")
        .body(Body::from(text.to_string()))
        .unwrap()
}

fn load_tls_config() -> ServerConfig {
    let cert_file = &mut BufReader::new(
        File::open("certs/server-cert.pem").expect("cannot open server-cert.pem"),
    );
    let key_file = &mut BufReader::new(
        File::open("certs/server-key.pem").expect("cannot open server-key.pem"),
    );

    // Load public cert
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

    /*let ca_file = &mut BufReader::new(File::open("ca.pem").expect("cannot open ca.pem"));
    let mut root_store = RootCertStore::empty();
    root_store.add_parsable_certificates(&certs(ca_file).expect("failed to read CA certificate"));
    let verifier = rustls::server::AllowAnyAuthenticatedClient::new(root_store);*/

    ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth() //.with_client_cert_verifier(Arc::new(verifier)) -> For mtls
        .with_single_cert(cert_chain, keys.remove(0))
        .expect("invalid certificate or key")
}
