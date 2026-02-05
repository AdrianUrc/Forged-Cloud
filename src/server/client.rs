use crate::server::download_token::DownloadToken;
use crate::server::files::FileManager;
use crate::server::security::Security;
use crate::server::state::State;
use crate::server::token_store::TokenStore;
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use std::io::Write;
use std::sync::Arc;
use std::time::SystemTime;
use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio::time::{Duration, sleep};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::oneshot,
};
use tokio_rustls::server::TlsStream;
use tracing::{error, info};
use uuid::Uuid;
use zeroize::Zeroizing;

pub struct Client {
    pub uuid: Uuid,
    socket: TlsStream<TcpStream>,
    address: core::net::Ipv4Addr,
    state: Arc<State>,
    security: Arc<Security>,
    file_manager: Arc<FileManager>,
    token_store: Arc<TokenStore>,
}

impl Client {
    pub fn new(
        uuid: Uuid,
        socket: TlsStream<TcpStream>,
        address: core::net::Ipv4Addr,
        state: Arc<State>,
        security: Arc<Security>,
        file_manager: Arc<FileManager>,
        token_store: Arc<TokenStore>,
    ) -> Self {
        Self {
            uuid,
            socket,
            address,
            state,
            security,
            file_manager,
            token_store,
        }
    }
    pub async fn run(mut self) {
        let _ = self
            .socket
            .write_all(b"\n [*] Enter password to log in: ")
            .await;
        // Autentication block
        let mut pass_buffer = [0; 512];
        match self.socket.read(&mut pass_buffer).await {
            Ok(0) => {
                // Client sends no data
                info!(
                    "[SERVER] Client disconnected while was on autentication: {}",
                    self.address.to_string()
                );
                // Unregister client from state
                self.state.remove_session(self.uuid).await;
                self.state.decrease_clients_count().await;
                info!(
                    "[SERVER] Client disconnected on: {}",
                    self.address.to_string()
                );
                info!(
                    "[SYSTEM] Total clients connected: {}",
                    self.state.get_clients_count().await
                );
                return;
            }
            Ok(n) => {
                let pass_introduced = Zeroizing::new(
                    String::from_utf8_lossy(&pass_buffer[..n])
                        .trim()
                        .to_string(),
                );
                if Self::verify_password(&pass_introduced, self.state.server_password_hash()) {
                    drop(pass_introduced);
                    if let Err(e) = self
                        .socket
                        .write_all(b"\n [*] Logged successfully!\n")
                        .await
                    {
                        error!("[ERROR] Cannot send data to client: {}", e);
                    }
                } else {
                    if let Err(e) = self.socket.write_all(b"Access denied.\n").await {
                        error!("[ERROR] Cannot send data to client: {}", e);
                    }
                    error!(
                        "[ERROR] Client [{}] failed on login.",
                        self.address.to_string()
                    );
                    // Register bad login attempt
                    self.security.register_log_att(self.address).await;
                    // Unregister client from state
                    self.state.remove_session(self.uuid).await;
                    self.state.decrease_clients_count().await;
                    return;
                }
            }
            Err(e) => {
                error!("[ERROR] Cannot read data from client: {}", e);
            }
        }
        // - - - TIMEOUT IMPLEMENTATION - - - //
        let (tx_reset, mut rx_reset) = watch::channel(()); // Channel to reset the counter
        let (tx_close, mut rx_close) = oneshot::channel::<()>();
        let uuid = self.uuid;
        let state_for_timeout = self.state.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = rx_reset.changed() => {}
                    _ = sleep(Duration::from_secs(120)) => {
                        tracing::warn!("[TIMEOUT] Client [{}] disconnected due inactivity.\n", uuid);
                        state_for_timeout.remove_session(uuid).await;
                        state_for_timeout.decrease_clients_count().await;
                        let _ = tx_close.send(());
                        return;
                    }
                }
            }
        });
        // Show available files
        let available_files = format!("\n{}\n", self.file_manager.list_files_formatted());
        let _ = self.socket.write_all(available_files.as_bytes()).await;
        let _ = self
            .socket
            .write_all(b"  =================================================================\n\n")
            .await;
        let _ = self.socket.write_all(b" [*] > ").await;
        // Main loop which reads data from client
        let mut buffer = [0; 512];
        loop {
            tokio::select! {
                _ = &mut rx_close => {
                    let _ = self.socket.shutdown().await;
                    return;
                }
                res = self.socket.read(&mut buffer) => {
                    match res {
                        Ok(0) => {
                            // Client sends no data
                            info!(
                                "[SERVER] Client disconnected while was on autentication: {}",
                                self.address.to_string()
                            );
                            // Unregister client from state
                            self.state.remove_session(self.uuid).await;
                            self.state.decrease_clients_count().await;
                            info!(
                                "[SERVER] Client disconnected on: {}",
                                self.address.to_string()
                            );
                            info!(
                                "[SYSTEM] Total clients connected: {}",
                                self.state.get_clients_count().await
                            );
                            return;
                        }
                        Ok(n) => {
                            // Restart timeout task
                            let _ = tx_reset.send(());
                            // Receive data from client
                            let data = String::from_utf8_lossy(&buffer[..n]).trim().to_string();
                            if !self.parse_command(&data).await {
                                info!("[CLIENT {}] Session ended by command.", self.uuid);
                                let _ = self.socket.shutdown().await;
                                return;
                            }
                        }
                        Err(e) => {
                            error!("[ERROR] Cannot read data from client: {}", e);
                            return;
                        }
                    }
                }
            }
        }
    }
    pub async fn parse_command(&mut self, input: &str) -> bool {
        let mut parts = input.split_whitespace();
        let cmd_name = parts.next().unwrap_or("");
        match cmd_name {
            "DOWNLOAD" => {
                if let Some(filename_arg) = parts.next() {
                    if !self.file_manager.file_exists(filename_arg) {
                        if let Err(e) = self.socket.write_all(b" [SERVER] File not found\n").await {
                            error!("[ERROR] Cannot send data to client: {}\n", e);
                        }
                        return true;
                    }
                    let uuid = Uuid::new_v4();
                    let expiration = SystemTime::now() + Duration::from_secs(300);
                    let token =
                        DownloadToken::new(uuid, filename_arg.to_string(), expiration, false);
                    self.token_store.insert(token.clone()).await;
                    // Generate URL
                    let url = format!(
                        "https://{}:{}/download/{}",
                        self.state.server_host.to_string(),
                        self.state.http_server_port,
                        uuid
                    );
                    let msg = format!(" [TOKEN] {}\n", url);
                    if let Err(e) = self.socket.write_all(msg.as_bytes()).await {
                        error!("[ERROR] Cannot send data to client: {}\n", e);
                    }
                } else {
                    let _ = self
                        .socket
                        .write_all(b" [ERROR] 'DOWNLOAD' command needs an argument.\n")
                        .await;
                }
                let _ = self.socket.write_all(b" [*] > ").await;
            }
            "UPLOAD" => {
                if let Some(filename) = parts.next() {
                    if let Some(filesize) = parts.next() {
                        let size_bytes: u64 = match filesize.parse() {
                            Ok(v) => v,
                            Err(_) => {
                                let _ = self
                                    .socket
                                    .write_all(b" [ERROR] Invalid file size.\n")
                                    .await;
                                return true;
                            }
                        };

                        let max_allowed = self.state.max_file_size();
                        if size_bytes > max_allowed {
                            let msg = format!(
                                " [ERROR] File too large ({} bytes). Max allowed: {} bytes.\n",
                                size_bytes, max_allowed
                            );
                            let _ = self.socket.write_all(msg.as_bytes()).await;
                            return false;
                        }

                        let mut file = self.file_manager.create_file(filename).unwrap();
                        let mut remaining = size_bytes;

                        let mut readed: u64 = 0;

                        // - - - TASK FOR LOW LATENCY UPLOAD - - - //
                        let bytes_received = std::sync::Arc::new(tokio::sync::Mutex::new(0 as u64));
                        let byt_rec_clone = bytes_received.clone();
                        let stop = std::sync::Arc::new(tokio::sync::Mutex::new(false));
                        let cloned_stop = stop.clone();
                        tokio::spawn(async move {
                            const MIN_BYTES: u64 = 20_000_000; // 20 MB
                            const GRACE_PERIOD: Duration = Duration::from_secs(30);
                            const SLEEP_LONG: Duration = Duration::from_secs(150);
                            tokio::time::sleep(GRACE_PERIOD).await;
                            let mut last_bytes: u64 = *byt_rec_clone.lock().await;
                            loop {
                                tokio::time::sleep(SLEEP_LONG).await;
                                let current_bytes = *byt_rec_clone.lock().await;
                                let diff = current_bytes - last_bytes;
                                if diff < MIN_BYTES {
                                    let mut stop_lock = cloned_stop.lock().await;
                                    *stop_lock = true;
                                    tracing::info!(
                                        "[SERVER] Upload stopped due to low transfer rate."
                                    );
                                    break;
                                }
                                last_bytes = current_bytes;
                            }
                        });
                        //
                        let mut buf = [0u8; 4096]; // 4KB
                        while remaining > 0 {
                            let to_read = buf.len().min(remaining as usize);
                            match self.socket.read(&mut buf[..to_read]).await {
                                Ok(0) => {
                                    tracing::error!("[ERROR] Client disconnected during upload.");
                                    return true;
                                }
                                Ok(n) => {
                                    crate::server::files::FileManager::append_chunk(
                                        &mut file,
                                        &buf[..n],
                                    )
                                    .unwrap();
                                    readed += n as u64;
                                    remaining -= n as u64;
                                    let mut lock_byt_rec = bytes_received.lock().await;
                                    *lock_byt_rec += n as u64;
                                    if *stop.lock().await {
                                        tracing::info!(
                                            "[SERVER] Stopping upload from {} for low latency...",
                                            self.uuid
                                        );
                                        let path = format!("files/{}", filename);
                                        if let Err(e) = tokio::fs::remove_file(path).await {
                                            tracing::error!(
                                                "[ERROR] An error ocurred while deleting corrupted file from server: {}",
                                                e
                                            );
                                        } else {
                                            tracing::info!(
                                                "[SERVER] Corrupt file removed successfully from server."
                                            );
                                        }
                                        return true;
                                    }
                                }
                                Err(e) => {
                                    tracing::error!(
                                        "[ERROR] An error ocurred while handling an upload: {}",
                                        e
                                    );
                                    let path = format!("files/{}", filename);
                                    if let Err(e) = tokio::fs::remove_file(path).await {
                                        tracing::error!(
                                            "[ERROR] An error ocurred while deleting corrupted file from server: {}",
                                            e
                                        );
                                    } else {
                                        tracing::info!(
                                            "[SERVER] Corrupt file removed successfully from server."
                                        );
                                    }
                                    return true;
                                }
                            }
                        }
                        if readed != size_bytes {
                            tracing::error!(
                                "[ERROR] Server couldn't read file completely, removing..."
                            );
                            let path = format!("files/{}", filename);
                            if let Err(e) = tokio::fs::remove_file(path).await {
                                tracing::error!(
                                    "[ERROR] An error ocurred while deleting corrupted file from server: {}",
                                    e
                                );
                            } else {
                                tracing::info!(
                                    "[SERVER] Corrupt file removed successfully from server."
                                );
                            }
                        }
                        file.flush().unwrap();
                        self.socket
                            .write_all(b" [SERVER] Upload completed.\n")
                            .await
                            .unwrap();
                        let _ = self.socket.write_all(b" [*] > ").await;
                    } else {
                        let _ = self
                            .socket
                            .write_all(b"[ERROR] Expected filesize argument.\n")
                            .await;
                        let _ = self.socket.write_all(b" [*] > ").await;
                    }
                } else {
                    let _ = self
                        .socket
                        .write_all(b" [ERROR] Expected filename argument.\n")
                        .await;
                    let _ = self.socket.write_all(b" [*] > ").await;
                }
            }
            "LIST" => {
                let files = self.file_manager.list_files_formatted();
                let _ = self.socket.write_all(files.as_bytes()).await;
                let _ = self.socket.write_all(b"\n").await;
                let _ = self.socket.write_all(b" [*] > ").await;
            }
            _ => {
                let _ = self.socket.write_all(b" [ERROR] Unknown command.\n").await;
                let _ = self.socket.write_all(b" [*] > ").await;
            }
        }
        true
    }
    fn verify_password(input_password: &str, stored_hash: &str) -> bool {
        let clean_pw = input_password.trim_matches(|c| c == '\r' || c == '\n' || c == ' ');
        if let Ok(parsed_hash) = PasswordHash::new(stored_hash) {
            Argon2::default()
                .verify_password(clean_pw.as_bytes(), &parsed_hash)
                .is_ok()
        } else {
            false
        }
    }
}
