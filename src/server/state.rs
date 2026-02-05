use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;
use zeroize::Zeroizing;

pub struct State {
    clients_count: Arc<Mutex<u16>>,
    sessions: Arc<Mutex<Vec<Uuid>>>,
    server_password_hash: Zeroizing<String>,
    pub server_host: String,
    pub http_server_port: u16,
    max_file_size: u64,
    max_connections: u16,
}

impl State {
    pub fn new(
        server_password_hash: Zeroizing<String>,
        server_host: String,
        http_server_port: u16,
        max_file_size: u64,
        max_connections: u16,
    ) -> Self {
        Self {
            clients_count: Arc::new(Mutex::new(0)),
            sessions: Arc::new(Mutex::new(Vec::new())),
            server_password_hash,
            server_host,
            http_server_port,
            max_file_size,
            max_connections,
        }
    }
    // Self -> max_connections
    pub fn max_connections(&self) -> u16 {
        self.max_connections
    }
    // Self -> max_file_size
    pub fn max_file_size(&self) -> u64 {
        self.max_file_size
    }
    // Self -> server_password_hash
    pub fn server_password_hash(&self) -> &str {
        &self.server_password_hash
    }
    // Self -> clients_count functions()
    pub async fn increase_clients_count(&self) {
        let mut locked_clients_count = self.clients_count.lock().await;
        *locked_clients_count += 1;
    }
    pub async fn decrease_clients_count(&self) {
        let mut locked_clients_count = self.clients_count.lock().await;
        if *locked_clients_count > 0 {
            *locked_clients_count -= 1;
        } else {
            tracing::warn!(
                "[WARNING] State's clients counter tried to decrease counter while it was 0!"
            );
        }
    }
    pub async fn get_clients_count(&self) -> u16 {
        let locked_clients_count = self.clients_count.lock().await;
        *locked_clients_count
    }
    // Self -> sessions functions()
    pub async fn add_session(&self, client_uuid: Uuid) {
        let mut locked_sessions = self.sessions.lock().await;
        locked_sessions.push(client_uuid);
    }
    pub async fn remove_session(&self, client_uuid: Uuid) {
        let mut locked_sessions = self.sessions.lock().await;
        let mut index_to_rm: Option<usize> = None;

        for (i, client) in locked_sessions.iter().enumerate() {
            if *client == client_uuid {
                index_to_rm = Some(i);
                break;
            }
        }
        if let Some(index) = index_to_rm {
            locked_sessions.remove(index);
        } else {
            tracing::warn!("[WARNING] Client not found: {}", client_uuid);
        }
    }
}
