use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::server::download_token::DownloadToken;

pub struct TokenStore {
    tokens: Arc<RwLock<Vec<DownloadToken>>>,
}

impl TokenStore {
    pub fn new() -> Self {
        Self {
            tokens: Arc::new(RwLock::new(Vec::new())),
        }
    }
    pub async fn insert(&self, token: DownloadToken) {
        self.tokens.write().await.push(token);
    }
    // Makes a download token as consumed and returns it
    pub async fn consume(&self, uuid: Uuid) -> Option<DownloadToken> {
        let mut tokens = self.tokens.write().await;

        if let Some(token) = tokens.iter_mut().find(|t| t.uuid() == uuid) {
            if token.is_expired() || token.is_consumed() {
                return None;
            }

            token.consume();
            return Some(token.clone());
        }
        None
    }
    // Clean expired and consumed tokens
    pub async fn cleanup(&self) {
        let mut tokens = self.tokens.write().await;
        tokens.retain(|t| !t.is_expired() && !t.is_consumed());
    }
}
