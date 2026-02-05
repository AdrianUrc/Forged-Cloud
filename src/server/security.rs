use std::sync::Arc;

use tokio::sync::Mutex;

const MAX_LOGIN_ATTEMPTS: u32 = 3;

pub struct Security {
    banned_ips: Arc<Mutex<Vec<core::net::Ipv4Addr>>>,
    login_attempts: Arc<Mutex<Vec<(core::net::Ipv4Addr, u32)>>>,
}

impl Security {
    pub fn new() -> Self {
        Self {
            banned_ips: Arc::new(Mutex::new(Vec::new())),
            login_attempts: Arc::new(Mutex::new(Vec::new())),
        }
    }
    // Ban functions
    pub async fn ban_ip(&self, ip: core::net::Ipv4Addr) {
        let mut locked_banned_ips = self.banned_ips.lock().await;
        if !locked_banned_ips.contains(&ip) {
            locked_banned_ips.push(ip);
            tracing::info!("[SECURITY] IP: {} was banned from server.", ip);
        } else {
            tracing::warn!("[WARNING] IP: {} is already banned.", ip);
        }
    }

    pub async fn is_banned(&self, ip: core::net::Ipv4Addr) -> bool {
        let locked_banned_ips = self.banned_ips.lock().await;
        for (_i, ip_addr) in locked_banned_ips.iter().enumerate() {
            if *ip_addr == ip {
                return true;
            }
        }
        return false;
    }

    pub async fn register_log_att(&self, ip: core::net::Ipv4Addr) {
        let mut should_ban = false;

        {
            let mut attempts = self.login_attempts.lock().await;
            if let Some((_, count)) = attempts.iter_mut().find(|(addr, _)| *addr == ip) {
                *count += 1;
                tracing::info!("[SECURITY] IP {} tried {} logins.", ip, *count);
                should_ban = *count >= MAX_LOGIN_ATTEMPTS;
            } else {
                attempts.push((ip, 1));
                tracing::info!("[SECURITY] New login attempt registered from {}", ip);
            }
        }

        if should_ban {
            self.ban_ip(ip).await;
            let mut attempts = self.login_attempts.lock().await;
            attempts.retain(|(addr, _)| *addr != ip);
            tracing::info!("[SECURITY] Cleared login attempts for banned IP {}", ip);
        }
    }
}
