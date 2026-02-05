use std::time::SystemTime;
use uuid::Uuid;

#[derive(Clone)]
pub struct DownloadToken {
    uuid: Uuid,
    filename: String,
    expiration: SystemTime,
    consumed: bool,
}

impl DownloadToken {
    pub fn new(uuid: Uuid, filename: String, expiration: SystemTime, consumed: bool) -> Self {
        Self {
            uuid,
            filename,
            expiration,
            consumed,
        }
    }
    pub fn is_expired(&self) -> bool {
        SystemTime::now() > self.expiration
    }
    pub fn is_consumed(&self) -> bool {
        self.consumed
    }
    pub fn uuid(&self) -> Uuid {
        self.uuid
    }
    pub fn filename(&self) -> &str {
        &self.filename
    }
    pub fn expiration(&self) -> SystemTime {
        self.expiration
    }
    pub fn consume(&mut self) {
        self.consumed = true;
    }
}
