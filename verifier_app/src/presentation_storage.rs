use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredPresentation {
    pub id: String,
    pub presentation: serde_json::Value,
    pub signature: String,
    pub verkey: String,
    pub created_at: u64,
    pub expires_at: u64,
}

#[derive(Clone)]
pub struct PresentationStorage {
    presentations: Arc<Mutex<HashMap<String, StoredPresentation>>>,
}

impl PresentationStorage {
    pub fn new() -> Self {
        Self {
            presentations: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Store a presentation and return its ID
    pub fn store(
        &self,
        presentation: serde_json::Value,
        signature: String,
        verkey: String,
        ttl_seconds: u64,
    ) -> String {
        let id = uuid::Uuid::new_v4().to_string();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let stored = StoredPresentation {
            id: id.clone(),
            presentation,
            signature,
            verkey,
            created_at: now,
            expires_at: now + ttl_seconds,
        };

        let mut presentations = self.presentations.lock().unwrap();
        presentations.insert(id.clone(), stored);

        // Clean up expired presentations
        self.cleanup_expired(&mut presentations, now);

        id
    }

    /// Retrieve a presentation by ID
    pub fn get(&self, id: &str) -> Option<StoredPresentation> {
        let mut presentations = self.presentations.lock().unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Clean up expired presentations
        self.cleanup_expired(&mut presentations, now);

        // Check if presentation exists and is not expired
        presentations.get(id).and_then(|p| {
            if p.expires_at > now {
                Some(p.clone())
            } else {
                None
            }
        })
    }

    /// Clean up expired presentations
    fn cleanup_expired(&self, presentations: &mut HashMap<String, StoredPresentation>, now: u64) {
        presentations.retain(|_, p| p.expires_at > now);
    }

    /// Get presentation count (for debugging)
    pub fn count(&self) -> usize {
        self.presentations.lock().unwrap().len()
    }

    /// Store a verified proof record for UI display
    pub fn store_proof_record(
        &self,
        record: serde_json::Value,
        ttl_seconds: u64,
    ) -> String {
        let id = record
            .get("pres_ex_id")
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| "unknown")
            .to_string();
        
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let stored = StoredPresentation {
            id: id.clone(),
            presentation: record,
            signature: String::new(), // Not needed for proof records
            verkey: String::new(), // Not needed for proof records
            created_at: now,
            expires_at: now + ttl_seconds,
        };

        let mut presentations = self.presentations.lock().unwrap();
        presentations.insert(id.clone(), stored);

        // Clean up expired presentations
        self.cleanup_expired(&mut presentations, now);

        id
    }

    /// Get all active (non-expired) proof records
    pub fn list_all(&self) -> Vec<serde_json::Value> {
        let mut presentations = self.presentations.lock().unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Clean up expired presentations
        self.cleanup_expired(&mut presentations, now);

        // Return all non-expired presentations
        presentations
            .values()
            .filter(|p| p.expires_at > now)
            .map(|p| p.presentation.clone())
            .collect()
    }
}
