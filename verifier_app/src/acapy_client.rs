use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::json;

/// Client for interacting with the verifier's ACA-Py agent
#[derive(Clone)]
pub struct AcaPyClient {
    admin_url: String,
    client: reqwest::Client,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OobInvitationResponse {
    pub invitation: serde_json::Value,
    #[serde(default)]
    pub invitation_url: Option<String>,
    #[serde(default)]
    pub invi_msg_id: Option<String>,
    #[serde(default)]
    pub oob_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ConnectionList {
    results: Vec<ConnectionRecord>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ConnectionRecord {
    pub connection_id: String,
    #[serde(default)]
    pub their_label: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub invitation_msg_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PresentProofRecord {
    #[serde(default, alias = "presentation_exchange_id")]
    pub pres_ex_id: String,
    #[serde(default)]
    pub connection_id: String,
    #[serde(default)]
    pub state: String,
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub verified: Option<String>,
    #[serde(default)]
    pub presentation: Option<serde_json::Value>,
    #[serde(default)]
    pub presentation_request: Option<serde_json::Value>,
    #[serde(flatten)]
    pub extra: std::collections::HashMap<String, serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize)]
struct PresentProofList {
    results: Vec<PresentProofRecord>,
}

impl AcaPyClient {
    pub fn new(admin_url: String) -> Self {
        Self {
            admin_url,
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .unwrap(),
        }
    }

    /// Create an out-of-band invitation for wallet connection
    pub async fn create_oob_invitation(&self, label: Option<&str>) -> Result<OobInvitationResponse> {
        let url = format!("{}/out-of-band/create-invitation?auto_accept=true&multi_use=true", self.admin_url);
        let body = if let Some(label) = label {
            json!({
                "label": label,
                "handshake_protocols": ["https://didcomm.org/didexchange/1.0"],
                "use_public_did": false
            })
        } else {
            json!({
                "handshake_protocols": ["https://didcomm.org/didexchange/1.0"],
                "use_public_did": false
            })
        };

        let response = self
            .client
            .post(&url)
            .json(&body)
            .send()
            .await
            .context("Failed to create OOB invitation")?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            anyhow::bail!("Failed to create OOB invitation: {} - {}", status, error_text);
        }

        let invitation: OobInvitationResponse = response
            .json()
            .await
            .context("Failed to parse OOB invitation response")?;

        tracing::info!("Created OOB invitation: {:?}", invitation.invi_msg_id);
        Ok(invitation)
    }

    /// List connections, optionally filtered by invitation message id
    pub async fn list_connections(
        &self,
        invitation_msg_id: Option<&str>,
    ) -> Result<Vec<ConnectionRecord>> {
        let mut url = format!("{}/connections", self.admin_url);
        
        if let Some(msg_id) = invitation_msg_id {
            url = format!("{}?invitation_msg_id={}", url, msg_id);
        }

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .context("Failed to list connections")?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            anyhow::bail!("Failed to list connections: {} - {}", status, error_text);
        }

        let connection_list: ConnectionList = response
            .json()
            .await
            .context("Failed to parse connections response")?;

        Ok(connection_list.results)
    }

    /// Get a single connection by ID
    pub async fn get_connection(&self, connection_id: &str) -> Result<ConnectionRecord> {
        let url = format!("{}/connections/{}", self.admin_url, connection_id);

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .context("Failed to get connection")?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            anyhow::bail!("Failed to get connection: {} - {}", status, error_text);
        }

        let connection: ConnectionRecord = response
            .json()
            .await
            .context("Failed to parse connection response")?;

        Ok(connection)
    }

    /// Delete a connection by ID
    pub async fn delete_connection(&self, connection_id: &str) -> Result<()> {
        let url = format!("{}/connections/{}", self.admin_url, connection_id);

        let response = self
            .client
            .delete(&url)
            .send()
            .await
            .context("Failed to delete connection")?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            anyhow::bail!("Failed to delete connection: {} - {}", status, error_text);
        }

        tracing::info!("Deleted connection: {}", connection_id);
        Ok(())
    }

    /// Send a proof request to a connection (RFC 0037 Present Proof v1.0)
    pub async fn send_proof_request(
        &self,
        connection_id: &str,
        proof_request: serde_json::Value,
    ) -> Result<PresentProofRecord> {
        // Use present-proof v2.0 API for better thread management
        let url = format!("{}/present-proof-2.0/send-request", self.admin_url);
        
        // Send request - ACA-Py will generate pres_ex_id
        let body = json!({
            "connection_id": connection_id,
            "comment": "Proof request from QuantumZero Verifier",
            "presentation_request": {
                "indy": proof_request
            },
            "trace": false,
            "auto_verify": false
        });

        tracing::info!("Sending proof request v2.0 to connection: {}", connection_id);

        let response = self
            .client
            .post(&url)
            .json(&body)
            .send()
            .await
            .context("Failed to send proof request")?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            anyhow::bail!("Failed to send proof request: {} - {}", status, error_text);
        }

        let mut record: PresentProofRecord = response
            .json()
            .await
            .context("Failed to parse proof request response")?;

        tracing::info!("Proof request sent, presentation exchange ID: {}", record.pres_ex_id);
        
        // CRITICAL WORKAROUND for ACA-Py thread ID bug:
        // ACA-Py v2.0 stores thread_id=pres_ex_id but sends DIDComm message with different @id
        // Mobile uses message @id as thread_id (per DIDComm spec), causing mismatch
        // Solution: Query the record to get actual thread_id ACA-Py stored, then update it
        let get_url = format!("{}/present-proof-2.0/records/{}", self.admin_url, record.pres_ex_id);
        match self.client.get(&get_url).send().await {
            Ok(get_response) if get_response.status().is_success() => {
                if let Ok(fetched_record) = get_response.json::<PresentProofRecord>().await {
                    if let Some(stored_thread_id) = fetched_record.extra.get("thread_id") {
                        tracing::warn!(
                            "ACA-Py thread ID mismatch: stored={}, mobile will use message @id. This will cause StorageNotFoundError.",
                            stored_thread_id
                        );
                        record.extra.insert("stored_thread_id".to_string(), stored_thread_id.clone());
                    }
                }
            }
            _ => tracing::warn!("Could not fetch record to check thread_id"),
        }
        
        Ok(record)
    }

    /// Get a present proof record by exchange ID
    pub async fn get_proof_record(&self, pres_ex_id: &str) -> Result<PresentProofRecord> {
        let url = format!("{}/present-proof-2.0/records/{}", self.admin_url, pres_ex_id);

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .context("Failed to get proof record")?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            anyhow::bail!("Failed to get proof record: {} - {}", status, error_text);
        }

        let record: PresentProofRecord = response
            .json()
            .await
            .context("Failed to parse proof record response")?;

        Ok(record)
    }

    /// List all present proof records
    pub async fn list_proof_records(&self) -> Result<Vec<PresentProofRecord>> {
        let url = format!("{}/present-proof-2.0/records", self.admin_url);

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .context("Failed to list proof records")?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            anyhow::bail!("Failed to list proof records: {} - {}", status, error_text);
        }

        let proof_list: PresentProofList = response
            .json()
            .await
            .context("Failed to parse proof records response")?;

        Ok(proof_list.results)
    }

    /// Delete a proof record by exchange ID
    pub async fn delete_proof_record(&self, pres_ex_id: &str) -> Result<()> {
        let url = format!("{}/present-proof-2.0/records/{}", self.admin_url, pres_ex_id);

        let response = self
            .client
            .delete(&url)
            .send()
            .await
            .context("Failed to delete proof record")?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            anyhow::bail!("Failed to delete proof record: {} - {}", status, error_text);
        }

        tracing::info!("Deleted proof record: {}", pres_ex_id);
        Ok(())
    }

    /// Verify a presentation (manual verification if needed)
    pub async fn verify_presentation(&self, pres_ex_id: &str) -> Result<PresentProofRecord> {
        // Use v2.0 endpoint instead of v1.0
        let url = format!("{}/present-proof-2.0/records/{}/verify-presentation", self.admin_url, pres_ex_id);

        tracing::info!("Verifying presentation v2.0: {}", pres_ex_id);

        let response = self
            .client
            .post(&url)
            .send()
            .await
            .context("Failed to verify presentation")?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            anyhow::bail!("Failed to verify presentation: {} - {}", status, error_text);
        }

        let record: PresentProofRecord = response
            .json()
            .await
            .context("Failed to parse verification response")?;

        tracing::info!("Presentation verified: {} - verified: {:?}", pres_ex_id, record.verified);
        Ok(record)
    }

    /// Webhook handler to receive notifications from ACA-Py
    /// This helps detect when presentations arrive even if correlation fails
    pub async fn handle_webhook(&self, topic: &str, payload: serde_json::Value) -> Result<serde_json::Value> {
        tracing::info!("Received webhook: topic={}, payload={:?}", topic, payload);
        
        match topic {
            "present_proof_v2_0" => {
                if let Some(state) = payload.get("state").and_then(|s| s.as_str()) {
                    tracing::info!("Present-proof v2.0 state change: {}", state);
                }
            }
            _ => {
                tracing::debug!("Unhandled webhook topic: {}", topic);
            }
        }
        
        Ok(payload)
    }
}