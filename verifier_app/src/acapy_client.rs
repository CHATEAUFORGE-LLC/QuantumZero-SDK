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
        let url = format!("{}/out-of-band/create-invitation?auto_accept=true", self.admin_url);
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
        let url = format!("{}/present-proof/send-request", self.admin_url);
        
        let body = json!({
            "connection_id": connection_id,
            "proof_request": proof_request,
            "trace": false,
            "comment": "Proof request from QuantumZero Verifier"
        });

        tracing::info!("Sending proof request to connection: {}", connection_id);

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

        let record: PresentProofRecord = response
            .json()
            .await
            .context("Failed to parse proof request response")?;

        tracing::info!("Proof request sent, presentation exchange ID: {}", record.pres_ex_id);
        Ok(record)
    }

    /// Get a present proof record by exchange ID
    pub async fn get_proof_record(&self, pres_ex_id: &str) -> Result<PresentProofRecord> {
        let url = format!("{}/present-proof/records/{}", self.admin_url, pres_ex_id);

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
        let url = format!("{}/present-proof/records", self.admin_url);

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

    /// Verify a presentation (manual verification if needed)
    pub async fn verify_presentation(&self, pres_ex_id: &str) -> Result<PresentProofRecord> {
        let url = format!("{}/present-proof/records/{}/verify-presentation", self.admin_url, pres_ex_id);

        tracing::info!("Verifying presentation: {}", pres_ex_id);

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
}
