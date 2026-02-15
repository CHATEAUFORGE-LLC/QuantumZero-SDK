use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::time::Duration;

/// Client for interacting with the issuer's own ACA-Py agent
#[derive(Clone)]
pub struct AcaPyClient {
    admin_url: String,
    client: reqwest::Client,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateDidResponse {
    pub result: DidResult,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DidResult {
    pub did: String,
    pub verkey: String,
    #[serde(default)]
    pub posture: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SchemaResponse {
    pub schema_id: String,
    pub schema: SchemaDetail,
    #[serde(default)]
    pub signed_transaction: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SchemaDetail {
    pub id: String,
    pub name: String,
    pub version: String,
    #[serde(rename = "attrNames")]
    pub attr_names: Vec<String>,
    #[serde(rename = "seqNo")]
    pub seq_no: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CredDefResponse {
    pub credential_definition_id: String,
    pub credential_definition: CredDefDetail,
    #[serde(default)]
    pub signed_transaction: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CredDefDetail {
    pub id: String,
    pub tag: String,
    #[serde(rename = "type")]
    pub cred_def_type: String,
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
    pub connection_protocol: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CredentialOfferResponse {
    #[serde(default)]
    pub cred_ex_id: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub role: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CredentialAttribute {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CredentialExchangeRecord {
    #[serde(default)]
    pub cred_ex_id: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub cred_ex_record: Option<serde_json::Value>,
    #[serde(default)]
    pub indy: Option<IndyCredentialDetail>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IndyCredentialDetail {
    #[serde(default)]
    pub schema_id: Option<String>,
    #[serde(default)]
    pub cred_def_id: Option<String>,
    #[serde(default)]
    pub rev_reg_id: Option<String>,
    #[serde(default)]
    pub cred_rev_id: Option<String>,
    #[serde(default)]
    pub values: Option<serde_json::Value>,
    #[serde(default)]
    pub signature: Option<serde_json::Value>,
    #[serde(default)]
    pub signature_correctness_proof: Option<serde_json::Value>,
    #[serde(default)]
    pub witness: Option<serde_json::Value>,
}

impl AcaPyClient {
    pub fn new(admin_url: String) -> Self {
        Self {
            admin_url,
            client: reqwest::Client::new(),
        }
    }

    /// Delete a connection by connection_id
    pub async fn delete_connection(&self, connection_id: &str) -> Result<()> {
        let url = format!("{}/connections/{}", self.admin_url, connection_id);
        
        let response = self
            .client
            .delete(&url)
            .timeout(Duration::from_secs(10))
            .send()
            .await
            .context("Failed to delete connection")?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            tracing::warn!("Failed to delete connection {}: {} - {}", connection_id, status, error_text);
        } else {
            tracing::info!("Deleted connection: {}", connection_id);
        }

        Ok(())
    }

    /// Clean up old peer-to-peer (didexchange) connections to prevent duplicate connection errors
    /// Only deletes didexchange protocol connections (mobile wallets)
    /// Preserves: endorser, trustee, ledger, and server connections
    pub async fn cleanup_old_connections(&self) -> Result<usize> {
        tracing::info!("Cleaning up old peer-to-peer (didexchange) connections");
        
        let connections = match self.list_connections(None).await {
            Ok(conns) => conns,
            Err(e) => {
                tracing::warn!("Failed to list connections for cleanup: {}", e);
                return Ok(0);
            }
        };
        
        let mut deleted_count = 0;
        
        for conn in connections {
            // CRITICAL: Only delete connections using didexchange protocol (peer-to-peer mobile wallets)
            // This ensures we never touch endorser, trustee, ledger, or server connections
            let conn_protocol = conn.connection_protocol.as_deref().unwrap_or("");
            
            // Skip if NOT a didexchange connection
            if !conn_protocol.contains("didexchange") {
                tracing::debug!(
                    "Skipping non-didexchange connection: {} (protocol: {})",
                    conn.connection_id,
                    conn_protocol
                );
                continue;
            }
            
            // Double-check by label to be extra safe
            let their_label = conn.their_label.as_deref().unwrap_or("");
            if their_label.to_lowercase().contains("endorser") 
                || their_label.to_lowercase().contains("trustee")
                || their_label.to_lowercase().contains("ledger")
                || their_label.to_lowercase().contains("server") {
                tracing::info!(
                    "Skipping critical connection: {} (label: {})",
                    conn.connection_id,
                    their_label
                );
                continue;
            }
            
            // Safe to delete - it's a peer-to-peer mobile wallet connection
            tracing::info!(
                "Deleting didexchange connection: {} (label: {})",
                conn.connection_id,
                their_label
            );
            
            match self.delete_connection(&conn.connection_id).await {
                Ok(_) => deleted_count += 1,
                Err(e) => {
                    tracing::warn!("Failed to delete connection {}: {}", conn.connection_id, e);
                    // Continue with other connections even if one fails
                }
            }
        }
        
        if deleted_count > 0 {
            tracing::info!("Cleanup complete: deleted {} didexchange connections", deleted_count);
        } else {
            tracing::debug!("No didexchange connections to clean up");
        }
        
        Ok(deleted_count)
    }

    /// Create an out-of-band invitation for wallet connection
    /// Cleans up old peer-to-peer connections first to prevent duplicate connection errors
    pub async fn create_oob_invitation(&self, label: Option<&str>) -> Result<OobInvitationResponse> {
        // Clean up old didexchange connections to ensure only ONE peer-to-peer connection at a time
        // This prevents "Multiple ConnRecord" errors in ACA-Py when the same mobile wallet reconnects
        if let Err(e) = self.cleanup_old_connections().await {
            tracing::warn!("Connection cleanup failed (non-fatal): {}", e);
            // Continue anyway - cleanup failure shouldn't block invitation creation
        }
        
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
            .timeout(Duration::from_secs(10))
            .send()
            .await
            .context("Failed to create OOB invitation")?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            anyhow::bail!("Failed to create OOB invitation: {} - {}", status, error_text);
        }

        let result: OobInvitationResponse = response
            .json()
            .await
            .context("Failed to parse OOB invitation response")?;

        Ok(result)
    }

    /// Lookup connection by invitation message id
    pub async fn get_connection_by_invitation_id(
        &self,
        invitation_msg_id: &str,
    ) -> Result<Option<ConnectionRecord>> {
        let url = format!("{}/connections?invitation_msg_id={}", self.admin_url, invitation_msg_id);
        let response = self
            .client
            .get(&url)
            .send()
            .await
            .context("Failed to query ACA-Py connections")?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            anyhow::bail!("Failed to query connections: {} - {}", status, error_text);
        }

        let connections: ConnectionList = response
            .json()
            .await
            .context("Failed to parse connections response")?;

        Ok(connections.results.into_iter().next())
    }

    /// List connections, optionally filtered by invitation message id
    pub async fn list_connections(
        &self,
        invitation_msg_id: Option<&str>,
    ) -> Result<Vec<ConnectionRecord>> {
        let url = if let Some(invitation_msg_id) = invitation_msg_id {
            format!(
                "{}/connections?invitation_msg_id={}",
                self.admin_url, invitation_msg_id
            )
        } else {
            format!("{}/connections", self.admin_url)
        };

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .context("Failed to query ACA-Py connections")?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            anyhow::bail!("Failed to query connections: {} - {}", status, error_text);
        }

        let connections: ConnectionList = response
            .json()
            .await
            .context("Failed to parse connections response")?;

        Ok(connections.results)
    }

    /// Send a credential offer over an existing connection
    pub async fn send_credential_offer(
        &self,
        connection_id: &str,
        cred_def_id: &str,
        attributes: Vec<CredentialAttribute>,
    ) -> Result<CredentialOfferResponse> {
        let url = format!("{}/issue-credential-2.0/send-offer", self.admin_url);

        let body = json!({
            "connection_id": connection_id,
            "auto_issue": true,
            "auto_remove": true,
            "credential_preview": {
                "@type": "issue-credential/2.0/credential-preview",
                "attributes": attributes
            },
            "filter": {
                "indy": {
                    "cred_def_id": cred_def_id
                }
            }
        });

        let response = self
            .client
            .post(&url)
            .json(&body)
            .timeout(Duration::from_secs(30))
            .send()
            .await
            .context("Failed to send credential offer")?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            anyhow::bail!("Failed to send credential offer: {} - {}", status, error_text);
        }

        let result: CredentialOfferResponse = response
            .json()
            .await
            .context("Failed to parse credential offer response")?;

        Ok(result)
    }

    /// Get credential exchange record by ID to retrieve the actual issued credential
    pub async fn get_credential_exchange(&self, cred_ex_id: &str) -> Result<CredentialExchangeRecord> {
        let url = format!("{}/issue-credential-2.0/records/{}", self.admin_url, cred_ex_id);

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .context("Failed to get credential exchange record")?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            anyhow::bail!("Failed to get credential exchange: {} - {}", status, error_text);
        }

        let result: CredentialExchangeRecord = response
            .json()
            .await
            .context("Failed to parse credential exchange record")?;

        Ok(result)
    }

    /// Issue credential directly using holder's link secret (bypassing protocol)
    /// This generates the complete AnonCreds credential with cryptographic proof immediately
    pub async fn issue_credential_with_link_secret(
        &self,
        cred_def_id: &str,
        attributes: Vec<CredentialAttribute>,
        link_secret: &str,
    ) -> Result<serde_json::Value> {
        // Use ACA-Py's W3C VC issuance which generates complete AnonCreds credentials
        let url = format!("{}/issue-credential/create-offer", self.admin_url);

        // First get the schema_id for this cred_def
        let cred_def_url = format!("{}/credential-definitions/{}", self.admin_url, cred_def_id);
        let cred_def_response = self
            .client
            .get(&cred_def_url)
            .send()
            .await
            .context("Failed to get credential definition")?;
            
        let cred_def_json: serde_json::Value = cred_def_response
            .json()
            .await
            .context("Failed to parse credential definition")?;
            
        let schema_id = cred_def_json["credential_definition"]["schemaId"]
            .as_str()
            .unwrap_or("");

        // Create credential offer which contains the cryptographic material
        let body = json!({
            "cred_def_id": cred_def_id,
            "credential_preview": {
                "@type": "issue-credential/2.0/credential-preview",
                "attributes": attributes
            }
        });

        let response = self
            .client
            .post(&url)
            .json(&body)
            .send()
            .await
            .context("Failed to create credential offer")?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            anyhow::bail!("Failed to create credential offer: {} - {}", status, error_text);
        }

        let offer_result: serde_json::Value = response
            .json()
            .await
            .context("Failed to parse create offer response")?;

        Ok(offer_result)
    }

    /// Send a custom message over an existing connection
    pub async fn send_connection_message(
        &self,
        connection_id: &str,
        message: &serde_json::Value,
    ) -> Result<()> {
        let url = format!(
            "{}/connections/{}/send-message",
            self.admin_url, connection_id
        );

        let content = serde_json::to_string(message)
            .unwrap_or_else(|_| "{}".to_string());
        let body = serde_json::json!({
            "content": content
        });

        let response = self
            .client
            .post(&url)
            .json(&body)
            .send()
            .await
            .context("Failed to send connection message")?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            anyhow::bail!("Failed to send connection message: {} - {}", status, error_text);
        }

        Ok(())
    }

    async fn get_endorser_connection_id(&self) -> Result<String> {
        let url = format!("{}/connections?state=active", self.admin_url);
        let response = self.client
            .get(&url)
            .send()
            .await
            .context("Failed to query ACA-Py connections")?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            anyhow::bail!("Failed to query connections: {} - {}", status, error_text);
        }

        let connections: ConnectionList = response
            .json()
            .await
            .context("Failed to parse connections response")?;

        let endorser_label = "QuantumZero-Admin-Agent";
        connections
            .results
            .into_iter()
            .find(|rec| rec.their_label.as_deref() == Some(endorser_label))
            .map(|rec| rec.connection_id)
            .ok_or_else(|| anyhow::anyhow!(
                "No endorser connection found with label '{}'", endorser_label
            ))
    }

    /// Set endorser info for the active endorser connection
    pub async fn set_endorser_info(&self, endorser_did: &str, endorser_name: Option<&str>) -> Result<()> {
        let conn_id = self.get_endorser_connection_id().await?;
        let mut url = format!(
            "{}/transactions/{}/set-endorser-info?endorser_did={}",
            self.admin_url,
            conn_id,
            endorser_did
        );

        if let Some(name) = endorser_name {
            if !name.is_empty() {
                url = format!("{}&endorser_name={}", url, name);
            }
        }

        tracing::info!("Setting endorser info in ACA-Py: {}", endorser_did);

        let response = self.client
            .post(&url)
            .send()
            .await
            .context("Failed to set endorser info")?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            anyhow::bail!("Failed to set endorser info: {} - {}", status, error_text);
        }

        Ok(())
    }

    pub async fn set_endorser_info_on_connection(
        &self,
        conn_id: &str,
        endorser_did: &str,
        endorser_name: Option<&str>,
    ) -> Result<()> {
        let mut url = format!(
            "{}/transactions/{}/set-endorser-info?endorser_did={}",
            self.admin_url,
            conn_id,
            endorser_did
        );

        if let Some(name) = endorser_name {
            if !name.is_empty() {
                url = format!("{}&endorser_name={}", url, name);
            }
        }

        tracing::info!("Setting endorser info in ACA-Py: {}", endorser_did);

        let response = self.client
            .post(&url)
            .send()
            .await
            .context("Failed to set endorser info")?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            anyhow::bail!("Failed to set endorser info: {} - {}", status, error_text);
        }

        Ok(())
    }

    /// Create a new DID in the agent's wallet
    pub async fn create_did(&self) -> Result<DidResult> {
        let url = format!("{}/wallet/did/create", self.admin_url);
        
        tracing::info!("Creating DID in ACA-Py wallet");
        
        let response = self.client
            .post(&url)
            .json(&json!({}))
            .send()
            .await
            .context("Failed to create DID in ACA-Py")?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            anyhow::bail!("Failed to create DID: {} - {}", status, error_text);
        }

        let result: CreateDidResponse = response
            .json()
            .await
            .context("Failed to parse DID creation response")?;

        tracing::info!("Created DID in ACA-Py: {}", result.result.did);
        Ok(result.result)
    }

    /// Create a DID in the agent's wallet using a specific seed
    pub async fn create_did_with_seed(&self, seed: &str) -> Result<DidResult> {
        let url = format!("{}/wallet/did/create", self.admin_url);

        tracing::info!("Creating DID in ACA-Py wallet with provided seed");

        let response = self.client
            .post(&url)
            .json(&json!({
                "method": "sov",
                "seed": seed,
                "options": {
                    "key_type": "ed25519"
                }
            }))
            .send()
            .await
            .context("Failed to create DID in ACA-Py with seed")?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            anyhow::bail!("Failed to create DID with seed: {} - {}", status, error_text);
        }

        let result: CreateDidResponse = response
            .json()
            .await
            .context("Failed to parse seeded DID creation response")?;

        tracing::info!("Created DID in ACA-Py with seed: {}", result.result.did);
        Ok(result.result)
    }

    /// Set a DID as the public DID for this agent
    pub async fn set_public_did(&self, did: &str) -> Result<DidResult> {
        let conn_id = self.get_endorser_connection_id().await?;
        let normalized_did = did.strip_prefix("did:sov:").unwrap_or(did);
        let url = format!(
            "{}/wallet/did/public?did={}&create_transaction_for_endorser=true&conn_id={}",
            self.admin_url,
            normalized_did,
            conn_id
        );
        
        tracing::info!("Setting public DID in ACA-Py: {}", normalized_did);
        
        let response = self.client
            .post(&url)
            .send()
            .await
            .context("Failed to set public DID")?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            anyhow::bail!("Failed to set public DID: {} - {}", status, error_text);
        }

        let body: serde_json::Value = response
            .json()
            .await
            .context("Failed to parse set public DID response")?;

        if let Some(result) = body.get("result") {
            let parsed: DidResult = serde_json::from_value(result.clone())
                .context("Failed to parse set public DID result")?;
            tracing::info!("Set public DID: {} (posture: {:?})", parsed.did, parsed.posture);
            return Ok(parsed);
        }

        // When using endorser flow, ACA-Py returns a transaction record under "txn".
        tracing::info!("Set public DID queued for endorsement: {}", normalized_did);
        Ok(DidResult {
            did: normalized_did.to_string(),
            verkey: String::new(),
            posture: Some("transaction".to_string()),
        })
    }

    pub async fn set_public_did_with_connection(&self, did: &str, conn_id: &str) -> Result<DidResult> {
        let normalized_did = did.strip_prefix("did:sov:").unwrap_or(did);
        let url = format!(
            "{}/wallet/did/public?did={}&create_transaction_for_endorser=true&conn_id={}",
            self.admin_url,
            normalized_did,
            conn_id
        );

        tracing::info!("Setting public DID in ACA-Py: {}", normalized_did);

        let response = self.client
            .post(&url)
            .send()
            .await
            .context("Failed to set public DID")?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            anyhow::bail!("Failed to set public DID: {} - {}", status, error_text);
        }

        let body: serde_json::Value = response
            .json()
            .await
            .context("Failed to parse set public DID response")?;

        if let Some(result) = body.get("result") {
            let parsed: DidResult = serde_json::from_value(result.clone())
                .context("Failed to parse set public DID result")?;
            tracing::info!("Set public DID: {} (posture: {:?})", parsed.did, parsed.posture);
            return Ok(parsed);
        }

        tracing::info!("Set public DID queued for endorsement: {}", normalized_did);
        Ok(DidResult {
            did: normalized_did.to_string(),
            verkey: String::new(),
            posture: Some("transaction".to_string()),
        })
    }

    /// Create a schema on the ledger using this agent
    /// NOTE: The agent must have its public DID set and registered on the ledger first
    pub async fn create_schema(
        &self,
        name: &str,
        version: &str,
        attributes: &[String],
    ) -> Result<SchemaResponse> {
        let conn_id = self.get_endorser_connection_id().await?;
        let url = format!(
            "{}/schemas?create_transaction_for_endorser=true&conn_id={}",
            self.admin_url,
            conn_id
        );
        
        let payload = json!({
            "schema_name": name,
            "schema_version": version,
            "attributes": attributes
        });

        tracing::info!("Creating schema via ACA-Py: {}:{} with {} attributes", 
            name, version, attributes.len());
        
        let response = self.client
            .post(&url)
            .json(&payload)
            .send()
            .await
            .context("Failed to create schema via ACA-Py")?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            anyhow::bail!("Failed to create schema: {} - {}", status, error_text);
        }

        let body: serde_json::Value = response
            .json()
            .await
            .context("Failed to parse schema creation response")?;

        let parsed = if body.get("schema_id").is_some() {
            serde_json::from_value::<SchemaResponse>(body)
                .context("Failed to parse schema response")?
        } else if let Some(sent) = body.get("sent") {
            let schema_id = sent.get("schema_id").and_then(|v| v.as_str());
            let signed_txn = sent
                .get("schema")
                .and_then(|schema| schema.get("signed_txn"))
                .and_then(|v| v.as_str())
                .map(|value| value.to_string());

            SchemaResponse {
                schema_id: schema_id.unwrap_or_default().to_string(),
                schema: SchemaDetail {
                    id: schema_id.unwrap_or_default().to_string(),
                    name: name.to_string(),
                    version: version.to_string(),
                    attr_names: attributes.to_vec(),
                    seq_no: None,
                },
                signed_transaction: signed_txn,
            }
        } else {
            SchemaResponse {
                schema_id: String::new(),
                schema: SchemaDetail {
                    id: String::new(),
                    name: name.to_string(),
                    version: version.to_string(),
                    attr_names: attributes.to_vec(),
                    seq_no: None,
                },
                signed_transaction: None,
            }
        };

        tracing::info!("Schema request processed: schema_id={} seq_no={:?}", 
            parsed.schema_id, parsed.schema.seq_no);
        Ok(parsed)
    }

    pub async fn create_schema_with_connection(
        &self,
        name: &str,
        version: &str,
        attributes: &[String],
        conn_id: &str,
    ) -> Result<SchemaResponse> {
        let url = format!(
            "{}/schemas?create_transaction_for_endorser=true&conn_id={}",
            self.admin_url,
            conn_id
        );

        let payload = json!({
            "schema_name": name,
            "schema_version": version,
            "attributes": attributes
        });

        tracing::info!("Creating schema via ACA-Py: {}:{} with {} attributes", 
            name, version, attributes.len());

        let response = self.client
            .post(&url)
            .json(&payload)
            .send()
            .await
            .context("Failed to create schema via ACA-Py")?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            anyhow::bail!("Failed to create schema: {} - {}", status, error_text);
        }

        let body: serde_json::Value = response
            .json()
            .await
            .context("Failed to parse schema creation response")?;

        let parsed = if body.get("schema_id").is_some() {
            serde_json::from_value::<SchemaResponse>(body)
                .context("Failed to parse schema response")?
        } else if let Some(sent) = body.get("sent") {
            let schema_id = sent.get("schema_id").and_then(|v| v.as_str());
            let signed_txn = sent
                .get("schema")
                .and_then(|schema| schema.get("signed_txn"))
                .and_then(|v| v.as_str())
                .map(|value| value.to_string());

            SchemaResponse {
                schema_id: schema_id.unwrap_or_default().to_string(),
                schema: SchemaDetail {
                    id: schema_id.unwrap_or_default().to_string(),
                    name: name.to_string(),
                    version: version.to_string(),
                    attr_names: attributes.to_vec(),
                    seq_no: None,
                },
                signed_transaction: signed_txn,
            }
        } else {
            SchemaResponse {
                schema_id: String::new(),
                schema: SchemaDetail {
                    id: String::new(),
                    name: name.to_string(),
                    version: version.to_string(),
                    attr_names: attributes.to_vec(),
                    seq_no: None,
                },
                signed_transaction: None,
            }
        };

        tracing::info!("Schema request processed: schema_id={} seq_no={:?}", 
            parsed.schema_id, parsed.schema.seq_no);
        Ok(parsed)
    }

    /// Create a credential definition on the ledger using this agent
    pub async fn create_cred_def(
        &self,
        schema_id: &str,
        tag: &str,
        support_revocation: bool,
    ) -> Result<CredDefResponse> {
        let conn_id = self.get_endorser_connection_id().await?;
        let url = format!(
            "{}/credential-definitions?create_transaction_for_endorser=true&conn_id={}",
            self.admin_url,
            conn_id
        );
        
        let mut payload = json!({
            "schema_id": schema_id,
            "tag": tag,
            "support_revocation": support_revocation
        });

        if support_revocation {
            payload["revocation_registry_size"] = json!(1000);
        }

        tracing::info!("Creating cred-def via ACA-Py: schema={} tag={} revocation={}", 
            schema_id, tag, support_revocation);
        
        let response = self.client
            .post(&url)
            .json(&payload)
            .send()
            .await
            .context("Failed to create cred-def via ACA-Py")?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            anyhow::bail!("Failed to create cred-def: {} - {}", status, error_text);
        }

        let body: serde_json::Value = response
            .json()
            .await
            .context("Failed to parse cred-def creation response")?;

        let txn_signed = body
            .get("txn")
            .and_then(|txn| txn.get("messages_attach"))
            .and_then(|value| value.as_array())
            .and_then(|arr| arr.get(0))
            .and_then(|value| value.get("data"))
            .and_then(|value| value.get("json"))
            .and_then(|value| value.as_str())
            .map(|value| value.to_string());

        let parsed = if body.get("credential_definition_id").is_some() {
            let mut parsed: CredDefResponse = serde_json::from_value(body)
                .context("Failed to parse cred-def response")?;
            if parsed.signed_transaction.is_none() {
                parsed.signed_transaction = txn_signed;
            }
            parsed
        } else if let Some(sent) = body.get("sent") {
            let cred_def_id = sent
                .get("credential_definition_id")
                .or_else(|| sent.get("cred_def_id"))
                .and_then(|v| v.as_str());
            let signed_txn = sent
                .get("credential_definition")
                .or_else(|| sent.get("cred_def"))
                .and_then(|value| value.get("signed_txn"))
                .and_then(|v| v.as_str())
                .map(|value| value.to_string());

            CredDefResponse {
                credential_definition_id: cred_def_id.unwrap_or_default().to_string(),
                credential_definition: CredDefDetail {
                    id: cred_def_id.unwrap_or_default().to_string(),
                    tag: tag.to_string(),
                    cred_def_type: "CL".to_string(),
                },
                signed_transaction: signed_txn.or(txn_signed),
            }
        } else {
            CredDefResponse {
                credential_definition_id: String::new(),
                credential_definition: CredDefDetail {
                    id: String::new(),
                    tag: tag.to_string(),
                    cred_def_type: "CL".to_string(),
                },
                signed_transaction: txn_signed,
            }
        };

        tracing::info!("Cred-def request processed: {}", parsed.credential_definition_id);
        Ok(parsed)
    }

    pub async fn create_cred_def_with_connection(
        &self,
        schema_id: &str,
        tag: &str,
        support_revocation: bool,
        conn_id: &str,
    ) -> Result<CredDefResponse> {
        let url = format!(
            "{}/credential-definitions?create_transaction_for_endorser=true&conn_id={}",
            self.admin_url,
            conn_id
        );

        let mut payload = json!({
            "schema_id": schema_id,
            "tag": tag,
            "support_revocation": support_revocation
        });

        if support_revocation {
            payload["revocation_registry_size"] = json!(1000);
        }

        tracing::info!("Creating cred-def via ACA-Py: schema={} tag={} revocation={}", 
            schema_id, tag, support_revocation);

        let response = self.client
            .post(&url)
            .json(&payload)
            .send()
            .await
            .context("Failed to create cred-def via ACA-Py")?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            anyhow::bail!("Failed to create cred-def: {} - {}", status, error_text);
        }

        let body: serde_json::Value = response
            .json()
            .await
            .context("Failed to parse cred-def creation response")?;

        let txn_signed = body
            .get("txn")
            .and_then(|txn| txn.get("messages_attach"))
            .and_then(|value| value.as_array())
            .and_then(|arr| arr.get(0))
            .and_then(|value| value.get("data"))
            .and_then(|value| value.get("json"))
            .and_then(|value| value.as_str())
            .map(|value| value.to_string());

        let parsed = if body.get("credential_definition_id").is_some() {
            let mut parsed: CredDefResponse = serde_json::from_value(body)
                .context("Failed to parse cred-def response")?;
            if parsed.signed_transaction.is_none() {
                parsed.signed_transaction = txn_signed;
            }
            parsed
        } else if let Some(sent) = body.get("sent") {
            let cred_def_id = sent
                .get("credential_definition_id")
                .or_else(|| sent.get("cred_def_id"))
                .and_then(|v| v.as_str());
            let signed_txn = sent
                .get("credential_definition")
                .or_else(|| sent.get("cred_def"))
                .and_then(|value| value.get("signed_txn"))
                .and_then(|v| v.as_str())
                .map(|value| value.to_string());

            CredDefResponse {
                credential_definition_id: cred_def_id.unwrap_or_default().to_string(),
                credential_definition: CredDefDetail {
                    id: cred_def_id.unwrap_or_default().to_string(),
                    tag: tag.to_string(),
                    cred_def_type: "CL".to_string(),
                },
                signed_transaction: signed_txn.or(txn_signed),
            }
        } else {
            CredDefResponse {
                credential_definition_id: String::new(),
                credential_definition: CredDefDetail {
                    id: String::new(),
                    tag: tag.to_string(),
                    cred_def_type: "CL".to_string(),
                },
                signed_transaction: txn_signed,
            }
        };

        tracing::info!("Cred-def request processed: {}", parsed.credential_definition_id);
        Ok(parsed)
    }

    /// Get the agent's public DID
    pub async fn get_public_did(&self) -> Result<Option<DidResult>> {
        let url = format!("{}/wallet/did/public", self.admin_url);
        
        let response = self.client
            .get(&url)
            .send()
            .await
            .context("Failed to get public DID")?;

        if response.status().as_u16() == 404 {
            return Ok(None);
        }

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            anyhow::bail!("Failed to get public DID: {} - {}", status, error_text);
        }

        let result: CreateDidResponse = response
            .json()
            .await
            .context("Failed to parse public DID response")?;

        Ok(Some(result.result))
    }
}
