use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::json;

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
struct ConnectionList {
    results: Vec<ConnectionRecord>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ConnectionRecord {
    connection_id: String,
    #[serde(default)]
    their_label: Option<String>,
    #[serde(default)]
    state: Option<String>,
}

impl AcaPyClient {
    pub fn new(admin_url: String) -> Self {
        Self {
            admin_url,
            client: reqwest::Client::new(),
        }
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
