use anyhow::{Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

/// API client for QuantumZero server interactions
#[derive(Clone)]
pub struct ApiClient {
    base_url: String,
    ledger_url: String,
    client: reqwest::Client,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub data: Option<T>,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct StagingRequestStatus {
    pub request_id: Uuid,
    pub status: String,
    pub message: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IssuerOnboardingRequest {
    pub issuer_did: String,
    pub verkey: String,
    pub alias: String,
    pub role: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SchemaRequest {
    pub issuer_did: String,
    pub name: String,
    pub version: String,
    pub attributes: Vec<String>,
    pub schema_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed_transaction: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CredDefRequest {
    pub issuer_did: String,
    pub schema_id: String,
    pub tag: String,
    pub support_revocation: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
    pub cred_def_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed_transaction: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IssuanceRequest {
    pub issuer_did: String,
    pub cred_def_id: String,
    pub credential_values: serde_json::Value,
    pub holder_did: Option<String>,
}

impl ApiClient {
    pub fn new(base_url: String, ledger_url: String) -> Self {
        Self {
            base_url,
            ledger_url,
            client: reqwest::Client::new(),
        }
    }

    /// Create signed request headers for API authentication
    pub fn create_signed_headers(
        &self,
        signing_key: &ed25519_dalek::SigningKey,
        verifying_key: &ed25519_dalek::VerifyingKey,
        body: &str,
    ) -> Result<reqwest::header::HeaderMap> {
        use ed25519_dalek::Signer;

        let nonce = Uuid::new_v4().to_string();
        let timestamp = Utc::now().timestamp();

        // Create signature payload: nonce.timestamp.body (as bytes, matching server verification)
        let mut payload = Vec::with_capacity(body.len() + nonce.len() + 32);
        payload.extend_from_slice(nonce.as_bytes());
        payload.push(b'.');
        payload.extend_from_slice(timestamp.to_string().as_bytes());
        payload.push(b'.');
        payload.extend_from_slice(body.as_bytes());
        
        let signature = signing_key.sign(&payload);

        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            "X-QZ-Nonce",
            nonce.parse().context("Invalid nonce header")?,
        );
        headers.insert(
            "X-QZ-Timestamp",
            timestamp
                .to_string()
                .parse()
                .context("Invalid timestamp header")?,
        );
        headers.insert(
            "X-QZ-Signature",
            STANDARD
                .encode(signature.to_bytes())
                .parse()
                .context("Invalid signature header")?,
        );
        headers.insert(
            "X-QZ-Verkey",
            STANDARD
                .encode(verifying_key.to_bytes())
                .parse()
                .context("Invalid verkey header")?,
        );
        headers.insert(
            "Content-Type",
            "application/json"
                .parse()
                .context("Invalid content-type")?,
        );

        Ok(headers)
    }

    /// Submit issuer onboarding request
    pub async fn submit_issuer_request(
        &self,
        request: &IssuerOnboardingRequest,
        signing_key: &ed25519_dalek::SigningKey,
        verifying_key: &ed25519_dalek::VerifyingKey,
    ) -> Result<StagingRequestStatus> {
        let body = serde_json::to_string(&request)?;
        let headers = self.create_signed_headers(signing_key, verifying_key, &body)?;

        let url = format!("{}/api/v1/issuer-requests", self.base_url);
        let response = self
            .client
            .post(&url)
            .headers(headers)
            .body(body)
            .send()
            .await
            .context("Failed to send issuer request")?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            anyhow::bail!("API error: {}", error_text);
        }

        let api_response: ApiResponse<StagingRequestStatus> = response
            .json()
            .await
            .context("Failed to parse issuer response")?;

        api_response
            .data
            .ok_or_else(|| anyhow::anyhow!("No data in response"))
    }

    /// Submit schema request
    pub async fn submit_schema_request(
        &self,
        request: &SchemaRequest,
        signing_key: &ed25519_dalek::SigningKey,
        verifying_key: &ed25519_dalek::VerifyingKey,
    ) -> Result<StagingRequestStatus> {
        let body = serde_json::to_string(&request)?;
        let headers = self.create_signed_headers(signing_key, verifying_key, &body)?;

        let url = format!("{}/api/v1/schema-requests", self.base_url);
        let response = self
            .client
            .post(&url)
            .headers(headers)
            .body(body)
            .send()
            .await
            .context("Failed to send schema request")?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            anyhow::bail!("API error: {}", error_text);
        }

        let api_response: ApiResponse<StagingRequestStatus> = response
            .json()
            .await
            .context("Failed to parse schema response")?;

        api_response
            .data
            .ok_or_else(|| anyhow::anyhow!("No data in response"))
    }

    /// Submit credential definition request
    pub async fn submit_cred_def_request(
        &self,
        request: &CredDefRequest,
        signing_key: &ed25519_dalek::SigningKey,
        verifying_key: &ed25519_dalek::VerifyingKey,
    ) -> Result<StagingRequestStatus> {
        let body = serde_json::to_string(&request)?;
        let headers = self.create_signed_headers(signing_key, verifying_key, &body)?;

        let url = format!("{}/api/v1/cred-def-requests", self.base_url);
        let response = self
            .client
            .post(&url)
            .headers(headers)
            .body(body)
            .send()
            .await
            .context("Failed to send cred def request")?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            anyhow::bail!("API error: {}", error_text);
        }

        let api_response: ApiResponse<StagingRequestStatus> = response
            .json()
            .await
            .context("Failed to parse cred def response")?;

        api_response
            .data
            .ok_or_else(|| anyhow::anyhow!("No data in response"))
    }

    /// Submit issuance request
    pub async fn submit_issuance_request(
        &self,
        request: &IssuanceRequest,
        signing_key: &ed25519_dalek::SigningKey,
        verifying_key: &ed25519_dalek::VerifyingKey,
    ) -> Result<StagingRequestStatus> {
        let body = serde_json::to_string(&request)?;
        let headers = self.create_signed_headers(signing_key, verifying_key, &body)?;

        let url = format!("{}/api/v1/issuance-requests", self.base_url);
        let response = self
            .client
            .post(&url)
            .headers(headers)
            .body(body)
            .send()
            .await
            .context("Failed to send issuance request")?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            anyhow::bail!("API error: {}", error_text);
        }

        let api_response: ApiResponse<StagingRequestStatus> = response
            .json()
            .await
            .context("Failed to parse issuance response")?;

        api_response
            .data
            .ok_or_else(|| anyhow::anyhow!("No data in response"))
    }

    /// Sync issuer data from the server (read-only)
    pub async fn sync_issuer_data(
        &self,
        did: &str,
        signing_key: &ed25519_dalek::SigningKey,
        verifying_key: &ed25519_dalek::VerifyingKey,
    ) -> Result<serde_json::Value> {
        // Query the ledger browser directly to check if data has been written
        // Fetch recent ledger transactions
        let url = format!("{}/ledger/domain?page=1&page_size=100", self.ledger_url);
        let response = self
            .client
            .get(&url)
            .send()
            .await
            .context("Failed to query ledger")?;

        if !response.status().is_success() {
            anyhow::bail!("Failed to query ledger: {}", response.status());
        }

        let ledger_data: serde_json::Value = response
            .json()
            .await
            .context("Failed to parse ledger response")?;

        // Extract issuer DID without "did:sov:" prefix
        let issuer_did = did.strip_prefix("did:sov:").unwrap_or(did);

        // Check issuer status (NYM transaction with type "1")
        let issuer_status = ledger_data
            .get("results")
            .and_then(|r| r.as_array())
            .and_then(|results| {
                results.iter().find(|tx| {
                    tx.get("txn")
                        .and_then(|txn| txn.get("type"))
                        .and_then(|t| t.as_str())
                        == Some("1")
                        && tx.get("txn")
                            .and_then(|txn| txn.get("data"))
                            .and_then(|data| data.get("dest"))
                            .and_then(|dest| dest.as_str())
                        == Some(issuer_did)
                })
            })
            .map(|_| "ledger")
            .unwrap_or("pending");

        // Check schemas (type "101")
        let schemas: Vec<serde_json::Value> = ledger_data
            .get("results")
            .and_then(|r| r.as_array())
            .map(|results| {
                results
                    .iter()
                    .filter(|tx| {
                        tx.get("txn")
                            .and_then(|txn| txn.get("type"))
                            .and_then(|t| t.as_str())
                            == Some("101")
                            && tx.get("txn")
                                .and_then(|txn| txn.get("metadata"))
                                .and_then(|meta| meta.get("from"))
                                .and_then(|from| from.as_str())
                            == Some(issuer_did)
                    })
                    .map(|tx| {
                        let txn_id = tx
                            .get("txnMetadata")
                            .and_then(|m| m.get("txnId"))
                            .and_then(|id| id.as_str())
                            .unwrap_or("");
                        serde_json::json!({
                            "schema_id": txn_id,
                            "ledger_status": "ledger"
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();

        // Check credential definitions (type "102")
        let cred_defs: Vec<serde_json::Value> = ledger_data
            .get("results")
            .and_then(|r| r.as_array())
            .map(|results| {
                results
                    .iter()
                    .filter(|tx| {
                        tx.get("txn")
                            .and_then(|txn| txn.get("type"))
                            .and_then(|t| t.as_str())
                            == Some("102")
                            && tx.get("txn")
                                .and_then(|txn| txn.get("metadata"))
                                .and_then(|meta| meta.get("from"))
                                .and_then(|from| from.as_str())
                            == Some(issuer_did)
                    })
                    .map(|tx| {
                        let txn_id = tx
                            .get("txnMetadata")
                            .and_then(|m| m.get("txnId"))
                            .and_then(|id| id.as_str())
                            .unwrap_or("");
                        serde_json::json!({
                            "cred_def_id": txn_id,
                            "ledger_status": "ledger"
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();

        Ok(serde_json::json!({
            "issuer": {
                "did": did,
                "ledger_status": issuer_status
            },
            "schemas": schemas,
            "credential_definitions": cred_defs
        }))
    }
}

/// Helper functions for DID operations
pub mod did_helpers {
    use quantumzero_rust_sdk::{CryptoCore, KeyPair};

    /// Generate a new DID and key pair
    /// Returns (DID, KeyPair) where DID is base58-encoded
    pub fn generate_did() -> (String, KeyPair) {
        let crypto = CryptoCore::new();
        let key_pair = crypto.generate_key_pair();

        // For Indy compatibility, DID must be base58-encoded (first 16 bytes of verkey)
        let verkey_bytes = key_pair.verifying_key.to_bytes();
        let did_base58 = bs58::encode(&verkey_bytes[..16]).into_string();
        let did = format!("did:sov:{}", did_base58);

        (did, key_pair)
    }

    /// Extract verkey as base64 string
    pub fn verkey_to_base64(verkey: &ed25519_dalek::VerifyingKey) -> String {
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine;
        STANDARD.encode(verkey.to_bytes())
    }

    /// Extract verkey as hex string
    pub fn verkey_to_hex(verkey: &ed25519_dalek::VerifyingKey) -> String {
        hex::encode(verkey.to_bytes())
    }

    /// Extract verkey as base58 string (Indy compatible)
    pub fn verkey_to_base58(verkey: &ed25519_dalek::VerifyingKey) -> String {
        bs58::encode(verkey.to_bytes()).into_string()
    }
}
