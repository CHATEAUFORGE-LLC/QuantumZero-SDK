use anyhow::{Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

#[derive(Clone)]
pub struct ApiClient {
    base_url: String,
    client: reqwest::Client,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub data: Option<T>,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VerificationRequest {
    pub presentation: Value,
    pub signature: String,
    pub verkey: String,
    pub issuer_did: Option<String>,
    pub schema_id: Option<String>,
    pub cred_def_id: Option<String>,
    pub rev_reg_id: Option<String>,
    pub credential_revocation_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VerificationResult {
    pub request_id: Uuid,
    pub verified: bool,
    pub status: String,
    pub message: String,
    pub completed_at: chrono::DateTime<chrono::Utc>,
}

impl ApiClient {
    pub fn new(base_url: String) -> Self {
        Self {
            base_url,
            client: reqwest::Client::new(),
        }
    }

    pub fn create_signed_headers(
        &self,
        signing_key: &ed25519_dalek::SigningKey,
        verifying_key: &ed25519_dalek::VerifyingKey,
        body: &str,
    ) -> Result<reqwest::header::HeaderMap> {
        use ed25519_dalek::Signer;

        let nonce = Uuid::new_v4().to_string();
        let timestamp = Utc::now().timestamp();

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

    pub async fn submit_verification_request(
        &self,
        request: &VerificationRequest,
        signing_key: &ed25519_dalek::SigningKey,
        verifying_key: &ed25519_dalek::VerifyingKey,
    ) -> Result<VerificationResult> {
        let body = serde_json::to_string(&request)?;
        let headers = self.create_signed_headers(signing_key, verifying_key, &body)?;

        let url = format!("{}/api/v1/verifications", self.base_url);
        let response = self
            .client
            .post(&url)
            .headers(headers)
            .body(body)
            .send()
            .await
            .context("Failed to send verification request")?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            anyhow::bail!("API error: {}", error_text);
        }

        let api_response: ApiResponse<VerificationResult> = response
            .json()
            .await
            .context("Failed to parse verification response")?;

        api_response
            .data
            .ok_or_else(|| anyhow::anyhow!("No data in response"))
    }
}
