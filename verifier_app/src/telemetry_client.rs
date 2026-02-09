use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::json;

/// Client for submitting telemetry events to the issuance API
#[derive(Clone)]
pub struct TelemetryClient {
    issuance_api_url: String,
    client: reqwest::Client,
}

#[derive(Debug, Serialize)]
#[serde(tag = "event_type", rename_all = "snake_case")]
pub enum TelemetryEvent {
    VerificationInitiated {
        verifier_id: String,
        connection_id: String,
        pres_ex_id: String,
    },
    VerificationCompleted {
        verifier_id: String,
        connection_id: String,
        pres_ex_id: String,
        verified: bool,
        presentation: Option<serde_json::Value>,
    },
}

impl TelemetryClient {
    pub fn new(issuance_api_url: String) -> Self {
        Self {
            issuance_api_url,
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .unwrap(),
        }
    }

    pub async fn submit_event(&self, event: TelemetryEvent) -> Result<()> {
        let url = format!("{}/api/v1/telemetry/verifier-events", self.issuance_api_url);

        let payload = match event {
            TelemetryEvent::VerificationInitiated {
                verifier_id,
                connection_id,
                pres_ex_id,
            } => json!({
                "event_type": "verification_initiated",
                "verifier_id": verifier_id,
                "connection_id": connection_id,
                "pres_ex_id": pres_ex_id,
                "timestamp": chrono::Utc::now().to_rfc3339()
            }),
            TelemetryEvent::VerificationCompleted {
                verifier_id,
                connection_id,
                pres_ex_id,
                verified,
                presentation,
            } => {
                let mut payload = json!({
                    "event_type": "verification_completed",
                    "verifier_id": verifier_id,
                    "connection_id": connection_id,
                    "pres_ex_id": pres_ex_id,
                    "verified": verified,
                    "timestamp": chrono::Utc::now().to_rfc3339()
                });
                
                if let Some(pres) = presentation {
                    payload["presentation"] = pres;
                }
                
                payload
            }
        };

        tracing::debug!("Submitting telemetry event: {:?}", payload);

        let response = self
            .client
            .post(&url)
            .json(&payload)
            .send()
            .await
            .context("Failed to submit telemetry event")?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            tracing::warn!("Telemetry submission failed: {} - {}", status, error_text);
            // Don't fail the main operation if telemetry fails
            return Ok(());
        }

        tracing::debug!("Telemetry event submitted successfully");
        Ok(())
    }
}
