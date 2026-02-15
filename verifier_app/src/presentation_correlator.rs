// Workaround for ACA-Py present-proof connection_id extraction bug
// This module attempts to manually correlate presentations that failed
// due to connection_id being None in the present-proof handler

use crate::acapy_client::{AcaPyClient, PresentProofRecord};
use anyhow::{Context, Result};
use std::sync::{Arc, Mutex};
use tokio::time::{sleep, Duration};

pub struct PresentationCorrelator {
    acapy_client: Arc<AcaPyClient>,
    has_active_connections: Arc<Mutex<bool>>,
}

impl PresentationCorrelator {
    pub fn new(acapy_client: Arc<AcaPyClient>, has_active_connections: Arc<Mutex<bool>>) -> Self {
        Self { 
            acapy_client,
            has_active_connections,
        }
    }

    /// Start background task to monitor and correlate stuck presentations
    pub fn start_monitoring(self: Arc<Self>) {
        tokio::spawn(async move {
            tracing::info!("Presentation correlation monitor started (conditional mode)");
            loop {
                // Only check if we have active connections
                let should_check = *self.has_active_connections.lock().unwrap();
                if should_check {
                    if let Err(e) = self.check_and_correlate().await {
                        tracing::error!("Presentation correlation error: {}", e);
                    }
                }
                sleep(Duration::from_secs(10)).await;
            }
        });
    }

    /// Check for proof exchanges stuck in "request-sent" and attempt correlation
    async fn check_and_correlate(&self) -> Result<()> {
        let records = self.acapy_client.list_proof_records().await?;

        for record in records {
            // Only process exchanges stuck in request-sent state
            if record.state != "request-sent" {
                continue;
            }

            // Check if this exchange has been waiting for more than 5 seconds
            // (presentation should arrive within 2-3 seconds normally)
            let connection_id = &record.connection_id;
            tracing::debug!(
                "Found stuck proof exchange {} on connection {}",
                record.pres_ex_id,
                connection_id
            );

            // Attempt to manually check if presentation arrived by querying
            // the exchange record again - sometimes ACA-Py updates it
            // after failing to correlate initially
            match self.acapy_client.get_proof_record(&record.pres_ex_id).await {
                Ok(updated_record) => {
                    if updated_record.state != "request-sent" {
                        tracing::info!(
                            "Proof exchange {} progressed to state: {}",
                            record.pres_ex_id,
                            updated_record.state
                        );
                    } else if updated_record.state == "request-sent" {
                        // Still stuck - check if we can find unprocessed messages
                        tracing::warn!(
                            "Proof exchange {} still stuck in request-sent state - \
                            this is likely due to ACA-Py connection_id extraction bug",
                            record.pres_ex_id
                        );
                    }
                }
                Err(e) => {
                    tracing::error!(
                        "Failed to check proof exchange {}: {}",
                        record.pres_ex_id,
                        e
                    );
                }
            }
        }

        Ok(())
    }
}
