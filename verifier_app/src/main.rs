use actix_web::{web, App, HttpRequest, HttpResponse, HttpServer, Responder};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use qrcode::QrCode;
use qrcode::render::svg;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use uuid::Uuid;

mod acapy_client;
mod telemetry_client;
mod presentation_storage;
mod presentation_correlator;

use acapy_client::AcaPyClient;
use telemetry_client::{TelemetryClient, TelemetryEvent};
use presentation_storage::PresentationStorage;
use presentation_correlator::PresentationCorrelator;

#[derive(Clone)]
struct AppState {
    verifier_info: Arc<Mutex<VerifierInfo>>,
    acapy_client: Arc<AcaPyClient>,
    telemetry_client: Arc<TelemetryClient>,
    mobile_app_scheme: String,
    presentation_storage: PresentationStorage,
    has_active_connections: Arc<Mutex<bool>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct VerifierInfo {
    verifier_id: String,
    label: String,
}

fn derive_public_verifier_url(req: &HttpRequest) -> Option<String> {
    // Check environment variable first
    if let Ok(env_url) = std::env::var("QZ_PUBLIC_VERIFIER_URL") {
        let trimmed = env_url.trim();
        if !trimmed.is_empty() 
            && !trimmed.to_lowercase().contains("verifier-acapy")
            && !trimmed.to_lowercase().contains("localhost")
            && !trimmed.to_lowercase().contains("127.0.0.1") {
            return Some(trimmed.to_string());
        }
    }

    // Derive from Host header
    let host_header = req
        .headers()
        .get("x-forwarded-host")
        .or_else(|| req.headers().get("host"))
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())?;

    let hostname = if host_header.starts_with('[') {
        host_header
            .split(']')
            .next()
            .map(|value| value.trim_start_matches('['))
            .filter(|value| !value.is_empty())?
    } else {
        host_header.split(':').next().unwrap_or(host_header)
    };

    let lowered_host = hostname.to_lowercase();
    if lowered_host == "localhost" || lowered_host == "127.0.0.1" {
        return None;
    }

    let connection_info = req.connection_info();
    let scheme = connection_info.scheme();
    Some(format!("{}://{}:8003", scheme, hostname))
}

#[derive(Deserialize)]
struct CreateInvitationRequest {
    label: Option<String>,
}

#[derive(Deserialize)]
struct SendProofRequestForm {
    connection_id: String,
    requested_attributes: serde_json::Value,
    requested_predicates: Option<serde_json::Value>,
    name: Option<String>,
}

async fn index() -> impl Responder {
    let html = include_str!("../static/index.html");
    HttpResponse::Ok().content_type("text/html").body(html)
}

async fn get_verifier_info(state: web::Data<AppState>) -> impl Responder {
    let info = state.verifier_info.lock().unwrap();
    HttpResponse::Ok().json(&*info)
}

async fn create_invitation(
    state: web::Data<AppState>,
    form: Option<web::Json<CreateInvitationRequest>>,
    req: HttpRequest,
) -> impl Responder {
    let label = form
        .as_ref()
        .and_then(|f| f.label.clone())
        .unwrap_or_else(|| "QuantumZero Verifier".to_string());

    // Clean up all existing connections before creating new invitation
    // This ensures multi-use invitations work correctly
    match state.acapy_client.list_connections(None).await {
        Ok(connections) => {
            if !connections.is_empty() {
                tracing::info!("Cleaning up {} existing connections before creating invitation", connections.len());
                for conn in connections {
                    if let Err(e) = state.acapy_client.delete_connection(&conn.connection_id).await {
                        tracing::warn!("Failed to delete connection {}: {}", conn.connection_id, e);
                    } else {
                        tracing::info!("Deleted connection: {}", conn.connection_id);
                    }
                }
            }
        }
        Err(e) => {
            tracing::warn!("Could not list connections for cleanup: {}", e);
        }
    }
    
    // Enable correlator monitoring when invitation is created
    *state.has_active_connections.lock().unwrap() = true;
    tracing::info!("Enabled presentation correlator monitoring");

    match state.acapy_client.create_oob_invitation(Some(&label)).await {
        Ok(mut invitation) => {
            tracing::info!("Created verifier invitation: {:?}", invitation.invi_msg_id);
            
            // Override invitation service endpoint with publicly accessible URL
            if let Some(public_url) = derive_public_verifier_url(&req) {
                tracing::info!("Using public verifier endpoint: {}", public_url);
                if let Some(inv_obj) = invitation.invitation.as_object_mut() {
                    if let Some(services) = inv_obj.get_mut("services").and_then(|s| s.as_array_mut()) {
                        for service in services.iter_mut() {
                            if let Some(service_obj) = service.as_object_mut() {
                                service_obj.insert("serviceEndpoint".to_string(), serde_json::json!(public_url));
                            }
                        }
                    }
                }
            } else {
                tracing::warn!("No public URL available - mobile connections may fail");
            }
            
            // Create deep link for mobile app
            let invitation_json = serde_json::to_string(&invitation.invitation).unwrap_or_default();
            let encoded_invitation = URL_SAFE_NO_PAD.encode(invitation_json.as_bytes());
            
            let deep_link = format!(
                "{}://connect?oob={}",
                state.mobile_app_scheme,
                encoded_invitation
            );
            
            // Generate QR code SVG
            let qr_svg = match QrCode::new(&deep_link) {
                Ok(code) => {
                    let svg = code
                        .render()
                        .min_dimensions(300, 300)
                        .dark_color(svg::Color("#000000"))
                        .light_color(svg::Color("#ffffff"))
                        .build();
                    Some(svg)
                }
                Err(err) => {
                    tracing::warn!("Failed to generate QR code: {}", err);
                    None
                }
            };
            
            HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "invitation": invitation.invitation,
                "invitation_url": invitation.invitation_url,
                "deep_link": deep_link,
                "qr_code_svg": qr_svg,
                "invi_msg_id": invitation.invi_msg_id
            }))
        }
        Err(err) => {
            tracing::error!("Failed to create invitation: {}", err);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "success": false,
                "error": format!("Failed to create invitation: {}", err)
            }))
        }
    }
}

async fn cleanup_connections(state: web::Data<AppState>) -> impl Responder {
    match state.acapy_client.list_connections(None).await {
        Ok(connections) => {
            if connections.is_empty() {
                tracing::info!("No connections to clean up");
                // Disable correlator monitoring when no connections
                *state.has_active_connections.lock().unwrap() = false;
                tracing::info!("Disabled presentation correlator monitoring");
                return HttpResponse::Ok().json(serde_json::json!({
                    "success": true,
                    "message": "No connections to clean up",
                    "deleted_count": 0
                }));
            }

            tracing::info!("Cleaning up {} existing connections", connections.len());
            let mut deleted_count = 0;
            for conn in connections {
                if let Err(e) = state.acapy_client.delete_connection(&conn.connection_id).await {
                    tracing::warn!("Failed to delete connection {}: {}", conn.connection_id, e);
                } else {
                    tracing::info!("Deleted connection: {}", conn.connection_id);
                    deleted_count += 1;
                }
            }
            
            // Disable correlator monitoring after cleanup
            *state.has_active_connections.lock().unwrap() = false;
            tracing::info!("Disabled presentation correlator monitoring");
            
            HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "message": format!("Cleaned up {} connections", deleted_count),
                "deleted_count": deleted_count
            }))
        }
        Err(err) => {
            tracing::error!("Failed to list connections for cleanup: {}", err);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "success": false,
                "error": format!("Failed to cleanup connections: {}", err)
            }))
        }
    }
}

async fn list_connections(state: web::Data<AppState>) -> impl Responder {
    match state.acapy_client.list_connections(None).await {
        Ok(connections) => {
            // Note: Auto-cleanup disabled to prevent deleting connections during active presentation exchanges
            // Use /api/connections/cleanup endpoint to manually cleanup old connections
            HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "connections": connections
            }))
        }
        Err(err) => {
            tracing::error!("Failed to list connections: {}", err);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "success": false,
                "error": format!("Failed to list connections: {}", err)
            }))
        }
    }
}

async fn send_proof_request(
    state: web::Data<AppState>,
    form: web::Json<SendProofRequestForm>,
) -> impl Responder {
    // Clean up ONLY stuck/failed proof records, preserve verified ones
    match state.acapy_client.list_proof_records().await {
        Ok(records) => {
            let stuck_records: Vec<_> = records.iter()
                .filter(|r| r.state == "request-sent" || r.state == "abandoned" || r.state == "declined")
                .collect();
            
            if !stuck_records.is_empty() {
                tracing::info!("Cleaning up {} stuck/failed proof records", stuck_records.len());
                for record in stuck_records {
                    if let Err(e) = state.acapy_client.delete_proof_record(&record.pres_ex_id).await {
                        tracing::warn!("Failed to delete proof record {}: {}", record.pres_ex_id, e);
                    } else {
                        tracing::info!("Deleted stuck proof record: {}", record.pres_ex_id);
                    }
                }
            }
            
            // Log count of preserved verified records
            let verified_count = records.iter()
                .filter(|r| r.state == "done" || r.state == "verified" || r.verified == Some("true".to_string()))
                .count();
            if verified_count > 0 {
                tracing::info!("Preserving {} verified proof records", verified_count);
            }
        }
        Err(e) => {
            tracing::warn!("Could not list proof records for cleanup: {}", e);
        }
    }

    // Generate a numeric nonce (ACA-Py requires positive numeric string without leading zeros)
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let random_part: u64 = rand::random();
    let nonce = format!("{}{}", timestamp, random_part)[..20].to_string();
    
    let proof_request = serde_json::json!({
        "name": form.name.as_ref().unwrap_or(&"Proof Request".to_string()),
        "version": "1.0",
        "requested_attributes": form.requested_attributes,
        "requested_predicates": form.requested_predicates.as_ref().unwrap_or(&serde_json::json!({})),
        "nonce": nonce
    });

    tracing::info!("Sending proof request to connection: {}", form.connection_id);

    match state
        .acapy_client
        .send_proof_request(&form.connection_id, proof_request)
        .await
    {
        Ok(record) => {
            // Submit telemetry for proof request
            let _ = state.telemetry_client.submit_event(TelemetryEvent::VerificationInitiated {
                verifier_id: state.verifier_info.lock().unwrap().verifier_id.clone(),
                connection_id: form.connection_id.clone(),
                pres_ex_id: record.pres_ex_id.clone(),
            }).await;

            HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "pres_ex_id": record.pres_ex_id,
                "state": record.state
            }))
        }
        Err(err) => {
            tracing::error!("Failed to send proof request: {}", err);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "success": false,
                "error": format!("Failed to send proof request: {}", err)
            }))
        }
    }
}

async fn get_proof_record(
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let pres_ex_id = path.into_inner();

    // First, try to get from cache (persists after ACA-Py auto-cleanup)
    let cached_records = state.presentation_storage.list_all();
    if let Some(cached_record) = cached_records.iter().find(|r| {
        r.get("pres_ex_id")
            .and_then(|v| v.as_str())
            .map(|id| id == pres_ex_id)
            .unwrap_or(false)
    }) {
        tracing::info!("📦 Returning cached proof record: {}", pres_ex_id);
        return HttpResponse::Ok().json(serde_json::json!({
            "success": true,
            "record": cached_record
        }));
    }

    // If not in cache, try ACA-Py (for fresh/in-progress records)
    match state.acapy_client.get_proof_record(&pres_ex_id).await {
        Ok(record) => {
            // If presentation is verified, submit telemetry
            if record.state == "verified" || record.verified == Some("true".to_string()) {
                let verified = record.verified.as_ref().map_or(false, |v| v == "true");
                
                let _ = state.telemetry_client.submit_event(TelemetryEvent::VerificationCompleted {
                    verifier_id: state.verifier_info.lock().unwrap().verifier_id.clone(),
                    connection_id: record.connection_id.clone(),
                    pres_ex_id: record.pres_ex_id.clone(),
                    verified,
                    presentation: record.presentation.clone(),
                }).await;
            }

            HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "record": record
            }))
        }
        Err(err) => {
            tracing::error!("Failed to get proof record from ACA-Py: {}", err);
            HttpResponse::Ok().json(serde_json::json!({
                "success": false,
                "error": format!("Failed to get proof record: {}", err)
            }))
        }
    }
}

async fn list_cached_presentations(
    state: web::Data<AppState>,
) -> impl Responder {
    let cached_presentations = state.presentation_storage.list_all();
    
    tracing::info!("Returning {} cached verified presentations", cached_presentations.len());
    
    HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "records": cached_presentations,
        "count": cached_presentations.len()
    }))
}

async fn list_proof_records(state: web::Data<AppState>) -> impl Responder {
    match state.acapy_client.list_proof_records().await {
        Ok(records) => {
            // Get active connections to filter proof records
            if let Ok(connections) = state.acapy_client.list_connections(None).await {
                let active_conn_ids: std::collections::HashSet<_> = 
                    connections.iter().map(|c| c.connection_id.as_str()).collect();
                
                // Filter records to only those for active connections
                let filtered_records: Vec<_> = records.into_iter()
                    .filter(|r| active_conn_ids.contains(r.connection_id.as_str()))
                    .collect();
                
                HttpResponse::Ok().json(serde_json::json!({
                    "success": true,
                    "records": filtered_records
                }))
            } else {
                HttpResponse::Ok().json(serde_json::json!({
                    "success": true,
                    "records": records
                }))
            }
        },
        Err(err) => {
            tracing::error!("Failed to list proof records: {}", err);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "success": false,
                "error": format!("Failed to list proof records: {}", err)
            }))
        }
    }
}

#[derive(Deserialize)]
struct SubmitPresentationRequest {
    presentation: serde_json::Value,
    signature: String,
    verkey: String,
}

async fn submit_presentation(
    state: web::Data<AppState>,
    req: HttpRequest,
    form: web::Json<SubmitPresentationRequest>,
) -> impl Responder {
    tracing::info!("Received presentation submission");

    // Store presentation with 5 minute TTL
    let presentation_id = state.presentation_storage.store(
        form.presentation.clone(),
        form.signature.clone(),
        form.verkey.clone(),
        300, // 5 minutes
    );

    // Generate retrieval URL - use the actual verifier app port
    let connection_info = req.connection_info();
    let host = req
        .headers()
        .get("x-forwarded-host")
        .or_else(|| req.headers().get("host"))
        .and_then(|value| value.to_str().ok())
        .unwrap_or("localhost:3031");
    
    let retrieval_url = format!("{}://{}/api/presentations/{}", 
        connection_info.scheme(), 
        host, 
        presentation_id
    );

    tracing::info!("Presentation stored with ID: {} - URL: {}", presentation_id, retrieval_url);

    HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "presentation_id": presentation_id,
        "retrieval_url": retrieval_url,
        "expires_in": 300
    }))
}

async fn get_presentation(
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let presentation_id = path.into_inner();

    tracing::info!("Fetching presentation: {}", presentation_id);

    match state.presentation_storage.get(&presentation_id) {
        Some(stored) => {
            tracing::info!("Presentation retrieved successfully");
            HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "presentation": stored.presentation,
                "signature": stored.signature,
                "verkey": stored.verkey,
                "created_at": stored.created_at,
                "expires_at": stored.expires_at
            }))
        }
        None => {
            tracing::warn!("Presentation not found or expired: {}", presentation_id);
            HttpResponse::NotFound().json(serde_json::json!({
                "success": false,
                "error": "Presentation not found or expired"
            }))
        }
    }
}

/// Webhook handler for ACA-Py events
async fn acapy_webhook(
    state: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<serde_json::Value>,
) -> impl Responder {
    let topic = path.into_inner();
    
    tracing::info!("Received ACA-Py webhook: topic={}", topic);
    
    match state.acapy_client.handle_webhook(&topic, body.into_inner()).await {
        Ok(payload) => {
            // Store ALL presentation results (pass or fail) for UI display
            if topic == "present_proof_v2_0" {
                if let Some(state_str) = payload.get("state").and_then(|s| s.as_str()) {
                    // Store ALL presentations in done state (whether verified or failed)
                    if state_str == "done" || state_str == "verified" || state_str == "presentation-received" {
                        let pres_ex_id = state.presentation_storage.store_proof_record(
                            payload.clone(),
                            3600 * 24, // 24 hours TTL
                        );
                        tracing::info!("✅ Stored verified presentation in browser cache: {}", pres_ex_id);
                    }
                }
            }
        }
        Err(e) => {
            tracing::error!("Webhook processing error: {}", e);
        }
    }
    
    HttpResponse::Ok().json(serde_json::json!({"success": true}))
}

/// Manual processing endpoint for stuck presentations
async fn process_pending_presentation(
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let pres_ex_id = path.into_inner();
    
    tracing::info!("Manually processing presentation: {}", pres_ex_id);
    
    // Get the current proof record
    let record = match state.acapy_client.get_proof_record(&pres_ex_id).await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("Failed to get proof record: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to get proof record: {}", e)
            }));
        }
    };
    
    tracing::info!("Current proof record state: {}", record.state);
    
    // If still in request-sent state, check if we can trigger verification
    if record.state == "request-sent" {
        tracing::info!("Proof exchange stuck in request-sent - checking for received presentation");
        
        // Try to verify anyway - might trigger state update if presentation arrived
        match state.acapy_client.verify_presentation(&pres_ex_id).await {
            Ok(updated) => {
                tracing::info!("Manual verification triggered - new state: {}", updated.state);
                return HttpResponse::Ok().json(serde_json::json!({
                    "success": true,
                    "state": updated.state,
                    "verified": updated.verified,
                    "message": "Verification triggered successfully"
                }));
            }
            Err(e) => {
                tracing::warn!("Manual verification failed: {}", e);
                return HttpResponse::Ok().json(serde_json::json!({
                    "success": false,
                    "state": record.state,
                    "message": format!("Presentation not yet received or verification failed: {}", e)
                }));
            }
        }
    }
    
    // Already processed or in another state
    HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "state": record.state,
        "verified": record.verified,
        "message": "Proof exchange is not stuck"
    }))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let issuance_api_url =
        std::env::var("ISSUANCE_API_URL").unwrap_or_else(|_| "http://localhost:8081".to_string());
    let acapy_admin_url =
        std::env::var("ACAPY_ADMIN_URL").unwrap_or_else(|_| "http://localhost:11002".to_string());
    let bind_address =
        std::env::var("BIND_ADDRESS").unwrap_or_else(|_| "0.0.0.0:8091".to_string());
    let mobile_app_scheme =
        std::env::var("QZ_MOBILE_APP_SCHEME").unwrap_or_else(|_| "quantumzero".to_string());

    let verifier_id = format!("verifier-{}", Uuid::new_v4().simple());
    tracing::info!("Initializing verifier with ID: {}", verifier_id);
    tracing::info!("Mobile app scheme: {}", mobile_app_scheme);

    let state = AppState {
        verifier_info: Arc::new(Mutex::new(VerifierInfo {
            verifier_id: verifier_id.clone(),
            label: "QuantumZero Verifier".to_string(),
        })),
        acapy_client: Arc::new(AcaPyClient::new(acapy_admin_url)),
        telemetry_client: Arc::new(TelemetryClient::new(issuance_api_url)),
        mobile_app_scheme,
        presentation_storage: PresentationStorage::new(),
        has_active_connections: Arc::new(Mutex::new(false)),
    };

    // Start the presentation correlator background task
    let correlator = Arc::new(PresentationCorrelator::new(
        state.acapy_client.clone(),
        state.has_active_connections.clone(),
    ));
    correlator.start_monitoring();
    tracing::info!("Started presentation correlation monitor (will activate on invitation creation)");

    tracing::info!("Starting verifier app on {}", bind_address);

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(state.clone()))
            .service(actix_files::Files::new("/static", "./static"))
            .route("/", web::get().to(index))
            .route("/api/verifier-info", web::get().to(get_verifier_info))
            .route("/api/create-invitation", web::post().to(create_invitation))
            .route("/api/connections", web::get().to(list_connections))
            .route("/api/connections/cleanup", web::delete().to(cleanup_connections))
            .route("/api/send-proof-request", web::post().to(send_proof_request))
            .route("/api/proof-records", web::get().to(list_proof_records))
            .route("/api/proof-records/cached", web::get().to(list_cached_presentations))
            .route("/api/proof-records/{pres_ex_id}", web::get().to(get_proof_record))
            .route("/api/presentations", web::post().to(submit_presentation))
            .route("/api/presentations/{id}", web::get().to(get_presentation))
            .route("/api/process-presentation/{pres_ex_id}", web::post().to(process_pending_presentation))
            .route("/webhooks/topic/{topic}/", web::post().to(acapy_webhook))
    })
    .bind(bind_address)?
    .run()
    .await
}
