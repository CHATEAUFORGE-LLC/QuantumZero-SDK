use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use uuid::Uuid;

mod acapy_client;
mod telemetry_client;

use acapy_client::{AcaPyClient, PresentProofRecord};
use telemetry_client::{TelemetryClient, TelemetryEvent};

#[derive(Clone)]
struct AppState {
    verifier_info: Arc<Mutex<VerifierInfo>>,
    acapy_client: Arc<AcaPyClient>,
    telemetry_client: Arc<TelemetryClient>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct VerifierInfo {
    verifier_id: String,
    label: String,
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
) -> impl Responder {
    let label = form
        .as_ref()
        .and_then(|f| f.label.clone())
        .unwrap_or_else(|| "QuantumZero Verifier".to_string());

    match state.acapy_client.create_oob_invitation(Some(&label)).await {
        Ok(invitation) => {
            tracing::info!("Created verifier invitation: {:?}", invitation.invi_msg_id);
            
            HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "invitation": invitation.invitation,
                "invitation_url": invitation.invitation_url,
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

async fn list_connections(state: web::Data<AppState>) -> impl Responder {
    match state.acapy_client.list_connections(None).await {
        Ok(connections) => HttpResponse::Ok().json(serde_json::json!({
            "success": true,
            "connections": connections
        })),
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
    let proof_request = serde_json::json!({
        "name": form.name.as_ref().unwrap_or(&"Proof Request".to_string()),
        "version": "1.0",
        "requested_attributes": form.requested_attributes,
        "requested_predicates": form.requested_predicates.as_ref().unwrap_or(&serde_json::json!({})),
        "nonce": Uuid::new_v4().to_string().replace("-", "")[..20].to_string()
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
            tracing::error!("Failed to get proof record: {}", err);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "success": false,
                "error": format!("Failed to get proof record: {}", err)
            }))
        }
    }
}

async fn list_proof_records(state: web::Data<AppState>) -> impl Responder {
    match state.acapy_client.list_proof_records().await {
        Ok(records) => HttpResponse::Ok().json(serde_json::json!({
            "success": true,
            "records": records
        })),
        Err(err) => {
            tracing::error!("Failed to list proof records: {}", err);
            HttpResponse::InternalServerError().json(serde_json::json!({
        issuance_api_url =
        std::env::var("ISSUANCE_API_URL").unwrap_or_else(|_| "http://localhost:8081".to_string());
    let acapy_admin_url =
        std::env::var("ACAPY_ADMIN_URL").unwrap_or_else(|_| "http://localhost:11002".to_string());
    let bind_address =
        std::env::var("BIND_ADDRESS").unwrap_or_else(|_| "0.0.0.0:8091".to_string());

    let verifier_id = format!("verifier-{}", Uuid::new_v4().simple());
    tracing::info!("Initializing verifier with ID: {}", verifier_id);

    let state = AppState {
        verifier_info: Arc::new(Mutex::new(VerifierInfo {
            verifier_id: verifier_id.clone(),
            label: "QuantumZero Verifier".to_string(),
        })),
        acapy_client: Arc::new(AcaPyClient::new(acapy_admin_url)),
        telemetry_client: Arc::new(TelemetryClient::new(issuance_api_url)),
    };

    tracing::info!("Starting verifier app on {}", bind_address);

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(state.clone()))
            .service(actix_files::Files::new("/static", "./static"))
            .route("/", web::get().to(index))
            .route("/api/verifier-info", web::get().to(get_verifier_info))
            .route("/api/create-invitation", web::post().to(create_invitation))
            .route("/api/connections", web::get().to(list_connections))
            .route("/api/send-proof-request", web::post().to(send_proof_request))
            .route("/api/proof-records", web::get().to(list_proof_records))
            .route("/api/proof-records/{pres_ex_id}", web::get().to(get_proof_recordt:8083".to_string());
    let bind_address =
        std::env::var("BIND_ADDRESS").unwrap_or_else(|_| "0.0.0.0:8091".to_string());

    let state = AppState {
        verifier_info: Arc::new(Mutex::new(VerifierInfo::default())),
        api_client: Arc::new(ApiClient::new(verification_api_url)),
    };

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(state.clone()))
            .service(actix_files::Files::new("/static", "./static"))
            .route("/", web::get().to(index))
            .route("/api/verifier-info", web::get().to(get_verifier_info))
            .route("/api/create-verifier-keys", web::post().to(create_verifier_keys))
            .route("/api/verify-presentation", web::post().to(verify_presentation))
    })
    .bind(bind_address)?
    .run()
    .await
}
