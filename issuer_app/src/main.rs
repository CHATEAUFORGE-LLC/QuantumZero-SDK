use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use uuid::Uuid;

mod api_client;
use api_client::{
    did_helpers, ApiClient, CredDefRequest, IssuanceRequest, IssuerOnboardingRequest,
    SchemaRequest,
};
use quantumzero_rust_sdk::CryptoCore;

#[derive(Clone)]
struct AppState {
    issuer_info: Arc<Mutex<IssuerInfo>>,
    api_client: Arc<ApiClient>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct IssuerInfo {
    did: Option<String>,
    verkey: Option<String>,
    alias: Option<String>,
    role: Option<String>,
    signing_key_hex: Option<String>,
    registration_status: Option<String>,
    ledger_status: Option<String>,
    registration_id: Option<Uuid>,
    schemas: Vec<SchemaInfo>,
    cred_defs: Vec<CredDefInfo>,
    issuance_requests: Vec<IssuanceInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SchemaInfo {
    id: Uuid,
    name: String,
    version: String,
    attributes: Vec<String>,
    schema_id: String,
    status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CredDefInfo {
    id: Uuid,
    schema_id: String,
    tag: String,
    cred_def_id: String,
    status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct IssuanceInfo {
    id: Uuid,
    cred_def_id: String,
    status: String,
    submitted_at: String,
}

impl Default for IssuerInfo {
    fn default() -> Self {
        Self {
            did: None,
            verkey: None,
            alias: None,
            role: None,
            signing_key_hex: None,
            registration_status: None,
            ledger_status: None,
            registration_id: None,
            schemas: Vec::new(),
            cred_defs: Vec::new(),
            issuance_requests: Vec::new(),
        }
    }
}

#[derive(Deserialize)]
struct CreateDidRequest {
    alias: String,
    role: Option<String>,
}

#[derive(Deserialize)]
struct CreateSchemaRequestForm {
    name: String,
    version: String,
    attributes: String, // Comma-separated
}

#[derive(Deserialize)]
struct CreateCredDefRequestForm {
    schema_id: String,
    tag: String,
    support_revocation: bool,
}

#[derive(Deserialize)]
struct CreateIssuanceRequestForm {
    cred_def_id: String,
    credential_values: String, // JSON string
}

async fn index() -> impl Responder {
    let html = include_str!("../static/index.html");
    HttpResponse::Ok().content_type("text/html").body(html)
}

async fn get_issuer_info(state: web::Data<AppState>) -> impl Responder {
    let info = state.issuer_info.lock().unwrap();
    HttpResponse::Ok().json(&*info)
}

async fn create_did(
    state: web::Data<AppState>,
    form: web::Json<CreateDidRequest>,
) -> impl Responder {
    let (did, key_pair) = did_helpers::generate_did();
    let verkey = did_helpers::verkey_to_base58(&key_pair.verifying_key);
    let signing_key_hex = hex::encode(key_pair.signing_key.to_bytes());

    let role = form.role.clone().unwrap_or_else(|| "ENDORSER".to_string());
    
    let mut info = state.issuer_info.lock().unwrap();
    info.did = Some(did.clone());
    info.verkey = Some(verkey.clone());
    info.alias = Some(form.alias.clone());
    info.signing_key_hex = Some(signing_key_hex);
    info.role = Some(role.clone());

    tracing::info!(
        "Created DID: {} with verkey: {} for alias: {}",
        did,
        verkey,
        form.alias
    );

    HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "did": did,
        "verkey": verkey,
        "alias": form.alias,
        "role": role
    }))
}

async fn register_issuer(state: web::Data<AppState>) -> impl Responder {
    let info = state.issuer_info.lock().unwrap();

    let (did, verkey, alias, role, signing_key_hex) = match (
        &info.did,
        &info.verkey,
        &info.alias,
        &info.role,
        &info.signing_key_hex,
    ) {
        (Some(d), Some(v), Some(a), Some(r), Some(sk)) => (d.clone(), v.clone(), a.clone(), r.clone(), sk.clone()),
        _ => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "success": false,
                "error": "DID not created yet. Create a DID first."
            }));
        }
    };
    drop(info);

    // Reconstruct key pair from hex
    let signing_key_bytes = match hex::decode(&signing_key_hex) {
        Ok(bytes) => bytes,
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "success": false,
                "error": format!("Failed to decode signing key: {}", e)
            }));
        }
    };

    let signing_key = match ed25519_dalek::SigningKey::from_bytes(
        &signing_key_bytes
            .try_into()
            .map_err(|_| "Invalid key length")
            .unwrap(),
    ) {
        key => key,
    };
    let verifying_key = signing_key.verifying_key();

    let request = IssuerOnboardingRequest {
        issuer_did: did.clone(),
        verkey: verkey.clone(),
        alias: alias.clone(),
        role: role.clone(),
        metadata: None,
    };

    match state
        .api_client
        .submit_issuer_request(&request, &signing_key, &verifying_key)
        .await
    {
        Ok(result) => {
            let mut info = state.issuer_info.lock().unwrap();
            info.registration_status = Some(result.status.clone());
            info.registration_id = Some(result.request_id);

            tracing::info!(
                "Issuer registration submitted: request_id={}, status={}",
                result.request_id,
                result.status
            );

            HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "request_id": result.request_id,
                "status": result.status,
                "message": result.message
            }))
        }
        Err(e) => {
            tracing::error!("Failed to register issuer: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "success": false,
                "error": format!("Failed to register issuer: {}", e)
            }))
        }
    }
}

async fn sync_ledger(state: web::Data<AppState>) -> impl Responder {
    let info = state.issuer_info.lock().unwrap();

    let (did, signing_key_hex) = match (&info.did, &info.signing_key_hex) {
        (Some(d), Some(sk)) => (d.clone(), sk.clone()),
        _ => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "success": false,
                "error": "DID not created yet. Create a DID first."
            }));
        }
    };
    drop(info);

    let signing_key_bytes = match hex::decode(&signing_key_hex) {
        Ok(bytes) => bytes,
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "success": false,
                "error": format!("Failed to decode signing key: {}", e)
            }));
        }
    };

    let signing_key = ed25519_dalek::SigningKey::from_bytes(
        &signing_key_bytes
            .try_into()
            .map_err(|_| "Invalid key length")
            .unwrap(),
    );
    let verifying_key = signing_key.verifying_key();

    match state
        .api_client
        .sync_issuer_data(&did, &signing_key, &verifying_key)
        .await
    {
        Ok(sync_data) => {
            // Update local state with synced data
            let mut info = state.issuer_info.lock().unwrap();
            
            let mut ledger_status = None;
            if let Some(issuer) = sync_data.get("issuer") {
                if let Some(status) = issuer.get("ledger_status").and_then(|v| v.as_str()) {
                    info.registration_status = Some(status.to_string());
                    info.ledger_status = Some(status.to_string());
                    ledger_status = Some(status.to_string());
                }
            }
            
            // Update schemas
            if let Some(schemas) = sync_data.get("schemas").and_then(|v| v.as_array()) {
                for (idx, schema) in schemas.iter().enumerate() {
                    if idx < info.schemas.len() {
                        if let Some(ledger_status) = schema.get("ledger_status").and_then(|v| v.as_str()) {
                            info.schemas[idx].status = ledger_status.to_string();
                        }
                        if let Some(schema_id) = schema.get("schema_id").and_then(|v| v.as_str()) {
                            info.schemas[idx].schema_id = schema_id.to_string();
                        }
                    }
                }
            }
            
            // Update cred_defs
            if let Some(cred_defs) = sync_data.get("credential_definitions").and_then(|v| v.as_array()) {
                for (idx, cred_def) in cred_defs.iter().enumerate() {
                    if idx < info.cred_defs.len() {
                        if let Some(ledger_status) = cred_def.get("ledger_status").and_then(|v| v.as_str()) {
                            info.cred_defs[idx].status = ledger_status.to_string();
                        }
                        if let Some(cred_def_id) = cred_def.get("cred_def_id").and_then(|v| v.as_str()) {
                            info.cred_defs[idx].cred_def_id = cred_def_id.to_string();
                        }
                    }
                }
            }

            tracing::info!("Successfully synced ledger data for DID: {}", did);

            HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "message": "Ledger data synced successfully",
                "ledger_status": ledger_status,
                "data": sync_data
            }))
        }
        Err(e) => {
            tracing::error!("Failed to sync ledger data: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "success": false,
                "error": format!("Failed to sync: {}", e)
            }))
        }
    }
}

async fn create_schema(
    state: web::Data<AppState>,
    form: web::Json<CreateSchemaRequestForm>,
) -> impl Responder {
    let info = state.issuer_info.lock().unwrap();

    let (did, signing_key_hex) = match (&info.did, &info.signing_key_hex) {
        (Some(d), Some(sk)) => (d.clone(), sk.clone()),
        _ => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "success": false,
                "error": "DID not created yet. Create a DID first."
            }));
        }
    };
    drop(info);

    // Parse attributes
    let attributes: Vec<String> = form
        .attributes
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    if attributes.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "success": false,
            "error": "At least one attribute is required"
        }));
    }

    let schema_id = format!("{}:2:{}:{}", did, form.name, form.version);

    // Reconstruct key pair
    let signing_key_bytes = hex::decode(&signing_key_hex).unwrap();
    let signing_key =
        ed25519_dalek::SigningKey::from_bytes(&signing_key_bytes.try_into().unwrap());
    let verifying_key = signing_key.verifying_key();

    let request = SchemaRequest {
        issuer_did: did.clone(),
        name: form.name.clone(),
        version: form.version.clone(),
        attributes: attributes.clone(),
        schema_id: Some(schema_id.clone()),
    };

    match state
        .api_client
        .submit_schema_request(&request, &signing_key, &verifying_key)
        .await
    {
        Ok(result) => {
            let mut info = state.issuer_info.lock().unwrap();
            info.schemas.push(SchemaInfo {
                id: result.request_id,
                name: form.name.clone(),
                version: form.version.clone(),
                attributes,
                schema_id: schema_id.clone(),
                status: result.status.clone(),
            });

            tracing::info!(
                "Schema request submitted: request_id={}, schema_id={}",
                result.request_id,
                schema_id
            );

            HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "request_id": result.request_id,
                "schema_id": schema_id,
                "status": result.status,
                "message": result.message
            }))
        }
        Err(e) => {
            tracing::error!("Failed to create schema: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "success": false,
                "error": format!("Failed to create schema: {}", e)
            }))
        }
    }
}

async fn create_cred_def(
    state: web::Data<AppState>,
    form: web::Json<CreateCredDefRequestForm>,
) -> impl Responder {
    let info = state.issuer_info.lock().unwrap();

    let (did, signing_key_hex) = match (&info.did, &info.signing_key_hex) {
        (Some(d), Some(sk)) => (d.clone(), sk.clone()),
        _ => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "success": false,
                "error": "DID not created yet. Create a DID first."
            }));
        }
    };
    drop(info);

    let cred_def_id = format!("{}:3:CL:{}:{}", did, form.schema_id, form.tag);

    // Reconstruct key pair
    let signing_key_bytes = hex::decode(&signing_key_hex).unwrap();
    let signing_key =
        ed25519_dalek::SigningKey::from_bytes(&signing_key_bytes.try_into().unwrap());
    let verifying_key = signing_key.verifying_key();

    let request = CredDefRequest {
        issuer_did: did.clone(),
        schema_id: form.schema_id.clone(),
        tag: form.tag.clone(),
        support_revocation: form.support_revocation,
        cred_def_id: Some(cred_def_id.clone()),
    };

    match state
        .api_client
        .submit_cred_def_request(&request, &signing_key, &verifying_key)
        .await
    {
        Ok(result) => {
            let mut info = state.issuer_info.lock().unwrap();
            info.cred_defs.push(CredDefInfo {
                id: result.request_id,
                schema_id: form.schema_id.clone(),
                tag: form.tag.clone(),
                cred_def_id: cred_def_id.clone(),
                status: result.status.clone(),
            });

            tracing::info!(
                "Credential definition request submitted: request_id={}, cred_def_id={}",
                result.request_id,
                cred_def_id
            );

            HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "request_id": result.request_id,
                "cred_def_id": cred_def_id,
                "status": result.status,
                "message": result.message
            }))
        }
        Err(e) => {
            tracing::error!("Failed to create credential definition: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "success": false,
                "error": format!("Failed to create credential definition: {}", e)
            }))
        }
    }
}

async fn create_issuance(
    state: web::Data<AppState>,
    form: web::Json<CreateIssuanceRequestForm>,
) -> impl Responder {
    let info = state.issuer_info.lock().unwrap();

    let (did, signing_key_hex) = match (&info.did, &info.signing_key_hex) {
        (Some(d), Some(sk)) => (d.clone(), sk.clone()),
        _ => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "success": false,
                "error": "DID not created yet. Create a DID first."
            }));
        }
    };
    drop(info);

    // Parse credential values
    let credential_values: serde_json::Value = match serde_json::from_str(&form.credential_values)
    {
        Ok(v) => v,
        Err(e) => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "success": false,
                "error": format!("Invalid JSON for credential values: {}", e)
            }));
        }
    };

    // Reconstruct key pair
    let signing_key_bytes = hex::decode(&signing_key_hex).unwrap();
    let signing_key =
        ed25519_dalek::SigningKey::from_bytes(&signing_key_bytes.try_into().unwrap());
    let verifying_key = signing_key.verifying_key();

    let request = IssuanceRequest {
        issuer_did: did.clone(),
        cred_def_id: form.cred_def_id.clone(),
        credential_values,
        holder_did: None,
    };

    match state
        .api_client
        .submit_issuance_request(&request, &signing_key, &verifying_key)
        .await
    {
        Ok(result) => {
            let mut info = state.issuer_info.lock().unwrap();
            info.issuance_requests.push(IssuanceInfo {
                id: result.request_id,
                cred_def_id: form.cred_def_id.clone(),
                status: result.status.clone(),
                submitted_at: chrono::Utc::now().to_rfc3339(),
            });

            tracing::info!(
                "Issuance request submitted: request_id={}",
                result.request_id
            );

            HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "request_id": result.request_id,
                "status": result.status,
                "message": result.message
            }))
        }
        Err(e) => {
            tracing::error!("Failed to create issuance request: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "success": false,
                "error": format!("Failed to create issuance request: {}", e)
            }))
        }
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    // Read configuration from environment
    let api_base_url =
        std::env::var("ISSUANCE_API_URL").unwrap_or_else(|_| "http://localhost:8081".to_string());
    let ledger_url =
        std::env::var("LEDGER_URL").unwrap_or_else(|_| "http://ledger-browser:8000".to_string());
    let bind_address = std::env::var("BIND_ADDRESS").unwrap_or_else(|_| "0.0.0.0:8090".to_string());

    tracing::info!("Starting Issuer App");
    tracing::info!("API Base URL: {}", api_base_url);
    tracing::info!("Ledger URL: {}", ledger_url);
    tracing::info!("Binding to: {}", bind_address);

    let state = AppState {
        issuer_info: Arc::new(Mutex::new(IssuerInfo::default())),
        api_client: Arc::new(ApiClient::new(api_base_url, ledger_url)),
    };

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(state.clone()))
            .service(actix_files::Files::new("/static", "./static"))
            .route("/", web::get().to(index))
            .route("/api/issuer-info", web::get().to(get_issuer_info))
            .route("/api/create-did", web::post().to(create_did))
            .route("/api/register-issuer", web::post().to(register_issuer))
            .route("/api/sync-ledger", web::post().to(sync_ledger))
            .route("/api/create-schema", web::post().to(create_schema))
            .route("/api/create-cred-def", web::post().to(create_cred_def))
            .route("/api/create-issuance", web::post().to(create_issuance))
    })
    .bind(bind_address)?
    .run()
    .await
}
