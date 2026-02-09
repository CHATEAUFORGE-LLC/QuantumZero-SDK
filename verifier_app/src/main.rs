use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use uuid::Uuid;

mod api_client;
use api_client::{ApiClient, VerificationRequest};

#[derive(Clone)]
struct AppState {
    verifier_info: Arc<Mutex<VerifierInfo>>,
    api_client: Arc<ApiClient>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct VerifierInfo {
    verifier_id: Option<String>,
    verkey_base64: Option<String>,
    signing_key_hex: Option<String>,
    seed: Option<String>,
}

#[derive(Deserialize)]
struct CreateVerifierKeyRequest {
    seed: Option<String>,
}

#[derive(Deserialize)]
struct VerifyPresentationForm {
    presentation: String,
    signature: String,
    verkey: String,
    issuer_did: Option<String>,
    cred_def_id: Option<String>,
    rev_reg_id: Option<String>,
    credential_revocation_id: Option<String>,
}

async fn index() -> impl Responder {
    let html = include_str!("../static/index.html");
    HttpResponse::Ok().content_type("text/html").body(html)
}

async fn get_verifier_info(state: web::Data<AppState>) -> impl Responder {
    let info = state.verifier_info.lock().unwrap();
    HttpResponse::Ok().json(&*info)
}

async fn create_verifier_keys(
    state: web::Data<AppState>,
    form: web::Json<CreateVerifierKeyRequest>,
) -> impl Responder {
    let seed = form
        .seed
        .as_ref()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| Uuid::new_v4().simple().to_string());

    if seed.len() != 32 {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "success": false,
            "error": "Seed must be exactly 32 characters (ASCII)"
        }));
    }

    let seed_bytes: [u8; 32] = match seed.as_bytes().try_into() {
        Ok(bytes) => bytes,
        Err(_) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "success": false,
                "error": "Failed to generate valid seed"
            }));
        }
    };

    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed_bytes);
    let verifying_key = signing_key.verifying_key();

    let verkey_b64 = STANDARD.encode(verifying_key.to_bytes());
    let signing_key_hex = hex::encode(signing_key.to_bytes());
    let verifier_id = format!("verifier-{}", Uuid::new_v4().simple());

    let mut info = state.verifier_info.lock().unwrap();
    info.verifier_id = Some(verifier_id.clone());
    info.verkey_base64 = Some(verkey_b64.clone());
    info.signing_key_hex = Some(signing_key_hex);
    info.seed = Some(seed);

    HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "verifier_id": verifier_id,
        "verkey": verkey_b64
    }))
}

fn get_signing_keys(info: &VerifierInfo) -> Result<(ed25519_dalek::SigningKey, ed25519_dalek::VerifyingKey), String> {
    let signing_key_hex = info
        .signing_key_hex
        .as_ref()
        .ok_or_else(|| "Signing key not available. Create verifier keys first.".to_string())?;

    let signing_key_bytes = hex::decode(signing_key_hex)
        .map_err(|_| "Failed to decode signing key".to_string())?;

    let signing_key = ed25519_dalek::SigningKey::from_bytes(
        &signing_key_bytes
            .try_into()
            .map_err(|_| "Invalid key length".to_string())?,
    );
    let verifying_key = signing_key.verifying_key();
    Ok((signing_key, verifying_key))
}

async fn verify_presentation(
    state: web::Data<AppState>,
    form: web::Json<VerifyPresentationForm>,
) -> impl Responder {
    let info = state.verifier_info.lock().unwrap();
    let keys = get_signing_keys(&info);
    drop(info);

    let (signing_key, verifying_key) = match keys {
        Ok(keys) => keys,
        Err(err) => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "success": false,
                "error": err
            }));
        }
    };

    let presentation: serde_json::Value = match serde_json::from_str(&form.presentation) {
        Ok(value) => value,
        Err(err) => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "success": false,
                "error": format!("Invalid presentation JSON: {}", err)
            }));
        }
    };

    let request = VerificationRequest {
        presentation,
        signature: form.signature.clone(),
        verkey: form.verkey.clone(),
        issuer_did: form.issuer_did.clone(),
        schema_id: None,
        cred_def_id: form.cred_def_id.clone(),
        rev_reg_id: form.rev_reg_id.clone(),
        credential_revocation_id: form.credential_revocation_id.clone(),
    };

    match state
        .api_client
        .submit_verification_request(&request, &signing_key, &verifying_key)
        .await
    {
        Ok(result) => HttpResponse::Ok().json(serde_json::json!({
            "success": true,
            "verified": result.verified,
            "status": result.status,
            "message": result.message,
            "request_id": result.request_id,
            "completed_at": result.completed_at
        })),
        Err(err) => HttpResponse::InternalServerError().json(serde_json::json!({
            "success": false,
            "error": format!("Verification failed: {}", err)
        })),
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let verification_api_url =
        std::env::var("VERIFICATION_API_URL").unwrap_or_else(|_| "http://localhost:8083".to_string());
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
