use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::time::sleep;
use uuid::Uuid;

mod api_client;
mod indy_transactions;
mod acapy_client;

use api_client::{
    did_helpers, ApiClient, CredDefRequest, IssuanceRequest, IssuerOnboardingRequest,
    SchemaRequest,
};
use acapy_client::AcaPyClient;
use quantumzero_rust_sdk::CryptoCore;

#[derive(Clone)]
struct AppState {
    issuer_info: Arc<Mutex<IssuerInfo>>,
    api_client: Arc<ApiClient>,
    acapy_client: Arc<AcaPyClient>,
    issuer_admin_url: String,
    trustee_admin_url: String,
    http_client: reqwest::Client,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct IssuerInfo {
    did: Option<String>,
    verkey: Option<String>,
    alias: Option<String>,
    role: Option<String>,
    signing_key_hex: Option<String>,
    #[serde(skip_serializing)]
    seed: Option<String>,
    endorser_connection_id: Option<String>,
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
            seed: None,
            endorser_connection_id: None,
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
    seed: Option<String>,
}

#[derive(Deserialize)]
struct SetupAcaPyRequest {
    endorser_did: Option<String>,
    endorser_name: Option<String>,
}

#[derive(Deserialize)]
struct ConnectEndorserRequest {
    endorser_did: Option<String>,
    endorser_name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OobInvitationResponse {
    invitation: serde_json::Value,
    #[serde(default)]
    invi_msg_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ReceiveInvitationResponse {
    #[serde(default)]
    connection_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ConnectionList {
    results: Vec<ConnectionRecord>,
}

#[derive(Debug, Deserialize)]
struct ConnectionRecord {
    connection_id: String,
    #[serde(default)]
    their_label: Option<String>,
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

    // For Indy compatibility, DID must be base58-encoded (first 16 bytes of verkey)
    let verkey_bytes = verifying_key.to_bytes();
    let did_base58 = bs58::encode(&verkey_bytes[..16]).into_string();
    let did = format!("did:sov:{}", did_base58);
    let verkey = did_helpers::verkey_to_base58(&verifying_key);
    let signing_key_hex = hex::encode(signing_key.to_bytes());

    let role = form.role.clone().unwrap_or_else(|| "ENDORSER".to_string());
    
    let mut info = state.issuer_info.lock().unwrap();
    info.did = Some(did.clone());
    info.verkey = Some(verkey.clone());
    info.alias = Some(form.alias.clone());
    info.signing_key_hex = Some(signing_key_hex);
    info.seed = Some(seed);
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

async fn setup_acapy_did(
    state: web::Data<AppState>,
    form: Option<web::Json<SetupAcaPyRequest>>,
) -> impl Responder {
    let info = state.issuer_info.lock().unwrap();

    let (did, verkey, signing_key_hex, seed, endorser_connection_id) = match (
        &info.did,
        &info.verkey,
        &info.signing_key_hex,
        &info.seed,
        &info.endorser_connection_id,
    ) {
        (Some(d), Some(v), Some(sk), seed_opt, conn_id) => (
            d.clone(),
            v.clone(),
            sk.clone(),
            seed_opt.clone(),
            conn_id.clone(),
        ),
        _ => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "success": false,
                "error": "DID not created yet. Create a DID first."
            }));
        }
    };
    
    // Check if issuer is approved on ledger
    if info.ledger_status.as_deref() != Some("ledger") {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "success": false,
            "error": "Issuer must be approved and on ledger first. Sync with ledger to check status."
        }));
    }
    drop(info);

    let endorser_did = form
        .as_ref()
        .and_then(|data| data.endorser_did.clone())
        .filter(|value| !value.trim().is_empty());
    let endorser_name = form
        .as_ref()
        .and_then(|data| data.endorser_name.clone())
        .filter(|value| !value.trim().is_empty());

    // Import the DID into ACA-Py wallet and set as public
    // This requires recreating the DID using the same seed in ACA-Py
    tracing::info!("Setting up DID in ACA-Py: {}", did);
    let seed = match seed {
        Some(seed) => seed,
        None => {
            let signing_key_bytes = match hex::decode(&signing_key_hex) {
                Ok(bytes) => bytes,
                Err(_) => {
                    return HttpResponse::InternalServerError().json(serde_json::json!({
                        "success": false,
                        "error": "Failed to decode signing key for seed reconstruction"
                    }));
                }
            };

            match String::from_utf8(signing_key_bytes) {
                Ok(seed) if seed.len() == 32 => seed,
                _ => {
                    return HttpResponse::BadRequest().json(serde_json::json!({
                        "success": false,
                        "error": "Issuer seed is unavailable. Recreate the issuer DID to generate a seed compatible with ACA-Py."
                    }));
                }
            }
        }
    };

    match state.acapy_client.create_did_with_seed(&seed).await {
        Ok(result) => {
            let normalize = |value: &str| {
                value
                    .strip_prefix("did:sov:")
                    .unwrap_or(value)
                    .to_string()
            };
            if normalize(&result.did) != normalize(&did) {
                return HttpResponse::BadRequest().json(serde_json::json!({
                    "success": false,
                    "error": "Seed-derived DID does not match the issuer DID. Recreate the issuer DID to align with ACA-Py."
                }));
            }
        }
        Err(e) => {
            let error_message = e.to_string();
            if !error_message.contains("already exists") {
                tracing::error!("Failed to create DID in ACA-Py wallet: {}", error_message);
                return HttpResponse::InternalServerError().json(serde_json::json!({
                    "success": false,
                    "error": format!("Failed to create DID in ACA-Py wallet: {}", error_message)
                }));
            }
        }
    }

    if let Some(ref endorser_did) = endorser_did {
        let endorser_result = if let Some(ref conn_id) = endorser_connection_id {
            state
                .acapy_client
                .set_endorser_info_on_connection(conn_id, endorser_did, endorser_name.as_deref())
                .await
        } else {
            state
                .acapy_client
                .set_endorser_info(endorser_did, endorser_name.as_deref())
                .await
        };

        if let Err(e) = endorser_result {
            tracing::error!("Failed to set endorser info: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "success": false,
                "error": format!("Failed to set endorser info: {}", e)
            }));
        }
    }

    let public_did_result = if let Some(ref conn_id) = endorser_connection_id {
        state.acapy_client.set_public_did_with_connection(&did, conn_id).await
    } else {
        state.acapy_client.set_public_did(&did).await
    };

    match public_did_result {
        Ok(result) => {
            let mut info = state.issuer_info.lock().unwrap();
            info.ledger_status = Some("acapy_configured".to_string());

            tracing::info!("ACA-Py public DID set: {} (posture: {:?})", result.did, result.posture);

            HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "did": result.did,
                "posture": result.posture,
                "endorser_did": endorser_did,
                "message": "ACA-Py configured. You can now create schemas and credential definitions."
            }))
        }
        Err(e) => {
            tracing::error!("Failed to set ACA-Py public DID: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "success": false,
                "error": format!("Failed to configure ACA-Py: {}. Ensure issuer seed matches ACA-Py agent seed.", e)
            }))
        }
    }
}

async fn connect_endorser(
    state: web::Data<AppState>,
    form: web::Json<ConnectEndorserRequest>,
) -> impl Responder {
    let endorser_did = form
        .endorser_did
        .clone()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "AUPCKiiq1ema4fbkXYP2Kg".to_string());
    let endorser_name = form
        .endorser_name
        .clone()
        .filter(|value| !value.trim().is_empty());

    let invitation_response = state
        .http_client
        .post(format!(
            "{}/out-of-band/create-invitation?auto_accept=true",
            state.trustee_admin_url
        ))
        .json(&serde_json::json!({
            "alias": "qz-issuer",
            "handshake_protocols": ["https://didcomm.org/didexchange/1.0"],
            "use_public_did": false
        }))
        .send()
        .await;

    let invitation_response = match invitation_response {
        Ok(resp) => resp,
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "success": false,
                "error": format!("Failed to create endorser invitation: {}", e)
            }));
        }
    };

    if !invitation_response.status().is_success() {
        let status = invitation_response.status();
        let error_text = invitation_response.text().await.unwrap_or_default();
        return HttpResponse::InternalServerError().json(serde_json::json!({
            "success": false,
            "error": format!("Failed to create endorser invitation: {} - {}", status, error_text)
        }));
    }

    let invitation: OobInvitationResponse = match invitation_response.json().await {
        Ok(value) => value,
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "success": false,
                "error": format!("Failed to parse endorser invitation: {}", e)
            }));
        }
    };

    let receive_response = state
        .http_client
        .post(format!(
            "{}/out-of-band/receive-invitation?auto_accept=true",
            state.issuer_admin_url
        ))
        .json(&invitation.invitation)
        .send()
        .await;

    let receive_response = match receive_response {
        Ok(resp) => resp,
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "success": false,
                "error": format!("Failed to receive endorser invitation: {}", e)
            }));
        }
    };

    if !receive_response.status().is_success() {
        let status = receive_response.status();
        let error_text = receive_response.text().await.unwrap_or_default();
        return HttpResponse::InternalServerError().json(serde_json::json!({
            "success": false,
            "error": format!("Failed to receive endorser invitation: {} - {}", status, error_text)
        }));
    }

    let receive_body: ReceiveInvitationResponse = match receive_response.json().await {
        Ok(value) => value,
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "success": false,
                "error": format!("Failed to parse endorser connection response: {}", e)
            }));
        }
    };

    let issuer_conn_id = match receive_body.connection_id {
        Some(value) => value,
        None => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "success": false,
                "error": "Issuer connection id missing from ACA-Py response"
            }));
        }
    };

    let trustee_conn_id = if let Some(invi_msg_id) = invitation.invi_msg_id.as_ref() {
        let response = state
            .http_client
            .get(format!(
                "{}/connections?invitation_msg_id={}",
                state.trustee_admin_url,
                invi_msg_id
            ))
            .send()
            .await;

        match response {
            Ok(resp) if resp.status().is_success() => {
                let list: ConnectionList = resp.json().await.unwrap_or(ConnectionList { results: vec![] });
                list.results.into_iter().next().map(|rec| rec.connection_id)
            }
            _ => None,
        }
    } else {
        None
    };

    let trustee_conn_id = match trustee_conn_id {
        Some(value) => value,
        None => {
            let response = state
                .http_client
                .get(format!("{}/connections?state=active", state.trustee_admin_url))
                .send()
                .await;

            let response = match response {
                Ok(resp) => resp,
                Err(e) => {
                    return HttpResponse::InternalServerError().json(serde_json::json!({
                        "success": false,
                        "error": format!("Failed to query trustee connections: {}", e)
                    }));
                }
            };

            if !response.status().is_success() {
                let status = response.status();
                let error_text = response.text().await.unwrap_or_default();
                return HttpResponse::InternalServerError().json(serde_json::json!({
                    "success": false,
                    "error": format!("Failed to query trustee connections: {} - {}", status, error_text)
                }));
            }

            let list: ConnectionList = response.json().await.unwrap_or(ConnectionList { results: vec![] });
            match list
                .results
                .into_iter()
                .find(|rec| rec.their_label.as_deref() == Some("QuantumZero-Issuer-Agent"))
            {
                Some(rec) => rec.connection_id,
                None => {
                    return HttpResponse::InternalServerError().json(serde_json::json!({
                        "success": false,
                        "error": "Unable to locate trustee connection for issuer"
                    }));
                }
            }
        }
    };

    let trustee_role_response = state
        .http_client
        .post(format!(
            "{}/transactions/{}/set-endorser-role?transaction_my_job=TRANSACTION_ENDORSER",
            state.trustee_admin_url,
            trustee_conn_id
        ))
        .send()
        .await;

    if let Ok(resp) = trustee_role_response {
        if !resp.status().is_success() {
            let status = resp.status();
            let error_text = resp.text().await.unwrap_or_default();
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "success": false,
                "error": format!("Failed to set trustee endorser role: {} - {}", status, error_text)
            }));
        }
    }

    let issuer_role_response = state
        .http_client
        .post(format!(
            "{}/transactions/{}/set-endorser-role?transaction_my_job=TRANSACTION_AUTHOR&transaction_their_job=TRANSACTION_ENDORSER",
            state.issuer_admin_url,
            issuer_conn_id
        ))
        .send()
        .await;

    if let Ok(resp) = issuer_role_response {
        if !resp.status().is_success() {
            let status = resp.status();
            let error_text = resp.text().await.unwrap_or_default();
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "success": false,
                "error": format!("Failed to set issuer author role: {} - {}", status, error_text)
            }));
        }
    }

    let set_info_result = state
        .acapy_client
        .set_endorser_info_on_connection(&issuer_conn_id, &endorser_did, endorser_name.as_deref())
        .await;

    let set_info_result = match set_info_result {
        Ok(_) => Ok(()),
        Err(err) if err.to_string().contains("transaction_my_job") => {
            sleep(Duration::from_millis(500)).await;
            state
                .acapy_client
                .set_endorser_info_on_connection(&issuer_conn_id, &endorser_did, endorser_name.as_deref())
                .await
        }
        Err(err) => Err(err),
    };

    if let Err(e) = set_info_result {
        return HttpResponse::InternalServerError().json(serde_json::json!({
            "success": false,
            "error": format!("Failed to set endorser info: {}", e)
        }));
    }

    {
        let mut info = state.issuer_info.lock().unwrap();
        info.endorser_connection_id = Some(issuer_conn_id.clone());
    }

    HttpResponse::Ok().json(serde_json::json!({
        "success": true,
            "issuer_connection_id": issuer_conn_id,
        "trustee_connection_id": trustee_conn_id,
        "endorser_did": endorser_did
    }))
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

    let (did, signing_key_hex, ledger_status, endorser_connection_id) = match (&info.did, &info.signing_key_hex, &info.ledger_status, &info.endorser_connection_id) {
        (Some(d), Some(sk), ledger_status, conn_id) => (d.clone(), sk.clone(), ledger_status.clone(), conn_id.clone()),
        _ => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "success": false,
                "error": "DID not created yet. Create a DID first."
            }));
        }
    };
    
    // Check if issuer is approved on ledger
    if !matches!(ledger_status.as_deref(), Some("ledger") | Some("acapy_configured")) {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "success": false,
            "error": "Issuer must be approved and on ledger first. Check registration status."
        }));
    }
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

    let signing_key_bytes = match hex::decode(&signing_key_hex) {
        Ok(bytes) => bytes,
        Err(_) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "success": false,
                "error": "Failed to decode signing key"
            }));
        }
    };
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&signing_key_bytes.try_into().unwrap());
    let verifying_key = signing_key.verifying_key();

    let mut schema_id: Option<String> = None;
    let mut signed_transaction: Option<String> = None;

    if ledger_status.as_deref() == Some("acapy_configured") {
        let schema_result = if let Some(ref conn_id) = endorser_connection_id {
            state
                .acapy_client
                .create_schema_with_connection(&form.name, &form.version, &attributes, conn_id)
                .await
        } else {
            state
                .acapy_client
                .create_schema(&form.name, &form.version, &attributes)
                .await
        };

        match schema_result {
            Ok(result) => {
                if !result.schema_id.is_empty() {
                    schema_id = Some(result.schema_id.clone());
                }
                signed_transaction = result.signed_transaction.clone();
            }
            Err(e) => {
                tracing::warn!("Failed to create ACA-Py schema transaction: {}", e);
            }
        }
    }

    if ledger_status.as_deref() == Some("acapy_configured") && signed_transaction.is_none() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "success": false,
            "error": "Schema transaction was not created for endorsement. Ensure ACA-Py is configured with the endorser connection and the issuer DID is public."
        }));
    }

    let request = SchemaRequest {
        issuer_did: did.clone(),
        name: form.name.clone(),
        version: form.version.clone(),
        attributes: attributes.clone(),
        schema_id: schema_id.clone(),
        signed_transaction,
    };

    match state
        .api_client
        .submit_schema_request(&request, &signing_key, &verifying_key)
        .await
    {
        Ok(result) => {
            let schema_id_value = request
                .schema_id
                .clone()
                .unwrap_or_else(|| format!("{}:2:{}:{}", did, form.name, form.version));

            let mut info = state.issuer_info.lock().unwrap();
            info.schemas.push(SchemaInfo {
                id: result.request_id,
                name: form.name.clone(),
                version: form.version.clone(),
                attributes,
                schema_id: schema_id_value.clone(),
                status: result.status.clone(),
            });

            tracing::info!(
                "Schema request submitted: request_id={} schema_id={}",
                result.request_id,
                info.schemas.last().map(|s| s.schema_id.as_str()).unwrap_or("")
            );

            HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "request_id": result.request_id,
                "status": result.status,
                "schema_id": request.schema_id,
                "message": result.message
            }))
        }
        Err(e) => {
            tracing::error!("Failed to submit schema request: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "success": false,
                "error": format!("Failed to submit schema request: {}", e)
            }))
        }
    }
}

async fn create_cred_def(
    state: web::Data<AppState>,
    form: web::Json<CreateCredDefRequestForm>,
) -> impl Responder {
    let info = state.issuer_info.lock().unwrap();

    let (did, signing_key_hex, ledger_status, endorser_connection_id) = match (
        &info.did,
        &info.signing_key_hex,
        &info.ledger_status,
        &info.endorser_connection_id,
    ) {
        (Some(d), Some(sk), ledger_status, conn_id) => (
            d.clone(),
            sk.clone(),
            ledger_status.clone(),
            conn_id.clone(),
        ),
        _ => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "success": false,
                "error": "DID not created yet. Create a DID first."
            }));
        }
    };
    
    // Check if issuer is approved on ledger
    if !matches!(ledger_status.as_deref(), Some("ledger") | Some("acapy_configured")) {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "success": false,
            "error": "Issuer must be approved and on ledger first. Check registration status."
        }));
    }
    drop(info);

    let normalized_schema_id = form
        .schema_id
        .strip_prefix("did:sov:")
        .unwrap_or(&form.schema_id)
        .to_string();

    let signing_key_bytes = match hex::decode(&signing_key_hex) {
        Ok(bytes) => bytes,
        Err(_) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "success": false,
                "error": "Failed to decode signing key"
            }));
        }
    };
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&signing_key_bytes.try_into().unwrap());
    let verifying_key = signing_key.verifying_key();

    let mut cred_def_id: Option<String> = None;
    let mut signed_transaction: Option<String> = None;
    let mut tag = form.tag.clone();

    if ledger_status.as_deref() == Some("acapy_configured") {
        let cred_def_result = if let Some(ref conn_id) = endorser_connection_id {
            state.acapy_client.create_cred_def_with_connection(
                &normalized_schema_id,
                &tag,
                form.support_revocation,
                conn_id
            ).await
        } else {
            state.acapy_client.create_cred_def(
                &normalized_schema_id,
                &tag,
                form.support_revocation
            ).await
        };

        match cred_def_result {
            Ok(result) => {
                if !result.credential_definition_id.is_empty() {
                    cred_def_id = Some(result.credential_definition_id.clone());
                }
                signed_transaction = result.signed_transaction.clone();
            }
            Err(e) => {
                let error_message = e.to_string();
                if error_message.contains("in wallet") {
                    let fallback_tag = format!(
                        "{}-{}",
                        tag,
                        Uuid::new_v4().simple().to_string()
                    );
                    tracing::warn!("Cred-def tag collision; retrying with tag {}", fallback_tag);
                    tag = fallback_tag;

                    let retry_result = if let Some(ref conn_id) = endorser_connection_id {
                        state.acapy_client.create_cred_def_with_connection(
                            &normalized_schema_id,
                            &tag,
                            form.support_revocation,
                            conn_id
                        ).await
                    } else {
                        state.acapy_client.create_cred_def(
                            &normalized_schema_id,
                            &tag,
                            form.support_revocation
                        ).await
                    };

                    match retry_result {
                        Ok(result) => {
                            if !result.credential_definition_id.is_empty() {
                                cred_def_id = Some(result.credential_definition_id.clone());
                            }
                            signed_transaction = result.signed_transaction.clone();
                        }
                        Err(retry_error) => {
                            tracing::warn!("Failed to create ACA-Py cred-def transaction: {}", retry_error);
                        }
                    }
                } else {
                    tracing::warn!("Failed to create ACA-Py cred-def transaction: {}", e);
                }
            }
        }
    }

    if signed_transaction.is_none() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "success": false,
            "error": "Credential definition transaction was not created for endorsement. Ensure ACA-Py is configured with the endorser connection and the schema is on ledger."
        }));
    }

    let request = CredDefRequest {
        issuer_did: did.clone(),
        schema_id: form.schema_id.clone(),
        tag: tag.clone(),
        support_revocation: form.support_revocation,
        metadata: Some(serde_json::json!({
            "issuer_acapy_admin_url": state.issuer_admin_url,
            "issuer_acapy_endorser_conn_id": endorser_connection_id
        })),
        cred_def_id: cred_def_id.clone(),
        signed_transaction,
    };

    match state
        .api_client
        .submit_cred_def_request(&request, &signing_key, &verifying_key)
        .await
    {
        Ok(result) => {
            let cred_def_id_value = request
                .cred_def_id
                .clone()
                .unwrap_or_else(|| format!("{}:3:CL:{}:{}", did, normalized_schema_id, form.tag));

            let mut info = state.issuer_info.lock().unwrap();
            info.cred_defs.push(CredDefInfo {
                id: result.request_id,
                schema_id: form.schema_id.clone(),
                tag: tag.clone(),
                cred_def_id: cred_def_id_value,
                status: result.status.clone(),
            });

            tracing::info!(
                "Credential definition request submitted: request_id={}",
                result.request_id
            );

            HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "request_id": result.request_id,
                "status": result.status,
                "cred_def_id": request.cred_def_id,
                "message": result.message,
                "tag": tag
            }))
        }
        Err(e) => {
            tracing::error!("Failed to submit cred-def request: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "success": false,
                "error": format!("Failed to submit credential definition request: {}", e)
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
    let acapy_admin_url =
        std::env::var("ACAPY_ADMIN_URL").unwrap_or_else(|_| "http://localhost:11000".to_string());
    let trustee_admin_url = std::env::var("TRUSTEE_ACAPY_ADMIN_URL")
        .unwrap_or_else(|_| "http://acapy-admin:11000".to_string());
    let bind_address = std::env::var("BIND_ADDRESS").unwrap_or_else(|_| "0.0.0.0:8090".to_string());

    tracing::info!("Starting Issuer App");
    tracing::info!("API Base URL: {}", api_base_url);
    tracing::info!("Ledger URL: {}", ledger_url);
    tracing::info!("ACA-Py Admin URL: {}", acapy_admin_url);
    tracing::info!("Trustee ACA-Py Admin URL: {}", trustee_admin_url);
    tracing::info!("Binding to: {}", bind_address);

    let issuer_admin_url = acapy_admin_url.clone();

    let state = AppState {
        issuer_info: Arc::new(Mutex::new(IssuerInfo::default())),
        api_client: Arc::new(ApiClient::new(api_base_url, ledger_url)),
        acapy_client: Arc::new(AcaPyClient::new(acapy_admin_url)),
        issuer_admin_url,
        trustee_admin_url,
        http_client: reqwest::Client::new(),
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
            .route("/api/setup-acapy", web::post().to(setup_acapy_did))
            .route("/api/connect-endorser", web::post().to(connect_endorser))
            .route("/api/create-schema", web::post().to(create_schema))
            .route("/api/create-cred-def", web::post().to(create_cred_def))
            .route("/api/create-issuance", web::post().to(create_issuance))
    })
    .bind(bind_address)?
    .run()
    .await
}
