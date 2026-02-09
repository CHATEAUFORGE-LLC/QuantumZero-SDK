use actix_web::{web, App, HttpRequest, HttpResponse, HttpServer, Responder};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::time::sleep;
use uuid::Uuid;
use qrcode::QrCode;
use qrcode::render::svg;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use url::Url;

mod api_client;
mod indy_transactions;
mod acapy_client;

use api_client::{
    did_helpers, ApiClient, CredDefRequest, IssuerOnboardingRequest, SchemaRequest,
    WalletTelemetryRequest,
};
use acapy_client::{AcaPyClient, CredentialAttribute};

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
struct CreateMobileInvitationRequest {
    label: Option<String>,
    channel: Option<String>,
}

#[derive(Deserialize)]
struct WalletIssuanceRequestForm {
    connection_id: String,
    cred_def_id: String,
    credential_values: String, // JSON string
    channel: Option<String>,
}

#[derive(Deserialize)]
struct ConnectionLookupQuery {
    invitation_id: String,
}

#[derive(Deserialize)]
struct MobileConnectionsQuery {
    invitation_id: Option<String>,
}

#[derive(Deserialize)]
struct QrQuery {
    data: String,
}

fn default_endorser_did() -> String {
    std::env::var("QZ_ENDORSER_DID").unwrap_or_else(|_| "Cbkb3vmwitw4DoxkitzxdJ".to_string())
}

fn default_endorser_name() -> String {
    std::env::var("QZ_ENDORSER_ALIAS").unwrap_or_else(|_| "QZ-Endorser".to_string())
}

fn public_agent_base_url() -> Option<String> {
    std::env::var("QZ_PUBLIC_AGENT_URL")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn mobile_app_scheme() -> String {
    std::env::var("QZ_MOBILE_APP_SCHEME").unwrap_or_else(|_| "quantumzero".to_string())
}

fn extract_oob_param(invitation_url: Option<&str>) -> Option<String> {
    let url = invitation_url?;
    let parsed = Url::parse(url).ok()?;
    parsed
        .query_pairs()
        .find_map(|(key, value)| {
            if key == "oob" || key == "oobid" {
                Some(value.to_string())
            } else {
                None
            }
        })
}

fn encode_invitation_oob(invitation: &serde_json::Value) -> Option<String> {
    let payload = serde_json::to_vec(invitation).ok()?;
    Some(URL_SAFE_NO_PAD.encode(payload))
}

fn build_public_invitation_url_with_base(oob: &str, base: &str) -> Option<String> {
    let mut url = Url::parse(base).ok()?;
    url.set_query(Some(&format!("oob={}", oob)));
    Some(url.to_string())
}

fn derive_public_agent_url(req: &HttpRequest) -> Option<String> {
    if let Some(env) = public_agent_base_url() {
        let lowered = env.to_lowercase();
        if !lowered.contains("issuer-acapy")
            && !lowered.contains("localhost")
            && !lowered.contains("127.0.0.1")
        {
            return Some(env);
        }
    }

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
    Some(format!("{}://{}:8002", scheme, hostname))
}

fn build_app_invitation_url(oob: &str) -> Option<String> {
    let scheme = mobile_app_scheme();
    let mut url = Url::parse(&format!("{}://invite", scheme)).ok()?;
    url.set_query(Some(&format!("oob={}", oob)));
    Some(url.to_string())
}

fn rewrite_invitation_endpoint(
    invitation: &serde_json::Value,
    public_endpoint: &str,
) -> serde_json::Value {
    let mut updated = invitation.clone();
    if let Some(services) = updated.get_mut("services").and_then(|v| v.as_array_mut()) {
        for service in services.iter_mut() {
            if let Some(obj) = service.as_object_mut() {
                if obj.contains_key("serviceEndpoint") {
                    obj.insert(
                        "serviceEndpoint".to_string(),
                        serde_json::Value::String(public_endpoint.to_string()),
                    );
                }
            }
        }
    }
    updated
}

fn get_signing_keys(info: &IssuerInfo) -> Result<(ed25519_dalek::SigningKey, ed25519_dalek::VerifyingKey), String> {
    let signing_key_hex = info
        .signing_key_hex
        .as_ref()
        .ok_or_else(|| "Signing key not available. Create a DID first.".to_string())?;

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

async fn submit_wallet_telemetry(
    state: &AppState,
    event: WalletTelemetryRequest,
) {
    let info = state.issuer_info.lock().unwrap();
    let keys = get_signing_keys(&info);
    let issuer_did = info.did.clone();
    drop(info);

    let (signing_key, verifying_key) = match keys {
        Ok(keys) => keys,
        Err(err) => {
            tracing::warn!("Skipping telemetry (missing signing keys): {}", err);
            return;
        }
    };

    if issuer_did.is_none() {
        tracing::warn!("Skipping telemetry (missing issuer DID)");
        return;
    }

    if let Err(err) = state
        .api_client
        .submit_wallet_telemetry(&event, &signing_key, &verifying_key)
        .await
    {
        tracing::warn!("Failed to submit wallet telemetry: {}", err);
    }
}

async fn ensure_acapy_configured(
    state: &AppState,
    endorser_did_override: Option<String>,
    endorser_name_override: Option<String>,
) -> Result<(), String> {
    let (did, verkey, signing_key_hex, seed, endorser_connection_id, ledger_status) = {
        let info = state.issuer_info.lock().unwrap();
        (
            info.did.clone(),
            info.verkey.clone(),
            info.signing_key_hex.clone(),
            info.seed.clone(),
            info.endorser_connection_id.clone(),
            info.ledger_status.clone(),
        )
    };

    let (did, verkey, signing_key_hex) = match (did, verkey, signing_key_hex) {
        (Some(did), Some(verkey), Some(signing_key_hex)) => (did, verkey, signing_key_hex),
        _ => return Err("DID not created yet. Create a DID first.".to_string()),
    };

    if ledger_status.as_deref() == Some("acapy_configured") {
        return Ok(());
    }

    if ledger_status.as_deref() != Some("ledger") {
        return Err("Issuer must be approved and on ledger first. Sync with ledger to check status.".to_string());
    }

    let endorser_did = endorser_did_override
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(default_endorser_did);
    let endorser_name = endorser_name_override
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(default_endorser_name);

    let seed = match seed {
        Some(seed) => seed,
        None => {
            let signing_key_bytes = hex::decode(&signing_key_hex)
                .map_err(|_| "Failed to decode signing key for seed reconstruction".to_string())?;

            match String::from_utf8(signing_key_bytes) {
                Ok(seed) if seed.len() == 32 => seed,
                _ => {
                    return Err("Issuer seed is unavailable. Recreate the issuer DID to generate a seed compatible with ACA-Py.".to_string());
                }
            }
        }
    };

    if let Err(e) = state.acapy_client.create_did_with_seed(&seed).await {
        let error_message = e.to_string();
        if !error_message.contains("already exists") {
            return Err(format!("Failed to create DID in ACA-Py wallet: {}", error_message));
        }
    }

    if let Some(ref conn_id) = endorser_connection_id {
        state
            .acapy_client
            .set_endorser_info_on_connection(conn_id, &endorser_did, Some(&endorser_name))
            .await
            .map_err(|e| format!("Failed to set endorser info: {}", e))?;

        state
            .acapy_client
            .set_public_did_with_connection(&did, conn_id)
            .await
            .map_err(|e| format!("Failed to set ACA-Py public DID: {}", e))?;
    } else {
        state
            .acapy_client
            .set_endorser_info(&endorser_did, Some(&endorser_name))
            .await
            .map_err(|e| format!("Failed to set endorser info: {}", e))?;

        state
            .acapy_client
            .set_public_did(&did)
            .await
            .map_err(|e| format!("Failed to set ACA-Py public DID: {}", e))?;
    }

    let mut info = state.issuer_info.lock().unwrap();
    info.ledger_status = Some("acapy_configured".to_string());
    info.did = Some(did);
    info.verkey = Some(verkey);

    Ok(())
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
        (Some(d), Some(v), Some(a), Some(r), Some(sk)) => {
            (d.clone(), v.clone(), a.clone(), r.clone(), sk.clone())
        }
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
    let endorser_did = form
        .as_ref()
        .and_then(|data| data.endorser_did.clone())
        .filter(|value| !value.trim().is_empty());
    let endorser_name = form
        .as_ref()
        .and_then(|data| data.endorser_name.clone())
        .filter(|value| !value.trim().is_empty());
    match ensure_acapy_configured(state.get_ref(), endorser_did, endorser_name).await {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({
            "success": true,
            "message": "ACA-Py configured. You can now create schemas and credential definitions."
        })),
        Err(error) => HttpResponse::BadRequest().json(serde_json::json!({
            "success": false,
            "error": error
        })),
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
        .unwrap_or_else(|| "Cbkb3vmwitw4DoxkitzxdJ".to_string());
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

    let (did, signing_key_hex, mut ledger_status, endorser_connection_id) = match (&info.did, &info.signing_key_hex, &info.ledger_status, &info.endorser_connection_id) {
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

    if ledger_status.as_deref() == Some("ledger") {
        if let Err(error) = ensure_acapy_configured(state.get_ref(), None, None).await {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "success": false,
                "error": error
            }));
        }
        ledger_status = Some("acapy_configured".to_string());
    }

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

    let (did, signing_key_hex, mut ledger_status, endorser_connection_id) = match (
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

    if ledger_status.as_deref() == Some("ledger") {
        if let Err(error) = ensure_acapy_configured(state.get_ref(), None, None).await {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "success": false,
                "error": error
            }));
        }
        ledger_status = Some("acapy_configured".to_string());
    }

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

async fn create_mobile_invitation(
    state: web::Data<AppState>,
    req: HttpRequest,
    form: Option<web::Json<CreateMobileInvitationRequest>>,
) -> impl Responder {
    let info = state.issuer_info.lock().unwrap();
    let issuer_did = match info.did.clone() {
        Some(did) => did,
        None => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "success": false,
                "error": "DID not created yet. Create a DID first."
            }));
        }
    };
    let alias = info.alias.clone().unwrap_or_else(|| "QZ-Issuer".to_string());
    drop(info);

    if let Err(error) = ensure_acapy_configured(state.get_ref(), None, None).await {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "success": false,
            "error": error
        }));
    }

    let label = form
        .as_ref()
        .and_then(|data| data.label.clone())
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(alias);
    let channel = form
        .as_ref()
        .and_then(|data| data.channel.clone())
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "qr".to_string());

    let invitation_result = state.acapy_client.create_oob_invitation(Some(&label)).await;
    match invitation_result {
        Ok(invitation) => {
            submit_wallet_telemetry(
                state.get_ref(),
                WalletTelemetryRequest {
                    issuer_did,
                    event_type: "wallet.invitation.created".to_string(),
                    status: "success".to_string(),
                    channel: Some(channel),
                    schema_id: None,
                    cred_def_id: None,
                    error_category: None,
                },
            )
            .await;

            let public_endpoint = derive_public_agent_url(&req);
            let invitation_payload = public_endpoint
                .as_deref()
                .map(|endpoint| rewrite_invitation_endpoint(&invitation.invitation, endpoint))
                .unwrap_or_else(|| invitation.invitation.clone());
            let rewritten_oob = encode_invitation_oob(&invitation_payload)
                .or_else(|| extract_oob_param(invitation.invitation_url.as_deref()));
            let public_invitation_url = rewritten_oob
                .as_deref()
                .and_then(|oob| public_endpoint.as_deref().and_then(|base| build_public_invitation_url_with_base(oob, base)))
                .or_else(|| invitation.invitation_url.clone());
            let app_invitation_url = rewritten_oob
                .as_deref()
                .and_then(build_app_invitation_url);

            HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "invitation": invitation_payload,
                "invitation_url": public_invitation_url,
                "app_invitation_url": app_invitation_url,
                "invitation_id": invitation.invi_msg_id,
                "oob_id": invitation.oob_id
            }))
        }
        Err(err) => {
            submit_wallet_telemetry(
                state.get_ref(),
                WalletTelemetryRequest {
                    issuer_did,
                    event_type: "wallet.invitation.created".to_string(),
                    status: "failed".to_string(),
                    channel: Some(channel),
                    schema_id: None,
                    cred_def_id: None,
                    error_category: Some("acapy_invitation_failed".to_string()),
                },
            )
            .await;

            HttpResponse::InternalServerError().json(serde_json::json!({
                "success": false,
                "error": format!("Failed to create invitation: {}", err)
            }))
        }
    }
}

async fn get_mobile_connection(
    state: web::Data<AppState>,
    query: web::Query<ConnectionLookupQuery>,
) -> impl Responder {
    let invitation_id = query.invitation_id.trim();
    if invitation_id.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "success": false,
            "error": "Invitation id is required"
        }));
    }

    match state
        .acapy_client
        .get_connection_by_invitation_id(invitation_id)
        .await
    {
        Ok(Some(connection)) => {
            if connection.state.as_deref() == Some("active") {
                if let Some(issuer_did) = state.issuer_info.lock().unwrap().did.clone() {
                    submit_wallet_telemetry(
                        state.get_ref(),
                        WalletTelemetryRequest {
                            issuer_did,
                            event_type: "wallet.connection.active".to_string(),
                            status: "success".to_string(),
                            channel: None,
                            schema_id: None,
                            cred_def_id: None,
                            error_category: None,
                        },
                    )
                    .await;
                }
            }

            HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "connection_id": connection.connection_id,
                "state": connection.state
            }))
        }
        Ok(None) => HttpResponse::Ok().json(serde_json::json!({
            "success": true,
            "state": "pending"
        })),
        Err(err) => HttpResponse::InternalServerError().json(serde_json::json!({
            "success": false,
            "error": format!("Failed to query connection: {}", err)
        })),
    }
}

async fn list_mobile_connections(
    state: web::Data<AppState>,
    query: web::Query<MobileConnectionsQuery>,
) -> impl Responder {
    let invitation_id = query
        .invitation_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());

    match state.acapy_client.list_connections(invitation_id).await {
        Ok(connections) => HttpResponse::Ok().json(serde_json::json!({
            "success": true,
            "connections": connections.iter().map(|rec| {
                serde_json::json!({
                    "connection_id": rec.connection_id,
                    "state": rec.state,
                    "their_label": rec.their_label
                })
            }).collect::<Vec<_>>()
        })),
        Err(err) => HttpResponse::InternalServerError().json(serde_json::json!({
            "success": false,
            "error": format!("Failed to list connections: {}", err)
        })),
    }
}

async fn issue_wallet_credential(
    state: web::Data<AppState>,
    form: web::Json<WalletIssuanceRequestForm>,
) -> impl Responder {
    let info = state.issuer_info.lock().unwrap();
    let issuer_did = match info.did.clone() {
        Some(did) => did,
        None => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "success": false,
                "error": "DID not created yet. Create a DID first."
            }));
        }
    };
    drop(info);

    if let Err(error) = ensure_acapy_configured(state.get_ref(), None, None).await {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "success": false,
            "error": error
        }));
    }

    let credential_values: serde_json::Value = match serde_json::from_str(&form.credential_values) {
        Ok(v) => v,
        Err(e) => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "success": false,
                "error": format!("Invalid JSON for credential values: {}", e)
            }));
        }
    };

    let map = match credential_values.as_object() {
        Some(map) => map,
        None => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "success": false,
                "error": "Credential values must be a JSON object of attribute name/value pairs"
            }));
        }
    };

    let (expected_attrs, schema_label) = {
        let info = state.issuer_info.lock().unwrap();
        let cred_def = info.cred_defs.iter().find(|def| def.cred_def_id == form.cred_def_id);
        let schema = cred_def.and_then(|def| info.schemas.iter().find(|schema| schema.schema_id == def.schema_id));
        let label = schema
            .map(|schema| format!("{} v{}", schema.name, schema.version))
            .unwrap_or_else(|| "Unknown Schema".to_string());
        let attrs = schema.map(|schema| schema.attributes.clone()).unwrap_or_default();
        (attrs, label)
    };

    if !expected_attrs.is_empty() {
        let expected_set: std::collections::BTreeSet<String> = expected_attrs.iter().cloned().collect();
        let provided_set: std::collections::BTreeSet<String> = map.keys().cloned().collect();

        if expected_set != provided_set {
            let missing: Vec<String> = expected_set.difference(&provided_set).cloned().collect();
            let extra: Vec<String> = provided_set.difference(&expected_set).cloned().collect();
            return HttpResponse::BadRequest().json(serde_json::json!({
                "success": false,
                "error": format!("Credential values must match schema attributes for {}.", schema_label),
                "expected_attributes": expected_attrs,
                "provided_attributes": map.keys().cloned().collect::<Vec<_>>(),
                "missing_attributes": missing,
                "extra_attributes": extra,
            }));
        }
    }

    let mut attributes = Vec::new();
    if !expected_attrs.is_empty() {
        for name in expected_attrs {
            if let Some(value) = map.get(&name) {
                let rendered = match value {
                    serde_json::Value::String(val) => val.clone(),
                    _ => value.to_string(),
                };
                attributes.push(CredentialAttribute {
                    name,
                    value: rendered,
                });
            }
        }
    } else {
        for (name, value) in map {
            let rendered = match value {
                serde_json::Value::String(val) => val.clone(),
                _ => value.to_string(),
            };
            attributes.push(CredentialAttribute {
                name: name.clone(),
                value: rendered,
            });
        }
    }

    let channel = form
        .channel
        .clone()
        .filter(|value| !value.trim().is_empty());

    let offer_result = state
        .acapy_client
        .send_credential_offer(&form.connection_id, &form.cred_def_id, attributes)
        .await;

    match offer_result {
        Ok(response) => {
            let (schema_id, issuer_alias) = {
                let info = state.issuer_info.lock().unwrap();
                let schema_id = info
                    .cred_defs
                    .iter()
                    .find(|def| def.cred_def_id == form.cred_def_id)
                    .map(|def| def.schema_id.clone());
                let alias = info.alias.clone();
                (schema_id, alias)
            };

            let credential_payload = serde_json::json!({
                "id": format!("urn:uuid:{}", Uuid::new_v4()),
                "schema_id": schema_id,
                "cred_def_id": form.cred_def_id.clone(),
                "issuer": issuer_alias.unwrap_or_else(|| "Issuer".to_string()),
                "issuer_did": issuer_did,
                "attributes": credential_values,
            });

            let attachment_json = serde_json::to_string(&credential_payload)
                .unwrap_or_else(|_| "{}".to_string());
            let attachment_b64 = URL_SAFE_NO_PAD.encode(attachment_json);

            let issue_message = serde_json::json!({
                "@id": Uuid::new_v4().to_string(),
                "@type": "https://didcomm.org/issue-credential/2.0/issue-credential",
                "~thread": {
                    "thid": response.cred_ex_id.clone().unwrap_or_else(|| Uuid::new_v4().to_string())
                },
                "credentials~attach": [
                    {
                        "@id": "cred-0",
                        "mime-type": "application/json",
                        "data": {
                            "base64": attachment_b64
                        }
                    }
                ]
            });

            if let Err(err) = state
                .acapy_client
                .send_connection_message(&form.connection_id, &issue_message)
                .await
            {
                tracing::warn!("Failed to send direct issue message: {}", err);
            }

            submit_wallet_telemetry(
                state.get_ref(),
                WalletTelemetryRequest {
                    issuer_did,
                    event_type: "wallet.credential.offer.sent".to_string(),
                    status: "success".to_string(),
                    channel,
                    schema_id: None,
                    cred_def_id: Some(form.cred_def_id.clone()),
                    error_category: None,
                },
            )
            .await;

            HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "cred_ex_id": response.cred_ex_id,
                "state": response.state,
                "role": response.role
            }))
        }
        Err(err) => {
            submit_wallet_telemetry(
                state.get_ref(),
                WalletTelemetryRequest {
                    issuer_did,
                    event_type: "wallet.credential.offer.sent".to_string(),
                    status: "failed".to_string(),
                    channel,
                    schema_id: None,
                    cred_def_id: Some(form.cred_def_id.clone()),
                    error_category: Some("acapy_offer_failed".to_string()),
                },
            )
            .await;

            HttpResponse::InternalServerError().json(serde_json::json!({
                "success": false,
                "error": format!("Failed to send credential offer: {}", err)
            }))
        }
    }
}

async fn qr_svg(query: web::Query<QrQuery>) -> impl Responder {
    let data = query.data.trim();
    if data.is_empty() || data.len() > 2048 {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "success": false,
            "error": "QR data is required and must be <= 2048 characters"
        }));
    }

    let code = match QrCode::new(data.as_bytes()) {
        Ok(code) => code,
        Err(_) => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "success": false,
                "error": "Unable to generate QR code"
            }));
        }
    };

    let svg = code
        .render::<svg::Color>()
        .min_dimensions(280, 280)
        .dark_color(svg::Color("#111111"))
        .light_color(svg::Color("#ffffff"))
        .build();

    HttpResponse::Ok()
        .content_type("image/svg+xml")
        .body(svg)
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
                .route("/api/mobile-invitation", web::post().to(create_mobile_invitation))
                .route("/api/mobile-connection", web::get().to(get_mobile_connection))
                .route("/api/mobile-connections", web::get().to(list_mobile_connections))
                .route("/api/issue-wallet-credential", web::post().to(issue_wallet_credential))
                .route("/api/qr", web::get().to(qr_svg))
    })
    .bind(bind_address)?
    .run()
    .await
}
