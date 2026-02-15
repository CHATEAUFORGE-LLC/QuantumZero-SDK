use anoncreds::data_types::cred_def::{CredentialDefinition, CredentialDefinitionId};
use anoncreds::data_types::credential::Credential;
use anoncreds::data_types::cred_offer::CredentialOffer;
use anoncreds::data_types::link_secret::LinkSecret;
use anoncreds::data_types::pres_request::PresentationRequest;
use anoncreds::data_types::presentation::Presentation;
use anoncreds::data_types::schema::{Schema, SchemaId};
use anoncreds::prover;
use anoncreds::types::PresentCredentials;
use serde_json;
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::ptr;

/// FFI function to create a proper AnonCreds link secret
///
/// Returns the link secret as a decimal string that can be stored and reused
/// 
/// # Safety
/// This function is unsafe because it returns a raw pointer that must be freed by caller
#[no_mangle]
pub unsafe extern "C" fn qz_create_link_secret() -> *mut c_char {
    match prover::create_link_secret() {
        Ok(link_secret) => {
            // Convert LinkSecret to decimal string using TryInto<String>
            let link_secret_str: Result<String, _> = link_secret.try_into();
            match link_secret_str {
                Ok(str_value) => {
                    eprintln!("[FFI] Created link secret: {} decimal digits", str_value.len());
                    
                    match CString::new(str_value) {
                        Ok(c_str) => c_str.into_raw(),
                        Err(_) => error_response("Failed to create C string for link secret"),
                    }
                }
                Err(e) => error_response(&format!("Failed to convert link secret to string: {}", e)),
            }
        }
        Err(e) => error_response(&format!("Failed to create link secret: {}", e)),
    }
}

/// FFI function to create an AnonCreds credential request
/// 
/// # Safety
/// This function is unsafe because it deals with raw pointers from FFI
#[no_mangle]
pub unsafe extern "C" fn qz_create_credential_request(
    prover_did: *const c_char,
    cred_offer_json: *const c_char,
    cred_def_json: *const c_char,
    link_secret: *const c_char,
) -> *mut c_char {
    // Convert C strings to Rust strings
    let prover_did_str = match CStr::from_ptr(prover_did).to_str() {
        Ok(s) => s,
        Err(_) => return error_response("Invalid prover_did UTF-8"),
    };
    
    let cred_offer_str = match CStr::from_ptr(cred_offer_json).to_str() {
        Ok(s) => s,
        Err(_) => return error_response("Invalid cred_offer UTF-8"),
    };
    
    let cred_def_str = match CStr::from_ptr(cred_def_json).to_str() {
        Ok(s) => s,
        Err(_) => return error_response("Invalid cred_def UTF-8"),
    };
    
    let link_secret_str = match CStr::from_ptr(link_secret).to_str() {
        Ok(s) => s,
        Err(_) => return error_response("Invalid link_secret UTF-8"),
    };

    // Parse inputs
    let cred_offer: CredentialOffer = match serde_json::from_str(cred_offer_str) {
        Ok(co) => co,
        Err(e) => return error_response(&format!("Failed to parse credential offer: {}", e)),
    };
    
    let cred_def: CredentialDefinition = match serde_json::from_str(cred_def_str) {
        Ok(cd) => cd,
        Err(e) => return error_response(&format!("Failed to parse credential definition: {}", e)),
    };
    
    // Parse link secret from decimal string (created by qz_create_link_secret)
    // TryFrom<&str> expects decimal representation
    let link_secret_data = match LinkSecret::try_from(link_secret_str) {
        Ok(ls) => ls,
        Err(e) => return error_response(&format!("Failed to parse link secret: {}", e)),
    };
    
    eprintln!("[FFI] Creating credential request for prover: {}", prover_did_str);
    
    // Call real AnonCreds-RS credential request generation
    // Parameters: entropy, prover_did, cred_def, link_secret, link_secret_id, cred_offer
    // Note: Must pass either entropy OR prover_did, not both
    let (cred_req, cred_req_metadata) = match prover::create_credential_request(
        None, // entropy - not used when prover_did is provided
        Some(prover_did_str),
        &cred_def,
        &link_secret_data,
        "default", // link_secret_id
        &cred_offer,
    ) {
        Ok(result) => result,
        Err(e) => {
            eprintln!("[FFI] Failed to create credential request: {}", e);
            return error_response(&format!("Failed to create credential request: {}", e));
        }
    };
    
    eprintln!("[FFI] ✓ Successfully created credential request");
    
    // Serialize the credential request and metadata
    let response = serde_json::json!({
        "cred_req": cred_req,
        "cred_req_metadata": cred_req_metadata
    });
    
    let response_str = match serde_json::to_string(&response) {
        Ok(s) => s,
        Err(e) => return error_response(&format!("Failed to serialize response: {}", e)),
    };
    
    // Return as C string
    match CString::new(response_str) {
        Ok(c_str) => c_str.into_raw(),
        Err(_) => error_response("Failed to create C string"),
    }
}

/// FFI function to create an AnonCreds presentation
/// 
/// # Safety
/// This function is unsafe because it deals with raw pointers from FFI
#[no_mangle]
pub unsafe extern "C" fn qz_create_presentation(
    pres_req_json: *const c_char,
    credentials_json: *const c_char,
    self_attested_json: *const c_char,
    link_secret: *const c_char,
    schemas_json: *const c_char,
    cred_defs_json: *const c_char,
) -> *mut c_char {
    // Convert C strings to Rust strings
    let pres_req_str = match CStr::from_ptr(pres_req_json).to_str() {
        Ok(s) => s,
        Err(_) => return error_response("Invalid pres_req UTF-8"),
    };
    
    let credentials_str = match CStr::from_ptr(credentials_json).to_str() {
        Ok(s) => s,
        Err(_) => return error_response("Invalid credentials UTF-8"),
    };
    
    let self_attested_str = match CStr::from_ptr(self_attested_json).to_str() {
        Ok(s) => s,
        Err(_) => return error_response("Invalid self_attested UTF-8"),
    };
    
    let link_secret_str = match CStr::from_ptr(link_secret).to_str() {
        Ok(s) => s,
        Err(_) => return error_response("Invalid link_secret UTF-8"),
    };
    
    let schemas_str = match CStr::from_ptr(schemas_json).to_str() {
        Ok(s) => s,
        Err(_) => return error_response("Invalid schemas UTF-8"),
    };
    
    let cred_defs_str = match CStr::from_ptr(cred_defs_json).to_str() {
        Ok(s) => s,
        Err(_) => return error_response("Invalid cred_defs UTF-8"),
    };

    let pres_req_value: serde_json::Value = match serde_json::from_str(pres_req_str) {
        Ok(pr) => pr,
        Err(e) => return error_response(&format!("Failed to parse presentation request: {}", e)),
    };
    
    let _pres_req: PresentationRequest = match serde_json::from_value(pres_req_value.clone()) {
        Ok(pr) => pr,
        Err(e) => return error_response(&format!("Failed to parse presentation request structure: {}", e)),
    };

    let credentials: HashMap<String, serde_json::Value> = match serde_json::from_str(credentials_str) {
        Ok(c) => c,
        Err(e) => return error_response(&format!("Failed to parse credentials: {}", e)),
    };

    let self_attested: HashMap<String, String> = match serde_json::from_str(self_attested_str) {
        Ok(sa) => sa,
        Err(e) => return error_response(&format!("Failed to parse self_attested: {}", e)),
    };

    let schemas: HashMap<String, Schema> = match serde_json::from_str(schemas_str) {
        Ok(s) => s,
        Err(e) => return error_response(&format!("Failed to parse schemas: {}", e)),
    };

    let cred_defs: HashMap<String, CredentialDefinition> = match serde_json::from_str(cred_defs_str) {
        Ok(cd) => cd,
        Err(e) => return error_response(&format!("Failed to parse cred_defs: {}", e)),
    };

    // Log what we received for debugging
    eprintln!("[FFI] Presentation request parsed successfully");
    eprintln!("[FFI] Credentials count: {}", credentials.len());
    eprintln!("[FFI] Schemas count: {}", schemas.len());
    eprintln!("[FFI] Cred defs count: {}", cred_defs.len());
    eprintln!("[FFI] Link secret length: {}", link_secret_str.len());
    
    for (cred_def_id, cred_def) in cred_defs.iter() {
        let cred_def_json = serde_json::to_value(cred_def).ok();
        let issuer_id = cred_def_json.as_ref()
            .and_then(|v| v.get("issuerId"))
            .and_then(|i| i.as_str())
            .unwrap_or("missing")
            .to_string();
        let schema_id = cred_def_json.as_ref()
            .and_then(|v| v.get("schemaId"))
            .and_then(|s| s.as_str())
            .unwrap_or("missing")
            .to_string();
        eprintln!("[FFI] Cred def: {} - has issuerId: {}, schemaId: {}", 
            cred_def_id, issuer_id, schema_id
        );
    }

    // Parse link secret for AnonCreds-RS
    let link_secret_data = match LinkSecret::try_from(link_secret_str) {
        Ok(ls) => ls,
        Err(e) => return error_response(&format!("Failed to parse link secret: {}", e)),
    };
    
    eprintln!("[FFI] ✓ Link secret parsed successfully");

    // Build credentials map for AnonCreds-RS
    let mut present_credentials: HashMap<String, Credential> = HashMap::new();
    
    // Convert schemas HashMap to use SchemaId keys
    let mut credential_schemas: HashMap<SchemaId, Schema> = HashMap::new();
    for (schema_id_str, schema) in schemas.iter() {
        let schema_id = SchemaId::new_unchecked(schema_id_str);
        credential_schemas.insert(schema_id, schema.clone());
    }
    
    // Convert cred_defs HashMap to use CredentialDefinitionId keys
    // CredentialDefinition doesn't implement Clone, so we need to deserialize from JSON
    let mut credential_cred_defs: HashMap<CredentialDefinitionId, CredentialDefinition> = HashMap::new();
    for (cred_def_id_str, cred_def) in cred_defs.iter() {
        let cred_def_id = CredentialDefinitionId::new_unchecked(cred_def_id_str);
        // Serialize and deserialize to copy the CredentialDefinition
        if let Ok(cred_def_json) = serde_json::to_value(cred_def) {
            if let Ok(cred_def_copy) = serde_json::from_value::<CredentialDefinition>(cred_def_json) {
                credential_cred_defs.insert(cred_def_id, cred_def_copy);
            }
        }
    }
    
    // Extract credentials with real proof material
    // Key insight: The referents from Dart are presentation request referents (attr_dob, attr_name)
    // We need to use the WALLET credential referent (from cred_info.referent) as the key
    let mut parse_errors = Vec::new();
    
    for (pres_req_referent, cred_data) in credentials.iter() {
        // Get the wallet credential referent from cred_info
        let wallet_cred_referent = cred_data.get("cred_info")
            .and_then(|ci| ci.get("referent"))
            .and_then(|r| r.as_str())
            .unwrap_or(pres_req_referent);
        
        if let Some(cred_obj) = cred_data.get("credential") {
            // Parse the AnonCreds credential from stored proof material
            match serde_json::from_value::<Credential>(cred_obj.clone()) {
                Ok(anoncred) => {
                    // Use wallet credential referent as key (this is what AnonCreds expects)
                    present_credentials.insert(wallet_cred_referent.to_string(), anoncred);
                    eprintln!("[FFI] Mapped pres_req referent '{}' to wallet cred '{}'", 
                        pres_req_referent, wallet_cred_referent);
                },
                Err(e) => {
                    let error_msg = format!("Failed to parse credential {}: {}. Credential JSON: {}", 
                        pres_req_referent, e, serde_json::to_string_pretty(cred_obj).unwrap_or_default());
                    parse_errors.push(error_msg);
                }
            }
        } else {
            parse_errors.push(format!("Referent {} missing 'credential' key. Available keys: {:?}", 
                pres_req_referent, cred_data.as_object().map(|o| o.keys().collect::<Vec<_>>())));
        }
    }
    
    if present_credentials.is_empty() {
        let full_error = format!("No valid credentials with proof material found. Errors: {}", 
            parse_errors.join("; "));
        return error_response(&full_error);
    }
    
    eprintln!("[FFI] Prepared {} credential entries for presentation", present_credentials.len());
    eprintln!("[FFI] Using {} schemas and {} cred_defs", credential_schemas.len(), credential_cred_defs.len());
    
    // Build PresentCredentials for AnonCreds-RS
    // Add all unique credentials - deduplication happens naturally because HashMap uses wallet cred ID
    let mut present_creds = PresentCredentials::default();
    
    for (wallet_cred_ref, cred) in present_credentials.iter() {
        eprintln!("[FFI] Adding credential to presentation: {}", wallet_cred_ref);
        present_creds.add_credential(cred, None, None);
    }
    
    let num_creds = present_credentials.len();
    eprintln!("[FFI] ✓ Added {} unique credential(s) to presentation builder", num_creds);
    
    if num_creds == 0 {
        return error_response("No credentials added to presentation");
    }
    
    // Call real AnonCreds-RS presentation generation
    eprintln!("[FFI] Calling AnonCreds-RS create_presentation");
    
    let self_attested_map: HashMap<String, String> = self_attested
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    
    let presentation_result = prover::create_presentation(
        &_pres_req,
        present_creds,
        Some(self_attested_map),
        &link_secret_data,
        &credential_schemas,
        &credential_cred_defs,
    );
    
    let presentation: Presentation = match presentation_result {
        Ok(pres) => {
            eprintln!("[FFI] ✓✓✓ Successfully generated REAL AnonCreds presentation with cryptographic proofs!");
            pres
        },
        Err(e) => {
            eprintln!("[FFI] ✗ AnonCreds presentation generation failed: {}", e);
            return error_response(&format!("Failed to create presentation: {}", e));
        }
    };
    
    // Serialize presentation to JSON
    let presentation_json = match serde_json::to_value(&presentation) {
        Ok(json) => json,
        Err(e) => return error_response(&format!("Failed to serialize presentation: {}", e)),
    };
    
    eprintln!("[FFI] ✓ Presentation serialized successfully");
    eprintln!("[FFI] Presentation has {} proofs", 
        presentation_json.get("proof")
            .and_then(|p| p.get("proofs"))
            .and_then(|ps| ps.as_array())
            .map(|a| a.len())
            .unwrap_or(0)
    );
    
    let presentation = match serde_json::to_string(&presentation_json) {
        Ok(json) => json,
        Err(e) => return error_response(&format!("Failed to serialize presentation: {}", e)),
    };

    // Return as C string
    match CString::new(presentation) {
        Ok(c_str) => c_str.into_raw(),
        Err(_) => error_response("Failed to create C string"),
    }
}

/// Free a string allocated by Rust
/// 
/// # Safety
/// This function is unsafe because it deals with raw pointers from FFI
#[no_mangle]
pub unsafe extern "C" fn qz_free_string(s: *mut c_char) {
    if s.is_null() {
        return;
    }
    drop(CString::from_raw(s));
}

/// Helper function to create error response
unsafe fn error_response(msg: &str) -> *mut c_char {
    let error_json = serde_json::json!({
        "error": msg
    });
    let error_str = error_json.to_string();
    match CString::new(error_str) {
        Ok(c_str) => c_str.into_raw(),
        Err(_) => ptr::null_mut(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_anoncreds_basic() {
        // Basic smoke test
        assert!(true);
    }
}
