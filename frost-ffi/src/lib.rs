use std::collections::BTreeMap;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::ptr;

use frost_secp256k1_tr as frost;
use rand::rngs::OsRng;

// Type aliases for clarity
type ErrorCode = i32;

// Error codes
const SUCCESS: ErrorCode = 0;
const ERROR_NULL_POINTER: ErrorCode = -1;
const ERROR_INVALID_UTF8: ErrorCode = -2;
const ERROR_SERIALIZATION: ErrorCode = -3;
const ERROR_CRYPTO_ERROR: ErrorCode = -4;
const ERROR_INVALID_PARAMETER: ErrorCode = -5;
/// `frost_sign_aggregate_identify`: one or more signature shares do not verify; their holders are named.
const ERROR_INVALID_SIGNATURE_SHARE: ErrorCode = -6;

/// Frees a string allocated by Rust and passed to C#
#[no_mangle]
pub extern "C" fn frost_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe {
            let _ = CString::from_raw(ptr);
        }
    }
}

/// DKG Round 1: Generate commitment
/// 
/// # Parameters
/// - `participant_id`: Unique identifier for this participant (1-based)
/// - `max_signers`: Total number of participants
/// - `min_signers`: Minimum number of signers required (threshold)
/// - `out_commitment`: Output parameter for commitment (JSON string)
/// - `out_secret_package`: Output parameter for secret package (JSON string) 
/// 
/// # Returns
/// - 0 on success
/// - Negative error code on failure
#[no_mangle]
pub extern "C" fn frost_dkg_round1_generate(
    participant_id: u16,
    max_signers: u16,
    min_signers: u16,
    out_commitment: *mut *mut c_char,
    out_secret_package: *mut *mut c_char,
) -> ErrorCode {
    if out_commitment.is_null() || out_secret_package.is_null() {
        return ERROR_NULL_POINTER;
    }

    if participant_id == 0 || max_signers == 0 || min_signers == 0 || min_signers > max_signers {
        return ERROR_INVALID_PARAMETER;
    }

    // Convert to FROST Identifier
    let identifier = match frost::Identifier::try_from(participant_id) {
        Ok(id) => id,
        Err(_) => return ERROR_INVALID_PARAMETER,
    };

    // Call actual FROST DKG part1
    let (secret_package, package) = match frost::keys::dkg::part1(
        identifier,
        max_signers,
        min_signers,
        &mut OsRng,
    ) {
        Ok(result) => result,
        Err(_) => return ERROR_CRYPTO_ERROR,
    };

    // Serialize to JSON
    let commitment_json = match serde_json::to_string(&package) {
        Ok(json) => json,
        Err(_) => return ERROR_SERIALIZATION,
    };

    let secret_json = match serde_json::to_string(&secret_package) {
        Ok(json) => json,
        Err(_) => return ERROR_SERIALIZATION,
    };

    // Convert to C strings
    match (CString::new(commitment_json), CString::new(secret_json)) {
        (Ok(c_commitment), Ok(c_secret)) => {
            unsafe {
                *out_commitment = c_commitment.into_raw();
                *out_secret_package = c_secret.into_raw();
            }
            SUCCESS
        }
        _ => ERROR_SERIALIZATION,
    }
}

/// DKG Round 2: Process commitments and generate shares
/// 
/// # Parameters
/// - `secret_package`: Secret package from Round 1 (JSON string)
/// - `commitments_json`: Array of commitments from all participants (JSON object)
/// - `out_shares_json`: Output parameter for shares to distribute (JSON string)
/// - `out_round2_secret`: Output parameter for Round 2 secret package (JSON string)
/// 
/// # Returns
/// - 0 on success
/// - Negative error code on failure
#[no_mangle]
pub extern "C" fn frost_dkg_round2_generate_shares(
    secret_package: *const c_char,
    commitments_json: *const c_char,
    out_shares_json: *mut *mut c_char,
    out_round2_secret: *mut *mut c_char,
) -> ErrorCode {
    if secret_package.is_null() || commitments_json.is_null() || out_shares_json.is_null() || out_round2_secret.is_null() {
        return ERROR_NULL_POINTER;
    }

    // Parse input strings
    let secret_str = unsafe {
        match CStr::from_ptr(secret_package).to_str() {
            Ok(s) => s,
            Err(_) => return ERROR_INVALID_UTF8,
        }
    };

    let commitments_str = unsafe {
        match CStr::from_ptr(commitments_json).to_str() {
            Ok(s) => s,
            Err(_) => return ERROR_INVALID_UTF8,
        }
    };

    // Deserialize
    let round1_secret: frost::keys::dkg::round1::SecretPackage = match serde_json::from_str(secret_str) {
        Ok(pkg) => pkg,
        Err(_) => return ERROR_SERIALIZATION,
    };

    let round1_packages: BTreeMap<frost::Identifier, frost::keys::dkg::round1::Package> =
        match serde_json::from_str(commitments_str) {
            Ok(pkgs) => pkgs,
            Err(_) => return ERROR_SERIALIZATION,
        };

    // Call actual FROST DKG part2
    let (round2_secret, round2_packages) = match frost::keys::dkg::part2(round1_secret, &round1_packages) {
        Ok(result) => result,
        Err(_) => return ERROR_CRYPTO_ERROR,
    };

    // Serialize outputs
    let shares_json = match serde_json::to_string(&round2_packages) {
        Ok(json) => json,
        Err(_) => return ERROR_SERIALIZATION,
    };

    let round2_secret_json = match serde_json::to_string(&round2_secret) {
        Ok(json) => json,
        Err(_) => return ERROR_SERIALIZATION,
    };

    // Convert to C strings
    match (CString::new(shares_json), CString::new(round2_secret_json)) {
        (Ok(c_shares), Ok(c_secret)) => {
            unsafe {
                *out_shares_json = c_shares.into_raw();
                *out_round2_secret = c_secret.into_raw();
            }
            SUCCESS
        }
        _ => ERROR_SERIALIZATION,
    }
}

/// DKG Round 3: Finalize DKG and compute group public key
/// 
/// # Parameters
/// - `round2_secret_package`: Round 2 secret package
/// - `round1_packages_json`: All commitments from Round 1 (JSON object)
/// - `round2_packages_json`: Shares received from other participants (JSON object)
/// - `out_group_pubkey`: Output parameter for group public key (hex string)
/// - `out_key_package`: Output parameter for this participant's key package (JSON)
/// - `out_pubkey_package`: Output parameter for public key package (JSON)
/// 
/// # Returns
/// - 0 on success
/// - Negative error code on failure
#[no_mangle]
pub extern "C" fn frost_dkg_round3_finalize(
    round2_secret_package: *const c_char,
    round1_packages_json: *const c_char,
    round2_packages_json: *const c_char,
    out_group_pubkey: *mut *mut c_char,
    out_key_package: *mut *mut c_char,
    out_pubkey_package: *mut *mut c_char,
) -> ErrorCode {
    if round2_secret_package.is_null()
        || round1_packages_json.is_null()
        || round2_packages_json.is_null()
        || out_group_pubkey.is_null()
        || out_key_package.is_null()
        || out_pubkey_package.is_null()
    {
        return ERROR_NULL_POINTER;
    }

    // Parse input strings
    let round2_secret_str = unsafe {
        match CStr::from_ptr(round2_secret_package).to_str() {
            Ok(s) => s,
            Err(_) => return ERROR_INVALID_UTF8,
        }
    };

    let round1_str = unsafe {
        match CStr::from_ptr(round1_packages_json).to_str() {
            Ok(s) => s,
            Err(_) => return ERROR_INVALID_UTF8,
        }
    };

    let round2_str = unsafe {
        match CStr::from_ptr(round2_packages_json).to_str() {
            Ok(s) => s,
            Err(_) => return ERROR_INVALID_UTF8,
        }
    };

    // Deserialize
    let round2_secret: frost::keys::dkg::round2::SecretPackage = match serde_json::from_str(round2_secret_str) {
        Ok(pkg) => pkg,
        Err(_) => return ERROR_SERIALIZATION,
    };

    let round1_packages: BTreeMap<frost::Identifier, frost::keys::dkg::round1::Package> =
        match serde_json::from_str(round1_str) {
            Ok(pkgs) => pkgs,
            Err(_) => return ERROR_SERIALIZATION,
        };

    let round2_packages: BTreeMap<frost::Identifier, frost::keys::dkg::round2::Package> =
        match serde_json::from_str(round2_str) {
            Ok(pkgs) => pkgs,
            Err(_) => return ERROR_SERIALIZATION,
        };

    // Call actual FROST DKG part3
    let (key_package, pubkey_package) =
        match frost::keys::dkg::part3(&round2_secret, &round1_packages, &round2_packages) {
            Ok(result) => result,
            Err(_) => return ERROR_CRYPTO_ERROR,
        };

    // Extract group public key for Taproot address generation
    let group_verifying_key = pubkey_package.verifying_key();
    let pubkey_bytes = match group_verifying_key.serialize() {
        Ok(bytes) => bytes,
        Err(_) => return ERROR_SERIALIZATION,
    };
    let group_pubkey_hex = hex::encode(pubkey_bytes);

    // Serialize key packages
    let key_package_json = match serde_json::to_string(&key_package) {
        Ok(json) => json,
        Err(_) => return ERROR_SERIALIZATION,
    };

    let pubkey_package_json = match serde_json::to_string(&pubkey_package) {
        Ok(json) => json,
        Err(_) => return ERROR_SERIALIZATION,
    };

    // Convert to C strings
    match (
        CString::new(group_pubkey_hex),
        CString::new(key_package_json),
        CString::new(pubkey_package_json),
    ) {
        (Ok(c_pubkey), Ok(c_key), Ok(c_pubkey_pkg)) => {
            unsafe {
                *out_group_pubkey = c_pubkey.into_raw();
                *out_key_package = c_key.into_raw();
                *out_pubkey_package = c_pubkey_pkg.into_raw();
            }
            SUCCESS
        }
        _ => ERROR_SERIALIZATION,
    }
}

/// Signing Round 1: Generate nonce commitments
/// 
/// # Parameters
/// - `key_package_json`: This participant's key package from DKG (JSON)
/// - `out_nonce_commitment`: Output parameter for nonce commitment (JSON)
/// - `out_nonce_secret`: Output parameter for nonce secret (JSON)
/// 
/// # Returns
/// - 0 on success
/// - Negative error code on failure
#[no_mangle]
pub extern "C" fn frost_sign_round1_nonces(
    key_package_json: *const c_char,
    out_nonce_commitment: *mut *mut c_char,
    out_nonce_secret: *mut *mut c_char,
) -> ErrorCode {
    if key_package_json.is_null() || out_nonce_commitment.is_null() || out_nonce_secret.is_null() {
        return ERROR_NULL_POINTER;
    }

    // Parse input
    let key_str = unsafe {
        match CStr::from_ptr(key_package_json).to_str() {
            Ok(s) => s,
            Err(_) => return ERROR_INVALID_UTF8,
        }
    };

    // Deserialize key package
    let key_package: frost::keys::KeyPackage = match serde_json::from_str(key_str) {
        Ok(pkg) => pkg,
        Err(_) => return ERROR_SERIALIZATION,
    };

    // Generate signing nonces (returns tuple directly, not Result)
    let (nonces, commitments) = frost::round1::commit(key_package.signing_share(), &mut OsRng);

    // Serialize
    let nonce_commitment_json = match serde_json::to_string(&commitments) {
        Ok(json) => json,
        Err(_) => return ERROR_SERIALIZATION,
    };

    let nonce_secret_json = match serde_json::to_string(&nonces) {
        Ok(json) => json,
        Err(_) => return ERROR_SERIALIZATION,
    };

    // Convert to C strings
    match (
        CString::new(nonce_commitment_json),
        CString::new(nonce_secret_json),
    ) {
        (Ok(c_commitment), Ok(c_secret)) => {
            unsafe {
                *out_nonce_commitment = c_commitment.into_raw();
                *out_nonce_secret = c_secret.into_raw();
            }
            SUCCESS
        }
        _ => ERROR_SERIALIZATION,
    }
}

/// Signing Round 2: Generate signature share
/// 
/// # Parameters
/// - `key_package_json`: This participant's key package from DKG (JSON)
/// - `nonce_secret_json`: Nonce secret from Round 1 (JSON)
/// - `nonce_commitments_json`: All nonce commitments from participants (JSON object)
/// - `message_hash_hex`: Message hash to sign (32 bytes as hex string)
/// - `out_signature_share`: Output parameter for signature share (JSON)
/// 
/// # Returns
/// - 0 on success
/// - Negative error code on failure
#[no_mangle]
pub extern "C" fn frost_sign_round2_signature(
    key_package_json: *const c_char,
    nonce_secret_json: *const c_char,
    nonce_commitments_json: *const c_char,
    message_hash_hex: *const c_char,
    out_signature_share: *mut *mut c_char,
) -> ErrorCode {
    if key_package_json.is_null()
        || nonce_secret_json.is_null()
        || nonce_commitments_json.is_null()
        || message_hash_hex.is_null()
        || out_signature_share.is_null()
    {
        return ERROR_NULL_POINTER;
    }

    // Parse inputs
    let key_str = unsafe {
        match CStr::from_ptr(key_package_json).to_str() {
            Ok(s) => s,
            Err(_) => return ERROR_INVALID_UTF8,
        }
    };

    let nonce_str = unsafe {
        match CStr::from_ptr(nonce_secret_json).to_str() {
            Ok(s) => s,
            Err(_) => return ERROR_INVALID_UTF8,
        }
    };

    let commitments_str = unsafe {
        match CStr::from_ptr(nonce_commitments_json).to_str() {
            Ok(s) => s,
            Err(_) => return ERROR_INVALID_UTF8,
        }
    };

    let message_str = unsafe {
        match CStr::from_ptr(message_hash_hex).to_str() {
            Ok(s) => s,
            Err(_) => return ERROR_INVALID_UTF8,
        }
    };

    // Deserialize
    let key_package: frost::keys::KeyPackage = match serde_json::from_str(key_str) {
        Ok(pkg) => pkg,
        Err(_) => return ERROR_SERIALIZATION,
    };

    let nonces: frost::round1::SigningNonces = match serde_json::from_str(nonce_str) {
        Ok(n) => n,
        Err(_) => return ERROR_SERIALIZATION,
    };

    let commitments: BTreeMap<frost::Identifier, frost::round1::SigningCommitments> =
        match serde_json::from_str(commitments_str) {
            Ok(c) => c,
            Err(_) => return ERROR_SERIALIZATION,
        };

    // Decode message hash
    let message_bytes = match hex::decode(message_str) {
        Ok(bytes) => bytes,
        Err(_) => return ERROR_INVALID_PARAMETER,
    };

    if message_bytes.len() != 32 {
        return ERROR_INVALID_PARAMETER;
    }

    // Create signing package (returns struct directly, not Result)
    let signing_package = frost::SigningPackage::new(commitments, &message_bytes);

    // Generate signature share.
    // The key_package already has one BIP-341 tweak from post_dkg.
    // The current DeriveTaprootAddress (FIND-024) uses the FROST group key directly
    // (no additional tweak), so regular sign() is correct.
    let signature_share = match frost::round2::sign(&signing_package, &nonces, &key_package) {
        Ok(share) => share,
        Err(_) => return ERROR_CRYPTO_ERROR,
    };

    // Serialize
    let signature_share_json = match serde_json::to_string(&signature_share) {
        Ok(json) => json,
        Err(_) => return ERROR_SERIALIZATION,
    };

    // Convert to C string
    match CString::new(signature_share_json) {
        Ok(c_share) => {
            unsafe {
                *out_signature_share = c_share.into_raw();
            }
            SUCCESS
        }
        Err(_) => ERROR_SERIALIZATION,
    }
}

/// Aggregate signature shares into final Schnorr signature
/// 
/// # Parameters
/// - `signature_shares_json`: All signature shares from participants (JSON object)
/// - `nonce_commitments_json`: All nonce commitments from Round 1 (JSON object)
/// - `message_hash_hex`: Message hash that was signed (32 bytes as hex string)
/// - `pubkey_package_json`: Public key package from DKG (JSON)
/// - `out_schnorr_signature`: Output parameter for final Schnorr signature (hex string)
/// 
/// # Returns
/// - 0 on success
/// - Negative error code on failure
#[no_mangle]
pub extern "C" fn frost_sign_aggregate(
    signature_shares_json: *const c_char,
    nonce_commitments_json: *const c_char,
    message_hash_hex: *const c_char,
    pubkey_package_json: *const c_char,
    out_schnorr_signature: *mut *mut c_char,
) -> ErrorCode {
    if signature_shares_json.is_null()
        || nonce_commitments_json.is_null()
        || message_hash_hex.is_null()
        || pubkey_package_json.is_null()
        || out_schnorr_signature.is_null()
    {
        return ERROR_NULL_POINTER;
    }

    // Parse inputs
    let shares_str = unsafe {
        match CStr::from_ptr(signature_shares_json).to_str() {
            Ok(s) => s,
            Err(_) => return ERROR_INVALID_UTF8,
        }
    };

    let commitments_str = unsafe {
        match CStr::from_ptr(nonce_commitments_json).to_str() {
            Ok(s) => s,
            Err(_) => return ERROR_INVALID_UTF8,
        }
    };

    let message_str = unsafe {
        match CStr::from_ptr(message_hash_hex).to_str() {
            Ok(s) => s,
            Err(_) => return ERROR_INVALID_UTF8,
        }
    };

    let pubkey_str = unsafe {
        match CStr::from_ptr(pubkey_package_json).to_str() {
            Ok(s) => s,
            Err(_) => return ERROR_INVALID_UTF8,
        }
    };

    // Deserialize
    let signature_shares: BTreeMap<frost::Identifier, frost::round2::SignatureShare> =
        match serde_json::from_str(shares_str) {
            Ok(shares) => shares,
            Err(_) => return ERROR_SERIALIZATION,
        };

    let commitments: BTreeMap<frost::Identifier, frost::round1::SigningCommitments> =
        match serde_json::from_str(commitments_str) {
            Ok(c) => c,
            Err(_) => return ERROR_SERIALIZATION,
        };

    let pubkey_package: frost::keys::PublicKeyPackage = match serde_json::from_str(pubkey_str) {
        Ok(pkg) => pkg,
        Err(_) => return ERROR_SERIALIZATION,
    };

    // Decode message hash
    let message_bytes = match hex::decode(message_str) {
        Ok(bytes) => bytes,
        Err(_) => return ERROR_INVALID_PARAMETER,
    };

    if message_bytes.len() != 32 {
        return ERROR_INVALID_PARAMETER;
    }

    // Create signing package (returns struct directly, not Result)
    let signing_package = frost::SigningPackage::new(commitments, &message_bytes);

    // Aggregate signature shares into a final Schnorr signature.
    // The key_package already has one BIP-341 tweak from post_dkg.
    // The current DeriveTaprootAddress (FIND-024) uses the FROST group key directly
    // (no additional tweak), so regular aggregate() is correct.
    let group_signature = match frost::aggregate(&signing_package, &signature_shares, &pubkey_package) {
        Ok(sig) => sig,
        Err(_) => return ERROR_CRYPTO_ERROR,
    };

    // Serialize as hex (Schnorr signatures are 64 bytes)
    let sig_bytes = match group_signature.serialize() {
        Ok(bytes) => bytes,
        Err(_) => return ERROR_SERIALIZATION,
    };
    let schnorr_sig_hex = hex::encode(sig_bytes);

    // Convert to C string
    match CString::new(schnorr_sig_hex) {
        Ok(c_sig) => {
            unsafe {
                *out_schnorr_signature = c_sig.into_raw();
            }
            SUCCESS
        }
        Err(_) => ERROR_SERIALIZATION,
    }
}

/// Like `frost_sign_aggregate`, but when shares do not verify it names their holders instead of returning a bare
/// error: every share is checked against its holder's verifying share (`CheaterDetection::AllCheaters`), the call
/// returns `ERROR_INVALID_SIGNATURE_SHARE`, and `out_culprits` receives a JSON array of the holders' identifiers (in
/// the same encoding as the keys of `signature_shares_json`). On success `out_culprits` is left null. A coordinator
/// can then leave those holders out of its next session (RFC 9591, sections 5.4 and 7).
#[no_mangle]
pub extern "C" fn frost_sign_aggregate_identify(
    signature_shares_json: *const c_char,
    nonce_commitments_json: *const c_char,
    message_hash_hex: *const c_char,
    pubkey_package_json: *const c_char,
    out_schnorr_signature: *mut *mut c_char,
    out_culprits: *mut *mut c_char,
) -> ErrorCode {
    if signature_shares_json.is_null()
        || nonce_commitments_json.is_null()
        || message_hash_hex.is_null()
        || pubkey_package_json.is_null()
        || out_schnorr_signature.is_null()
        || out_culprits.is_null()
    {
        return ERROR_NULL_POINTER;
    }
    unsafe {
        *out_culprits = ptr::null_mut();
    }

    let read = |p: *const c_char| unsafe { CStr::from_ptr(p).to_str().map(|s| s.to_owned()) };
    let (shares_str, commitments_str, message_str, pubkey_str) = match (
        read(signature_shares_json),
        read(nonce_commitments_json),
        read(message_hash_hex),
        read(pubkey_package_json),
    ) {
        (Ok(a), Ok(b), Ok(c), Ok(d)) => (a, b, c, d),
        _ => return ERROR_INVALID_UTF8,
    };

    let signature_shares: BTreeMap<frost::Identifier, frost::round2::SignatureShare> =
        match serde_json::from_str(&shares_str) {
            Ok(shares) => shares,
            Err(_) => return ERROR_SERIALIZATION,
        };
    let commitments: BTreeMap<frost::Identifier, frost::round1::SigningCommitments> =
        match serde_json::from_str(&commitments_str) {
            Ok(c) => c,
            Err(_) => return ERROR_SERIALIZATION,
        };
    let pubkey_package: frost::keys::PublicKeyPackage = match serde_json::from_str(&pubkey_str) {
        Ok(pkg) => pkg,
        Err(_) => return ERROR_SERIALIZATION,
    };
    let message_bytes = match hex::decode(&message_str) {
        Ok(bytes) if bytes.len() == 32 => bytes,
        _ => return ERROR_INVALID_PARAMETER,
    };

    let signing_package = frost::SigningPackage::new(commitments, &message_bytes);
    let group_signature = match frost_core::aggregate_custom(
        &signing_package,
        &signature_shares,
        &pubkey_package,
        frost_core::CheaterDetection::AllCheaters,
    ) {
        Ok(sig) => sig,
        Err(frost_core::Error::InvalidSignatureShare { culprits }) => {
            let json = match serde_json::to_string(&culprits) {
                Ok(j) => j,
                Err(_) => return ERROR_SERIALIZATION,
            };
            return match CString::new(json) {
                Ok(c) => {
                    unsafe {
                        *out_culprits = c.into_raw();
                    }
                    ERROR_INVALID_SIGNATURE_SHARE
                }
                Err(_) => ERROR_SERIALIZATION,
            };
        }
        Err(_) => return ERROR_CRYPTO_ERROR,
    };

    let sig_bytes = match group_signature.serialize() {
        Ok(bytes) => bytes,
        Err(_) => return ERROR_SERIALIZATION,
    };
    match CString::new(hex::encode(sig_bytes)) {
        Ok(c_sig) => {
            unsafe {
                *out_schnorr_signature = c_sig.into_raw();
            }
            SUCCESS
        }
        Err(_) => ERROR_SERIALIZATION,
    }
}

/// Get library version
#[no_mangle]
pub extern "C" fn frost_get_version(out_version: *mut *mut c_char) -> ErrorCode {
    if out_version.is_null() {
        return ERROR_NULL_POINTER;
    }

    let version = "0.3.0-frost-real";
    match CString::new(version) {
        Ok(c_version) => {
            unsafe {
                *out_version = c_version.into_raw();
            }
            SUCCESS
        }
        Err(_) => ERROR_SERIALIZATION,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        let mut version_ptr: *mut c_char = ptr::null_mut();
        let result = frost_get_version(&mut version_ptr as *mut *mut c_char);
        assert_eq!(result, SUCCESS);
        assert!(!version_ptr.is_null());
        
        let version_str = unsafe {
            CStr::from_ptr(version_ptr).to_str().unwrap()
        };
        assert!(version_str.contains("frost-real"));
        
        unsafe {
            frost_free_string(version_ptr);
        }
    }

    #[test]
    fn test_dkg_round1() {
        let mut commitment_ptr: *mut c_char = ptr::null_mut();
        let mut secret_ptr: *mut c_char = ptr::null_mut();
        
        let result = frost_dkg_round1_generate(
            1,
            3,
            2,
            &mut commitment_ptr as *mut *mut c_char,
            &mut secret_ptr as *mut *mut c_char,
        );
        
        assert_eq!(result, SUCCESS);
        assert!(!commitment_ptr.is_null());
        assert!(!secret_ptr.is_null());
        
        unsafe {
            frost_free_string(commitment_ptr);
            frost_free_string(secret_ptr);
        }
    }

    /// Signs with a 2-of-3 dealer key. `swap` replaces the share of the given signers with another signer's share:
    /// well-formed, but not theirs.
    fn aggregate_with(swap: &[usize]) -> (ErrorCode, Option<String>, Option<String>, Vec<frost::Identifier>) {
        let mut rng = OsRng;
        let (shares, pubkeys) =
            frost::keys::generate_with_dealer(3, 2, frost::keys::IdentifierList::Default, &mut rng).unwrap();
        let keys: Vec<(frost::Identifier, frost::keys::KeyPackage)> = shares
            .into_iter()
            .map(|(id, s)| (id, frost::keys::KeyPackage::try_from(s).unwrap()))
            .collect();
        let message = [7u8; 32];
        let mut nonces = BTreeMap::new();
        let mut commitments = BTreeMap::new();
        for (id, key) in &keys {
            let (n, c) = frost::round1::commit(key.signing_share(), &mut rng);
            nonces.insert(*id, n);
            commitments.insert(*id, c);
        }
        let package = frost::SigningPackage::new(commitments.clone(), &message);
        let mut sig_shares = BTreeMap::new();
        for (id, key) in &keys {
            sig_shares.insert(*id, frost::round2::sign(&package, &nonces[id], key).unwrap());
        }
        let ids: Vec<frost::Identifier> = keys.iter().map(|(id, _)| *id).collect();
        for &i in swap {
            let other = sig_shares[&ids[(i + 1) % ids.len()]];
            sig_shares.insert(ids[i], other);
        }
        let c = |v: String| CString::new(v).unwrap();
        let shares_json = c(serde_json::to_string(&sig_shares).unwrap());
        let commitments_json = c(serde_json::to_string(&commitments).unwrap());
        let message_hex = c(hex::encode(message));
        let pubkey_json = c(serde_json::to_string(&pubkeys).unwrap());
        let mut sig_ptr: *mut c_char = ptr::null_mut();
        let mut culprits_ptr: *mut c_char = ptr::null_mut();
        let code = frost_sign_aggregate_identify(
            shares_json.as_ptr(),
            commitments_json.as_ptr(),
            message_hex.as_ptr(),
            pubkey_json.as_ptr(),
            &mut sig_ptr,
            &mut culprits_ptr,
        );
        let take = |p: *mut c_char| {
            (!p.is_null()).then(|| {
                let s = unsafe { CStr::from_ptr(p).to_str().unwrap().to_owned() };
                frost_free_string(p);
                s
            })
        };
        (code, take(sig_ptr), take(culprits_ptr), ids)
    }

    #[test]
    fn honest_shares_aggregate_and_name_nobody() {
        let (code, sig, culprits, _) = aggregate_with(&[]);
        assert_eq!(code, SUCCESS);
        assert_eq!(sig.unwrap().len(), 128);
        assert!(culprits.is_none());
    }

    #[test]
    fn a_wrong_share_is_refused_and_its_holder_named() {
        let (code, sig, culprits, ids) = aggregate_with(&[1]);
        assert_eq!(code, ERROR_INVALID_SIGNATURE_SHARE);
        assert!(sig.is_none());
        let named: Vec<frost::Identifier> = serde_json::from_str(&culprits.unwrap()).unwrap();
        assert_eq!(named, vec![ids[1]]);
    }

    #[test]
    fn every_wrong_share_is_named() {
        let (code, _, culprits, ids) = aggregate_with(&[0, 2]);
        assert_eq!(code, ERROR_INVALID_SIGNATURE_SHARE);
        let mut named: Vec<frost::Identifier> = serde_json::from_str(&culprits.unwrap()).unwrap();
        named.sort();
        assert_eq!(named, vec![ids[0], ids[2]]);
    }
}
