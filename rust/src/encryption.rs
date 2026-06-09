// AES-256-GCM at-rest encryption for inbox payloads. Byte-compatible with the
// Node reader (lib/inbox-crypto.ts) so what this server encrypts, getMail /
// the webmail / IMAP decrypt.
//
// Wire format: "<iv_hex>:<tag_hex>:<ct_hex>"
//   iv  = 12 random bytes (GCM nonce)
//   tag = 16-byte GCM auth tag
//   ct  = AES-256-GCM ciphertext of the UTF-8 plaintext
//
// Key: ENCRYPTION_MASTER_KEY_V1 (64 hex chars = 32 bytes). Per-user key is
// HKDF-SHA256(master, salt, info="cybertemp:inbox-encryption:v1"); a null/empty
// salt uses the master key directly (anonymous inboxes / legacy rows).
//
// KEY-GATED: if the env var is unset, is_configured() is false and the caller
// stores plaintext exactly as before — so this module is inert until you opt in.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use hkdf::Hkdf;
use once_cell::sync::Lazy;
use rand::RngCore;
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::Mutex;

pub const KEY_VERSION: i32 = 1;
const HKDF_INFO: &[u8] = b"cybertemp:inbox-encryption:v1";

fn load_master() -> Option<[u8; 32]> {
    let hex_str = std::env::var("ENCRYPTION_MASTER_KEY_V1").ok()?;
    let bytes = hex::decode(hex_str.trim()).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut k = [0u8; 32];
    k.copy_from_slice(&bytes);
    Some(k)
}

static MASTER: Lazy<Option<[u8; 32]>> = Lazy::new(load_master);
static USER_KEYS: Lazy<Mutex<HashMap<String, [u8; 32]>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
const USER_KEY_CACHE_MAX: usize = 1024;

/// Whether a valid master key is configured. False → caller stores plaintext.
pub fn is_configured() -> bool {
    MASTER.is_some()
}

/// Derive (and cache) the 32-byte AES key for a user's salt. None/empty salt
/// returns the master key directly. Returns None only when unconfigured or the
/// salt hex is malformed.
pub fn derive_key(salt_hex: Option<&str>) -> Option<[u8; 32]> {
    let master = (*MASTER)?;
    let salt_hex = match salt_hex {
        Some(s) if !s.is_empty() => s,
        _ => return Some(master),
    };
    if let Some(k) = USER_KEYS.lock().unwrap().get(salt_hex) {
        return Some(*k);
    }
    let salt = hex::decode(salt_hex).ok()?;
    let hk = Hkdf::<Sha256>::new(Some(&salt), &master);
    let mut okm = [0u8; 32];
    hk.expand(HKDF_INFO, &mut okm).ok()?;
    let mut cache = USER_KEYS.lock().unwrap();
    if cache.len() >= USER_KEY_CACHE_MAX {
        if let Some(k) = cache.keys().next().cloned() {
            cache.remove(&k);
        }
    }
    cache.insert(salt_hex.to_string(), okm);
    Some(okm)
}

/// Encrypt one field with a pre-derived key → "iv:tag:ct" hex. Empty input
/// passes through as empty (matches the Node side — no point sealing blanks).
#[allow(dead_code)]
pub fn encrypt_with(key: &[u8; 32], plaintext: &str) -> String {
    if plaintext.is_empty() {
        return String::new();
    }
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let mut iv = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut iv);
    let nonce = Nonce::from_slice(&iv);
    match cipher.encrypt(nonce, plaintext.as_bytes()) {
        Ok(mut ct_tag) => {
            // RustCrypto's aes-gcm returns ciphertext||tag; split the trailing
            // 16-byte tag so the layout matches Node's separate iv:tag:ct.
            let split = ct_tag.len().saturating_sub(16);
            let tag = ct_tag.split_off(split);
            format!(
                "{}:{}:{}",
                hex::encode(iv),
                hex::encode(&tag),
                hex::encode(&ct_tag)
            )
        }
        // AES-GCM encryption of a normal string effectively never errors; if it
        // somehow does, fall back to plaintext (caller must then mark the row
        // NOT encrypted — see seal()).
        Err(_) => plaintext.to_string(),
    }
}

/// Decrypt one "iv:tag:ct" field with a pre-derived key. Returns the value
/// unchanged if it isn't our format, or "" on an auth/format failure (never
/// leak ciphertext).
#[allow(dead_code)]
pub fn decrypt_with(key: &[u8; 32], value: &str) -> String {
    let parts: Vec<&str> = value.split(':').collect();
    if parts.len() != 3 {
        return value.to_string();
    }
    let iv = match hex::decode(parts[0]) {
        Ok(v) => v,
        Err(_) => return value.to_string(),
    };
    let tag = match hex::decode(parts[1]) {
        Ok(v) => v,
        Err(_) => return value.to_string(),
    };
    let ct = match hex::decode(parts[2]) {
        Ok(v) => v,
        Err(_) => return value.to_string(),
    };
    if iv.len() != 12 {
        return value.to_string();
    }
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(&iv);
    let mut ct_tag = ct;
    ct_tag.extend_from_slice(&tag);
    match cipher.decrypt(nonce, ct_tag.as_ref()) {
        Ok(pt) => String::from_utf8_lossy(&pt).to_string(),
        Err(_) => String::new(),
    }
}
