use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
}; // AES-256 GCM

/// Encrypts `plaintext` using AES-256-GCM with the given `key` and `nonce`
/// (IV).
///
/// `key`: 32 bytes  
/// `nonce`: 12 bytes  
///
/// Returns ciphertext as `Vec<u8>`.
pub fn encrypt_aes(plaintext: &[u8], key: &[u8], nonce: &[u8]) -> Result<Vec<u8>, ()> {
    if key.len() != 32 || nonce.len() != 12 {
        return Err(()); // invalid input
    }

    let key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce); // 96-bit nonce

    cipher.encrypt(nonce, plaintext).map_err(|_| ())
}

/// Decrypts `ciphertext` using AES-256-GCM with the given `key` and `nonce`
/// (IV).
///
/// Returns the original plaintext bytes on success.
pub fn decrypt_aes(ciphertext: &[u8], key: &[u8], nonce: &[u8]) -> Result<Vec<u8>, ()> {
    if key.len() != 32 || nonce.len() != 12 {
        return Err(()); // invalid input
    }

    let key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce);

    cipher.decrypt(nonce, ciphertext).map_err(|_| ())
}
