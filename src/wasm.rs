use serde_wasm_bindgen::{self, from_value, to_value};
use wasm_bindgen::{prelude::*, JsValue};

use crate::delay_encryption::{
    decrypt as decryptor, encrypt as encryptor, PublicKey, SecretKey, SkdeParams,
};

#[wasm_bindgen]
pub fn encrypt(
    skde_params: JsValue,
    message: JsValue,
    encryption_key: JsValue,
) -> Result<String, JsValue> {
    let skde_params: SkdeParams = from_value(skde_params).unwrap();

    let message: String = message.as_string().unwrap();

    let encryption_key: PublicKey = from_value(encryption_key).unwrap();

    let ciphertext = encryptor(&skde_params, &message, &encryption_key);

    to_value(&ciphertext).unwrap()
}

#[wasm_bindgen]
pub fn decrypt(
    skde_params: JsValue,
    ciphertext: &str,
    decryption_key: JsValue,
) -> Result<String, JsValue> {
    // Deserialize skde_params from JsValue to SkdeParams
    let skde_params: SkdeParams = from_value(skde_params).unwrap();

    // Deserialize decryption_key from JsValue to SecretKey
    let decryption_key: SecretKey = from_value(decryption_key).unwrap();

    let message = decryptor(&skde_params, ciphertext, &decryption_key).unwrap();

    to_value(&message).unwrap()
}
