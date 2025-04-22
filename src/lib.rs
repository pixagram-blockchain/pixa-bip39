use wasm_bindgen::prelude::*;
use bip39::{Language, Mnemonic};
use sha2::{Sha256, Digest};
use bs58;
use scrypt::{scrypt, Params};
use rand::rngs::OsRng;
use rand::RngCore;
use unicode_normalization::UnicodeNormalization;

#[wasm_bindgen]
pub fn generate_mnemonic(word_count: u32, lang: &str) -> Result<String, JsValue> {
    let language = match lang.to_lowercase().as_str() {
        "english" => Language::English,
        "czech" => Language::Czech,
        "french" => Language::French,
        "italian" => Language::Italian,
        "japanese" => Language::Japanese,
        "korean" => Language::Korean,
        "portuguese" => Language::Portuguese,
        "spanish" => Language::Spanish,
        _ => return Err(JsValue::from_str("Unsupported language. Supported: english, czech, french, italian, japanese, korean, portuguese, spanish.")),
    };

    let entropy_bytes = match word_count {
        12 => generate_entropy(16),  // 128 bits
        15 => generate_entropy(20),  // 160 bits
        18 => generate_entropy(24),  // 192 bits
        21 => generate_entropy(28),  // 224 bits
        24 => generate_entropy(32),  // 256 bits
        _ => return Err(JsValue::from_str("Invalid word count (must be 12, 15, 18, 21, or 24)")),
    };

    let mnemonic = Mnemonic::from_entropy_in(language, &entropy_bytes)
        .map_err(|_| JsValue::from_str("Failed to generate mnemonic"))?;

    Ok(mnemonic.to_string())
}

fn generate_entropy(length: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; length];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

#[wasm_bindgen]
pub fn mnemonic_to_base58_master_key(mnemonic: &str, passphrase: &str) -> Result<String, JsValue> {
    let mnemonic = Mnemonic::parse_normalized(mnemonic)
        .map_err(|_| JsValue::from_str("Invalid mnemonic"))?;

    let normalized_passphrase = passphrase.nfkd().collect::<String>();
    let seed = mnemonic.to_seed(&normalized_passphrase);

    // Scrypt parameters (log_n = 17, r = 16, p = 2, output length = 32 bytes)
    let params = Params::new(17, 16, 2, 32)
        .map_err(|_| JsValue::from_str("Invalid scrypt params"))?;

    let salt = format!("{}-{}", "pixa-bip39", normalized_passphrase);
    let mut derived_key = [0u8; 32];
    scrypt(&seed, salt.as_bytes(), &params, &mut derived_key)
        .map_err(|_| JsValue::from_str("Scrypt failed"))?;

    // WIF encoding: prepend 0x80, append 0x01 + 4-byte checksum (double SHA256)
    let mut extended = vec![0x80];
    extended.extend_from_slice(&derived_key);
    extended.push(0x01);
    let checksum = Sha256::digest(&Sha256::digest(&extended));
    extended.extend_from_slice(&checksum[0..4]);

    let base58_wif = bs58::encode(extended).into_string();
    Ok(base58_wif)
}

