use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;
use serde_wasm_bindgen;
use bip39::{Language, Mnemonic};
use sha2::{Sha256, Digest};
use bs58;
use scrypt::{scrypt, Params};
use rand::rngs::OsRng;
use rand::RngCore;
use unicode_normalization::UnicodeNormalization;
use js_sys::Promise;

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
        12 => generate_entropy(16), // 128 bits
        15 => generate_entropy(20), // 160 bits
        18 => generate_entropy(24), // 192 bits
        21 => generate_entropy(28), // 224 bits
        24 => generate_entropy(32), // 256 bits
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
pub fn mnemonic_to_base58_master_key(mnemonic: &str, passphrase: &str) -> Promise {
    let mnemonic_str = mnemonic.to_string();
    let passphrase_str = passphrase.to_string();
    
    future_to_promise(async move {
        let result = generate_master_key_internal(&mnemonic_str, &passphrase_str).await;
        match result {
            Ok(key) => Ok(JsValue::from_str(&key)),
            Err(e) => Err(e),
        }
    })
}

async fn generate_master_key_internal(mnemonic: &str, passphrase: &str) -> Result<String, JsValue> {
    let mnemonic = Mnemonic::parse_normalized(mnemonic)
        .map_err(|_| JsValue::from_str("Invalid mnemonic"))?;

    let normalized_passphrase = passphrase.nfkd().collect::<String>();
    
    // BIP39 standard: mnemonic.to_seed() already incorporates the passphrase
    let seed = mnemonic.to_seed(&normalized_passphrase);

    // Reduced scrypt parameters for better web performance
    // log_n = 14 (16,384 iterations), r = 8, p = 1 - much faster while still secure
    let params = Params::new(14, 8, 1, 32)
        .map_err(|_| JsValue::from_str("Invalid scrypt params"))?;

    // Use a fixed salt - the passphrase is already incorporated in the seed
    let salt = b"pixa-bip39";
    let mut derived_key = [0u8; 32];
    
    // Yield control back to the browser periodically during scrypt
    scrypt(&seed, salt, &params, &mut derived_key)
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

#[derive(serde::Serialize)]
struct WordMatch {
    word: String,
    score: u32,
}

fn levenshtein_distance(s1: &str, s2: &str) -> u32 {
    let len1 = s1.chars().count();
    let len2 = s2.chars().count();
    
    if len1 == 0 { return len2 as u32; }
    if len2 == 0 { return len1 as u32; }
    
    let mut matrix = vec![vec![0u32; len2 + 1]; len1 + 1];
    
    // Initialize first row and column
    for i in 0..=len1 { matrix[i][0] = i as u32; }
    for j in 0..=len2 { matrix[0][j] = j as u32; }
    
    let s1_chars: Vec<char> = s1.chars().collect();
    let s2_chars: Vec<char> = s2.chars().collect();
    
    for i in 1..=len1 {
        for j in 1..=len2 {
            let cost = if s1_chars[i-1] == s2_chars[j-1] { 0 } else { 1 };
            matrix[i][j] = std::cmp::min(
                std::cmp::min(matrix[i-1][j] + 1, matrix[i][j-1] + 1),
                matrix[i-1][j-1] + cost
            );
        }
    }
    
    matrix[len1][len2]
}

fn fuzzy_score(query: &str, word: &str) -> u32 {
    let query_lower = query.to_lowercase();
    let word_lower = word.to_lowercase();
    
    // Exact match gets highest score
    if query_lower == word_lower {
        return 1000;
    }
    
    // Prefix match gets high score
    if word_lower.starts_with(&query_lower) {
        return 900 - (word_lower.len() - query_lower.len()) as u32;
    }
    
    // Contains match gets medium score
    if word_lower.contains(&query_lower) {
        let index = word_lower.find(&query_lower).unwrap();
        return 500 - index as u32;
    }
    
    // Fuzzy match based on edit distance
    let distance = levenshtein_distance(&query_lower, &word_lower);
    let max_len = std::cmp::max(query_lower.len(), word_lower.len()) as u32;
    
    // Only consider words with reasonable edit distance
    if distance > max_len / 2 + 1 {
        return 0;
    }
    
    // Score inversely proportional to edit distance
    300 - (distance * 10)
}

#[wasm_bindgen]
pub fn search_mnemonic_words(query: &str, lang: &str, max_length: usize) -> Result<JsValue, JsValue> {
    if query.trim().is_empty() {
        return Err(JsValue::from_str("Query must be at least 1 character"));
    }

    let language = match lang.to_lowercase().as_str() {
        "english" => Language::English,
        "czech" => Language::Czech,
        "french" => Language::French,
        "italian" => Language::Italian,
        "japanese" => Language::Japanese,
        "korean" => Language::Korean,
        "portuguese" => Language::Portuguese,
        "spanish" => Language::Spanish,
        _ => return Err(JsValue::from_str("Unsupported language")),
    };

    let mut matches: Vec<WordMatch> = language
        .word_list()
        .iter()
        .filter_map(|word| {
            let score = fuzzy_score(query, word);
            if score > 0 {
                Some(WordMatch {
                    word: word.to_string(),
                    score,
                })
            } else {
                None
            }
        })
        .collect();

    // Sort by score (highest first), then alphabetically
    matches.sort_by(|a, b| {
        b.score.cmp(&a.score)
            .then_with(|| a.word.cmp(&b.word))
    });

    // Take only the requested number of results
    matches.truncate(max_length);

    // Extract just the words for the response
    let words: Vec<&str> = matches.iter().map(|m| m.word.as_str()).collect();

    Ok(serde_wasm_bindgen::to_value(&words)
        .map_err(|_| JsValue::from_str("Serialization failed"))?)
}
