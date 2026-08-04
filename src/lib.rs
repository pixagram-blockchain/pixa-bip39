//! Pixagram wallet key generation (Rust → WASM).
//!
//! Public API — identical to the previous version:
//! - [`generate_mnemonic`] — BIP39 mnemonic from platform-CSPRNG entropy
//! - [`mnemonic_to_base58_master_key`] — mnemonic (+ passphrase) → Promise<WIF string>
//! - [`search_mnemonic_words`] — fuzzy wordlist autocomplete for the restore UI
//!
//! Key facts, in order of importance:
//! - The master key is encoded as a **Graphene/Hive-style WIF**: `0x80 || key ||
//!   double-SHA256[..4]`, 37 bytes, always starting with `'5'`. This is what
//!   `@pixagram/dpixa` (`NETWORK_ID = [0x80]`, `PrivateKey.fromString`) accepts.
//!   There is deliberately **no** Bitcoin "compressed" `0x01` suffix.
//! - The WIF *string* is consensus: dpixa derives the four role keys as
//!   `sha256(username + role + masterWIF)` via `PrivateKey.fromLogin`. Any change
//!   to the encoding or to `MASTER_KEY_DOMAIN` re-derives every role key. The
//!   pinned test vectors at the bottom exist to make such a change impossible to
//!   ship by accident.
//! - Entropy comes exclusively from the platform CSPRNG (`crypto.getRandomValues`
//!   under wasm32 via getrandom's `js` backend). The build fails without that
//!   backend, the call fails closed (error, never degraded bytes), and a
//!   continuous self-test refuses degenerate output. Chain keys must only ever
//!   originate here — never from user-chosen passwords.
//!
//! Build: `wasm-pack build --target bundler` (or `--target web`).

use bip39::{Language, Mnemonic};
use js_sys::Promise;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;
use zeroize::Zeroizing;

// ---------------------------------------------------------------------------
// Errors (static strings; converted to JsValue only at the wasm boundary)
// ---------------------------------------------------------------------------

const ERR_LANG: &str =
    "Unsupported language. Supported: english, czech, french, italian, japanese, korean, portuguese, spanish.";
const ERR_WORD_COUNT: &str = "Invalid word count (must be 12, 15, 18, 21, or 24)";
const ERR_RNG_UNAVAILABLE: &str = "Secure random source unavailable";
const ERR_RNG_DEGENERATE: &str =
    "Secure random source failed its self-test; refusing to generate keys";
const ERR_BAD_MNEMONIC: &str = "Invalid mnemonic";
const ERR_KEY_RANGE: &str = "Derived key out of curve range (regenerate mnemonic)";
const ERR_EMPTY_QUERY: &str = "Query must be at least 1 character";

fn parse_language(lang: &str) -> Result<Language, &'static str> {
    match lang.to_lowercase().as_str() {
        "english" => Ok(Language::English),
        "czech" => Ok(Language::Czech),
        "french" => Ok(Language::French),
        "italian" => Ok(Language::Italian),
        "japanese" => Ok(Language::Japanese),
        "korean" => Ok(Language::Korean),
        "portuguese" => Ok(Language::Portuguese),
        "spanish" => Ok(Language::Spanish),
        _ => Err(ERR_LANG),
    }
}

// ---------------------------------------------------------------------------
// Entropy
// ---------------------------------------------------------------------------

fn entropy_len_for(word_count: u32) -> Result<usize, &'static str> {
    Ok(match word_count {
        12 => 16, // 128 bits
        15 => 20, // 160 bits
        18 => 24, // 192 bits
        21 => 28, // 224 bits
        24 => 32, // 256 bits
        _ => return Err(ERR_WORD_COUNT),
    })
}

/// Draws `len` bytes from the platform CSPRNG, fail-closed.
///
/// - `OsRng` routes through `getrandom` to `crypto.getRandomValues` on
///   wasm32 (or the OS CSPRNG natively). If the backend is missing the crate
///   does not compile; if the call errors we return `Err`, never weak bytes.
/// - Continuous self-test (FIPS 140-2 style tripwire): two independent draws
///   must be non-zero and different. This costs one extra syscall and catches
///   the "stubbed / stuck RNG" failure class — the class behind the 2026
///   Coldcard sweep — in exotic embeddings that shim `crypto`.
///   False-trip probability is ≤ 2⁻¹²⁸.
fn secure_entropy(len: usize) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    let mut a = Zeroizing::new(vec![0u8; len]);
    let mut b = Zeroizing::new(vec![0u8; len]);
    OsRng
        .try_fill_bytes(a.as_mut_slice())
        .map_err(|_| ERR_RNG_UNAVAILABLE)?;
    OsRng
        .try_fill_bytes(b.as_mut_slice())
        .map_err(|_| ERR_RNG_UNAVAILABLE)?;

    let degenerate = a.iter().all(|&x| x == 0)
        || b.iter().all(|&x| x == 0)
        || a.as_slice() == b.as_slice();
    if degenerate {
        return Err(ERR_RNG_DEGENERATE);
    }
    Ok(a) // `b` is wiped on drop
}

// ---------------------------------------------------------------------------
// Mnemonic generation
// ---------------------------------------------------------------------------

fn core_generate_mnemonic(word_count: u32, lang: &str) -> Result<String, &'static str> {
    let language = parse_language(lang)?;
    let entropy = secure_entropy(entropy_len_for(word_count)?)?;

    let mnemonic = Mnemonic::from_entropy_in(language, entropy.as_slice())
        .map_err(|_| "Failed to generate mnemonic")?;

    // The phrase necessarily crosses to JS as a plain string (it must be shown
    // to the user); the raw entropy buffer above is wiped on drop.
    Ok(mnemonic.to_string())
}

// ---------------------------------------------------------------------------
// Master key derivation
// ---------------------------------------------------------------------------

/// Domain-separation tag for the seed → master-key reduction.
/// CONSENSUS VALUE — changing it changes every derived wallet.
const MASTER_KEY_DOMAIN: &[u8] = b"pixa-master-key-v1";

/// secp256k1 group order `n`, big-endian.
const SECP256K1_N: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36,
    0x41, 0x41,
];

/// Validates that a 32-byte value is a valid secp256k1 private scalar:
/// non-zero and strictly less than the curve order `n`. Big-endian byte
/// comparison equals numeric comparison here.
fn is_valid_secp256k1_scalar(key: &[u8; 32]) -> bool {
    let is_zero = key.iter().all(|&b| b == 0);
    let is_lt_n = key.as_slice() < SECP256K1_N.as_slice();
    !is_zero && is_lt_n
}

fn core_master_wif(mnemonic: &str, passphrase: &str) -> Result<Zeroizing<String>, &'static str> {
    // `Mnemonic::parse` NFKD-normalizes the input and auto-detects the language
    // among the enabled wordlists, so user-typed restores in composed Unicode
    // form (Japanese dakuten, accented French/Spanish…) are accepted. `trim`
    // forgives copy-paste padding.
    let mnemonic = Mnemonic::parse(mnemonic.trim()).map_err(|_| ERR_BAD_MNEMONIC)?;

    // BIP39 `to_seed` runs PBKDF2-HMAC-SHA512 (2048 rounds) with salt
    // "mnemonic" + passphrase and NFKD-normalizes the passphrase internally
    // (verified in rust-bip39; requires the default `std` feature set).
    let seed = Zeroizing::new(mnemonic.to_seed(passphrase));

    // Reduce the 64-byte BIP39 seed to a 32-byte master key with domain
    // separation. The domain string prevents this key from colliding with any
    // other value derived from the same seed, and the version suffix leaves
    // room for future migrations.
    //
    // Scrypt was removed deliberately: the seed is already stretched by 2048
    // PBKDF2-HMAC-SHA512 rounds and carries the full mnemonic entropy
    // (128–256 bits). SHA256 caps the key at 256 bits with no practical
    // entropy loss; secp256k1's own ECDLP ceiling is ~128 bits regardless.
    let mut hasher = Sha256::new();
    hasher.update(MASTER_KEY_DOMAIN);
    hasher.update(seed.as_slice());
    let master_key: Zeroizing<[u8; 32]> = Zeroizing::new(hasher.finalize().into());

    // Sanity-check the scalar (probability of failure ~2⁻¹²⁸). Reject rather
    // than reduce mod n — rejection has zero bias and the caller simply
    // regenerates.
    if !is_valid_secp256k1_scalar(&master_key) {
        return Err(ERR_KEY_RANGE);
    }

    // Graphene/Hive WIF, exactly as dpixa's `decodePrivate` expects:
    //   0x80 || 32-byte key || first 4 bytes of double-SHA256
    // = 37 bytes, base58 → always starts with '5'.
    // No Bitcoin "compressed pubkey" 0x01 suffix: Graphene chains use the bare
    // form, and dpixa rejects the 38-byte variant (`isValidSecretKey` on 33
    // bytes). This string is fed verbatim to `PrivateKey.fromLogin` as the
    // password from which all four role keys derive — treat it as consensus.
    let mut extended = Zeroizing::new(Vec::with_capacity(37));
    extended.push(0x80);
    extended.extend_from_slice(master_key.as_slice());
    let checksum = Sha256::digest(Sha256::digest(extended.as_slice()));
    extended.extend_from_slice(&checksum[0..4]);

    Ok(Zeroizing::new(bs58::encode(extended.as_slice()).into_string()))
}

// ---------------------------------------------------------------------------
// Wordlist search (restore-UI autocomplete)
// ---------------------------------------------------------------------------

struct WordMatch {
    word: &'static str,
    score: u32,
}

/// Two-row Levenshtein distance over chars (O(min-memory), same result as the
/// full matrix).
fn levenshtein(a: &[char], b: &[char]) -> u32 {
    if a.is_empty() {
        return b.len() as u32;
    }
    if b.is_empty() {
        return a.len() as u32;
    }
    let mut prev: Vec<u32> = (0..=b.len() as u32).collect();
    let mut curr = vec![0u32; b.len() + 1];
    for (i, &ca) in a.iter().enumerate() {
        curr[0] = i as u32 + 1;
        for (j, &cb) in b.iter().enumerate() {
            let cost = if ca == cb { 0 } else { 1 };
            curr[j + 1] = (prev[j + 1] + 1).min(curr[j] + 1).min(prev[j] + cost);
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[b.len()]
}

/// Scoring: exact 1000 > prefix (900 − extra chars) > contains (500 − char
/// offset) > edit distance (300 − 10·d, cut off at maxlen/2 + 1). All counts
/// are in chars, not bytes, so CJK wordlists score correctly. BIP39 wordlists
/// are lowercase by spec, so only the query is case-folded.
fn fuzzy_score(query_lower: &str, qchars: &[char], word: &'static str) -> u32 {
    if query_lower == word {
        return 1000;
    }
    if word.starts_with(query_lower) {
        let extra = word.chars().count().saturating_sub(qchars.len()) as u32;
        return 900u32.saturating_sub(extra);
    }
    if let Some(byte_idx) = word.find(query_lower) {
        let char_idx = word[..byte_idx].chars().count() as u32;
        return 500u32.saturating_sub(char_idx);
    }

    let wchars: Vec<char> = word.chars().collect();
    let max_len = qchars.len().max(wchars.len()) as u32;
    let threshold = max_len / 2 + 1;
    // |len(a) − len(b)| is a lower bound on the distance: cheap early out.
    let len_diff = qchars.len().abs_diff(wchars.len()) as u32;
    if len_diff > threshold {
        return 0;
    }
    let distance = levenshtein(qchars, &wchars);
    if distance > threshold {
        return 0;
    }
    300u32.saturating_sub(distance * 10)
}

/// Runs entirely locally by design: queries are candidate seed words and must
/// never be logged or sent anywhere.
fn core_search(
    query: &str,
    lang: &str,
    max_length: usize,
) -> Result<Vec<&'static str>, &'static str> {
    let query = query.trim();
    if query.is_empty() {
        return Err(ERR_EMPTY_QUERY);
    }
    let language = parse_language(lang)?;

    let query_lower = query.to_lowercase();
    let qchars: Vec<char> = query_lower.chars().collect();

    let mut matches: Vec<WordMatch> = language
        .word_list()
        .iter()
        .filter_map(|&word| {
            let score = fuzzy_score(&query_lower, &qchars, word);
            (score > 0).then(|| WordMatch { word, score })
        })
        .collect();

    // Highest score first, then alphabetical for stable ordering.
    matches.sort_by(|a, b| b.score.cmp(&a.score).then_with(|| a.word.cmp(b.word)));
    matches.truncate(max_length);

    Ok(matches.into_iter().map(|m| m.word).collect())
}

// ---------------------------------------------------------------------------
// WASM boundary — public API, unchanged signatures
// ---------------------------------------------------------------------------

#[wasm_bindgen]
pub fn generate_mnemonic(word_count: u32, lang: &str) -> Result<String, JsValue> {
    core_generate_mnemonic(word_count, lang).map_err(JsValue::from_str)
}

/// Same API as before: returns a Promise resolving to the WIF string.
///
/// Honesty note: there is no await point inside, so the ~10 ms of PBKDF2 run
/// synchronously when the microtask fires. If main-thread blocking ever
/// matters, instantiate this module inside a Web Worker — the Promise shape
/// here means callers won't change either way.
#[wasm_bindgen]
pub fn mnemonic_to_base58_master_key(mnemonic: &str, passphrase: &str) -> Promise {
    // Owned, self-wiping copies for the 'static future.
    let mnemonic = Zeroizing::new(mnemonic.to_string());
    let passphrase = Zeroizing::new(passphrase.to_string());

    future_to_promise(async move {
        core_master_wif(mnemonic.as_str(), passphrase.as_str())
            .map(|wif| JsValue::from_str(wif.as_str()))
            .map_err(JsValue::from_str)
    })
}

#[wasm_bindgen]
pub fn search_mnemonic_words(
    query: &str,
    lang: &str,
    max_length: usize,
) -> Result<JsValue, JsValue> {
    let words = core_search(query, lang, max_length).map_err(JsValue::from_str)?;
    serde_wasm_bindgen::to_value(&words).map_err(|_| JsValue::from_str("Serialization failed"))
}

// ---------------------------------------------------------------------------
// Tests (pure core — run with plain `cargo test` on the host)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    /// Pipeline vector pinned 2026-08-04, cross-checked against the official
    /// BIP39/Trezor seed vectors and dpixa 1.5.4's `decodePrivate`.
    /// If this test ever fails, the change is a CONSENSUS BREAK: every role
    /// key derives from this exact string. Do not "fix" the expected value.
    #[test]
    fn pinned_master_wif_vector() {
        let wif = core_master_wif(TEST_MNEMONIC, "").unwrap();
        assert_eq!(
            wif.as_str(),
            "5J4K9nt7JHheDYmsUC28yeb6K8gR2FxgD8KRZRibFAYcCuyxLvo"
        );
    }

    #[test]
    fn wif_is_graphene_shape() {
        let wif = core_master_wif(TEST_MNEMONIC, "").unwrap();
        assert!(wif.starts_with('5'), "Graphene WIF must start with '5'");
        let raw = bs58::decode(wif.as_str()).into_vec().unwrap();
        assert_eq!(raw.len(), 37, "0x80 + 32-byte key + 4-byte checksum, no 0x01 flag");
        assert_eq!(raw[0], 0x80);
        let chk = Sha256::digest(Sha256::digest(&raw[..33]));
        assert_eq!(&raw[33..], &chk[..4]);
        assert!(is_valid_secp256k1_scalar(raw[1..33].try_into().unwrap()));
    }

    #[test]
    fn passphrase_changes_key() {
        let a = core_master_wif(TEST_MNEMONIC, "").unwrap();
        let b = core_master_wif(TEST_MNEMONIC, "TREZOR").unwrap();
        assert_ne!(a.as_str(), b.as_str());
    }

    #[test]
    fn restore_tolerates_padding_whitespace() {
        let padded = format!("  {}  \n", TEST_MNEMONIC);
        assert_eq!(
            core_master_wif(&padded, "").unwrap().as_str(),
            core_master_wif(TEST_MNEMONIC, "").unwrap().as_str()
        );
    }

    #[test]
    fn rejects_invalid_mnemonic() {
        assert!(core_master_wif("not a real mnemonic phrase at all", "").is_err());
    }

    #[test]
    fn scalar_range_check() {
        assert!(!is_valid_secp256k1_scalar(&[0u8; 32]), "zero rejected");
        assert!(!is_valid_secp256k1_scalar(&SECP256K1_N), "n rejected");
        assert!(!is_valid_secp256k1_scalar(&[0xFF; 32]), ">n rejected");
        let mut n_minus_1 = SECP256K1_N;
        n_minus_1[31] -= 1;
        assert!(is_valid_secp256k1_scalar(&n_minus_1), "n-1 accepted");
        assert!(is_valid_secp256k1_scalar(&[1u8; 32]));
    }

    #[test]
    fn mnemonic_generation_all_word_counts() {
        for wc in [12u32, 15, 18, 21, 24] {
            let phrase = core_generate_mnemonic(wc, "english").unwrap();
            assert_eq!(phrase.split_whitespace().count(), wc as usize);
            // Every generated phrase must round-trip through derivation.
            core_master_wif(&phrase, "").unwrap();
        }
        assert!(core_generate_mnemonic(13, "english").is_err());
        assert!(core_generate_mnemonic(12, "klingon").is_err());
    }

    #[test]
    fn generated_mnemonics_are_unique() {
        let a = core_generate_mnemonic(24, "english").unwrap();
        let b = core_generate_mnemonic(24, "english").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn entropy_lengths_and_self_test() {
        for len in [16, 20, 24, 28, 32] {
            let e = secure_entropy(len).unwrap();
            assert_eq!(e.len(), len);
        }
    }

    #[test]
    fn search_ordering_and_edges() {
        let words = core_search("aban", "english", 5).unwrap();
        assert_eq!(words[0], "abandon");
        let exact = core_search("zoo", "english", 5).unwrap();
        assert_eq!(exact[0], "zoo");
        assert!(core_search("   ", "english", 5).is_err());
        assert!(core_search("zoo", "klingon", 5).is_err());
        assert!(core_search("zoo", "english", 0).unwrap().is_empty());
        // Multi-byte path: char-based scoring on the Japanese wordlist.
        let jp = core_search("あい", "japanese", 3).unwrap();
        assert!(!jp.is_empty() && jp[0].starts_with("あい"));
    }
}
