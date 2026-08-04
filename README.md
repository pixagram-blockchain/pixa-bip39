# pixa-bip39

WASM-ready BIP-39 mnemonic and master-key generator for [Pixagram](https://pixagram.com) wallets — CSPRNG-only entropy, Graphene-compatible WIF output, consensus-pinned test vectors.

`pixa_bip39` runs entirely in the browser (Rust → WebAssembly) and does exactly three things:

1. **Generate** BIP-39 mnemonics (12–24 words, 8 languages) from the platform CSPRNG.
2. **Derive** the Pixagram master key from a mnemonic (+ optional passphrase) and encode it as a Hive-style WIF (`5…`), ready to feed [`@pixagram/dpixa`](https://www.npmjs.com/package/@pixagram/dpixa).
3. **Autocomplete** wordlist entries for the restore UI, fully offline.

It was hardened against the *stuck-RNG* failure class — the one behind the 2026 Coldcard sweep: entropy can only come from the platform CSPRNG, the build fails without that backend, the call fails closed, and a continuous self-test refuses degenerate output.

---

## Build

Requires Rust **1.85+** (edition 2024) and [`wasm-pack`](https://rustwasm.github.io/wasm-pack/).

```bash
git clone https://github.com/pixagram-blockchain/pixa-bip39
cd pixa-bip39

wasm-pack build --release --target bundler   # webpack / vite / rollup → ./pkg
# or
wasm-pack build --release --target web       # plain <script type="module">
```

Run the test suite (native, no wasm runtime needed):

```bash
cargo test
```

---

## Quick start

```js
import {
  generate_mnemonic,
  mnemonic_to_base58_master_key,
  search_mnemonic_words,
} from "pixa_bip39";
// --target web instead:
//   import init, { … } from "./pkg/pixa_bip39.js"; await init();

// 1. New wallet — show the phrase ONCE, have the user write it down.
const mnemonic = generate_mnemonic(24, "english");

// 2. Master key — a 51-character Graphene WIF, always starting with '5'.
const masterWif = await mnemonic_to_base58_master_key(mnemonic, "");

// 3. Restore UI autocomplete (offline — never log these queries).
const hits = search_mnemonic_words("aba", "english", 5); // ["abandon", …]
```

### Deriving the account keys with dpixa

The master WIF plays the role of the classic Graphene *master password*: dpixa
derives the four role keys as `sha256(username + role + masterWif)`.

```js
import { PrivateKey } from "@pixagram/dpixa";

const owner   = PrivateKey.fromLogin(username, masterWif, "owner");
const active  = PrivateKey.fromLogin(username, masterWif, "active");
const posting = PrivateKey.fromLogin(username, masterWif, "posting");
const memo    = PrivateKey.fromLogin(username, masterWif, "memo");

posting.createPublic("PIX").toString(); // "PIX7…" — for account_create

await client.broadcast.vote(
  { voter: username, author, permlink, weight: 10000 },
  posting
);
```

> ⚠️ **Consensus warning** — the WIF *string* is key material downstream.
> Changing the derivation domain (`pixa-master-key-v1`), the WIF encoding, or
> anything in between re-derives **every role key** of every wallet. The
> [pinned test vector](#test-vectors) exists so this cannot happen by accident:
> if `pinned_master_wif_vector` fails, do not "fix" the expected value.

---

## API

All three functions keep stable signatures; errors are thrown (or the Promise
rejects) with the plain-string messages listed below.

### `generate_mnemonic(word_count, lang) → string`

Returns a space-joined BIP-39 mnemonic.

| `word_count` | entropy | checksum | total bits encoded |
|---:|---:|---:|---:|
| 12 | 128 | 4 | 132 |
| 15 | 160 | 5 | 165 |
| 18 | 192 | 6 | 198 |
| 21 | 224 | 7 | 231 |
| 24 | 256 | 8 | 264 |

`lang` ∈ `english · czech · french · italian · japanese · korean · portuguese · spanish`
(official BIP-39 wordlists; case-insensitive). Prefer `english` when
cross-wallet portability matters — it is the only list universally supported —
and default to **24 words** for maximum margin.

Throws: `Invalid word count (must be 12, 15, 18, 21, or 24)` ·
`Unsupported language. …` · `Secure random source unavailable` ·
`Secure random source failed its self-test; refusing to generate keys`

### `mnemonic_to_base58_master_key(mnemonic, passphrase) → Promise<string>`

Derives the Pixagram master key and resolves to its WIF encoding.

```text
mnemonic (+ passphrase, NFKD)
   │  PBKDF2-HMAC-SHA512 × 2048, salt "mnemonic" + passphrase   (BIP-39)
   ▼
64-byte seed
   │  SHA256("pixa-master-key-v1" ‖ seed)  +  secp256k1 range check
   ▼
32-byte master key
   │  0x80 ‖ key ‖ doubleSHA256[..4]  →  base58
   ▼
WIF "5…"  ──PrivateKey.fromLogin(name, wif, role)──►  owner / active / posting / memo
```

- Input is trimmed and NFKD-normalized, so pasted or user-typed mnemonics in
  composed Unicode form (Japanese dakuten, accented wordlists) are accepted;
  the language is auto-detected.
- Output is the **bare Graphene WIF** (37 bytes: version `0x80`, key, 4-byte
  double-SHA256 checksum). There is deliberately **no** Bitcoin "compressed"
  `0x01` suffix — dpixa's `PrivateKey.fromString` rejects that 38-byte form.
- The function returns a Promise for API stability, but contains no await
  point: the ~10 ms of PBKDF2 run when the microtask fires. If main-thread
  blocking ever matters, instantiate the module inside a Web Worker — callers
  don't change.

Rejects: `Invalid mnemonic` ·
`Derived key out of curve range (regenerate mnemonic)` (probability ≈ 2⁻¹²⁸)

### `search_mnemonic_words(query, lang, max_length) → string[]`

Fuzzy autocomplete over a wordlist, for tap-to-complete restore UIs.
Scoring: exact (1000) > prefix (900 − extra chars) > substring (500 − char
offset) > edit distance (300 − 10·d, cut off at ⌈len/2⌉+1). Ties break
alphabetically; counts are per character, so CJK lists score correctly.

Runs entirely locally by design: queries are candidate **seed words** — never
log them, never send them anywhere.

Throws: `Query must be at least 1 character` · `Unsupported language. …`

---

## Security model

**Entropy.** `OsRng` → `getrandom` → `crypto.getRandomValues` (or the OS
CSPRNG natively). Three properties, in order of importance:

- *Compile-time enforced* — the wasm32 target does not build without the
  `getrandom/js` backend, so a "forgot to wire the RNG" state cannot exist.
- *Fail-closed* — an RNG error returns an error; degraded or zeroed bytes are
  never used.
- *Continuous self-test* — two independent draws must be non-zero and
  different before one is used (FIPS 140-2-style tripwire, false-trip
  probability ≤ 2⁻¹²⁸). This catches stubbed/stuck RNGs in exotic embeddings
  that shim `crypto`.

**Brute-force resistance.** The keyspace is the mnemonic entropy: 2¹²⁸
(12 words) up to 2²⁵⁶ (24 words), each guess costing 2048 PBKDF2-HMAC-SHA512
rounds. Even the 12-word floor matches secp256k1's own ~2¹²⁸ ECDLP ceiling;
24 words adds margin against seed-space search. An optional BIP-39 passphrase
extends the keyspace further and yields a distinct wallet per passphrase.
The SHA256 reduction is domain-separated (`pixa-master-key-v1`) and versioned;
out-of-range scalars are *rejected*, never reduced mod *n*, so the
distribution carries zero bias.

**Memory hygiene.** Entropy buffers, the 64-byte seed, the master key, the WIF
payload, and the internal mnemonic/passphrase copies are wiped on drop
(`zeroize`). The unavoidable boundary: strings returned to JavaScript (the
phrase must be displayed) cannot be wiped from the JS heap.

**What this crate refuses to be.** It never derives keys from user-chosen
passwords — chain keys must only ever originate from `generate_mnemonic`'s
CSPRNG entropy. A human-picked password fed to `fromLogin` would give the
account password-grade keys, brute-forceable offline from its public keys;
use passwords only to encrypt a local vault, never as key material. The crate
also stores nothing and performs no network I/O.

---

## Test vectors

Pinned in `cargo test` (`pinned_master_wif_vector`) and cross-checked against
the official BIP-39/Trezor vectors and dpixa 1.5.4's decoder:

| | |
|---|---|
| mnemonic | `abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about` |
| passphrase | *(empty)* |
| master key | `1fd9a763a584504901aeaee14224f65af43a54797c9eeba4cdb287d4489981a6` |
| master WIF | `5J4K9nt7JHheDYmsUC28yeb6K8gR2FxgD8KRZRibFAYcCuyxLvo` |

> ⚠️ This is the universally known BIP-39 test phrase. Never fund it.

---

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT), at your option.

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in this work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.
