# pixa-bip39

WASM-ready BIP-39 mnemonic generator and base58-encoded master key derivation for Pixa.

## API

Three functions are exported to JavaScript:

- `generate_mnemonic(word_count: number, lang: string) -> string`
  Generates a fresh BIP-39 mnemonic. `word_count` must be one of 12, 15, 18, 21, 24.
  Supported `lang` values: `english`, `czech`, `french`, `italian`, `japanese`, `korean`, `portuguese`, `spanish`.

- `mnemonic_to_base58_master_key(mnemonic: string, passphrase: string) -> Promise<string>`
  Derives a 32-byte master key from the mnemonic (and optional passphrase) and returns it WIF-encoded.
  Derivation chain: `BIP39_seed = PBKDF2-HMAC-SHA512(mnemonic, "mnemonic"+passphrase, 2048)`,
  then `master_key = SHA256("pixa-master-key-v1" || BIP39_seed)`.

- `search_mnemonic_words(query: string, lang: string, max_length: number) -> string[]`
  Fuzzy-search the BIP-39 word list for autocomplete UIs.

## Build

```sh
# Install wasm-pack once: https://rustwasm.github.io/wasm-pack/installer/
wasm-pack build --target web --release
```

Output lands in `./pkg/`. For a bundler-friendly build use `--target bundler`; for Node use `--target nodejs`.

## Notes on derivation

The master key produced here is a single 32-byte secret. Role-specific keys
(`owner`, `active`, `posting`, `memo`) are derived downstream — Steem/Hive style —
as `SHA256(account_name || role || master_key)`.

The domain-separation prefix `"pixa-master-key-v1"` exists so the master key
cannot collide with any other 32-byte value derived from the same BIP-39 seed,
and so the derivation can be migrated to `v2` later without breaking existing accounts.

## License

MIT OR Apache-2.0
