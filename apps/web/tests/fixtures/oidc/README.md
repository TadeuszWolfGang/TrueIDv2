# OIDC ID-token regression test fixtures

Public, test-only key material used by the unit tests in
`apps/web/src/oidc.rs` to exercise `OidcProvider::validate_id_token` with real
signed JWTs (RS256, ES256, EdDSA). These files are **published upstream test
keys**, not credentials. They are widely distributed in the public
`jsonwebtoken` source distribution and carry no secrecy value. Do not copy any
lab or production key into this directory.

## Provenance

Source: `https://github.com/Keats/jsonwebtoken/tree/v11.1.0/tests`
(the MIT-licensed `jsonwebtoken` crate, version 11.1.0, `tests/` directory).

| File                 | Upstream original                          | Format                          |
|----------------------|--------------------------------------------|---------------------------------|
| `rsa-2048-pkcs1.der` | `tests/rsa/private_rsa_key.der`            | RSA-2048 private key, PKCS#1 DER |
| `p256-pkcs8.der`     | `tests/ecdsa/private_ecdsa_key.pk8`        | EC P-256 private key, PKCS#8 DER |
| `ed25519-pkcs8.der`  | `tests/eddsa/private_ed25519_key.pk8`      | Ed25519 private key, PKCS#8 DER |
| `UPSTREAM-LICENSE`   | `LICENSE` of jsonwebtoken v11.1.0          | MIT license text                |
| `manifest.json`      | hash manifest from the reference snapshot  | SHA-256 manifest                |

The `.der` files are byte-identical to the upstream originals and match the
SHA-256 hashes recorded in `manifest.json`:

- `rsa-2048-pkcs1.der`: `1284afe19cade2151ec1fd790fe171df813e4476be6c97a9e2e2e56195eedbf3`
- `p256-pkcs8.der`: `2ae7252c217ba34548b156dd5e178aa4e395dcfb3f9fffaf53cd89440cb6095f`
- `ed25519-pkcs8.der`: `919c314d0044c4e82efaeefa0cbf306d592e730de2c4661ea4cb2e9854b02f02`
- `UPSTREAM-LICENSE`: `a8012be84ea176195305bfb4e9109ed6f28860a8e697bc50302e75c2040813f3`

## License

These files are covered by the MIT license of the upstream `jsonwebtoken`
project, reproduced verbatim in `UPSTREAM-LICENSE` (Copyright (c) 2015 Vincent
Prouillet). The upstream repository and its license permit redistribution in
source and binary forms subject to the license notice above.

## Usage notes

- Tests sign throwaway ID tokens with these keys via
  `jsonwebtoken::EncodingKey::from_rsa_der` / `from_ec_der` / `from_ed_der`
  and serve matching JWKS documents from a loopback mock.
- Timestamps in test tokens are computed relative to the current UTC time at
  test run time; the key files themselves are static and deterministic.
