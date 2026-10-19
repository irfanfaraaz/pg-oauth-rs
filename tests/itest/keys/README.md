# Test-only keys

**Never use these keys for anything real.** The private key is public in this repository.

- `itest-rsa.pem`: RSA 2048 private key (PKCS#8). The integration tests sign forged tokens with it.
- `itest-rsa.pub.pem`: its public half.

The demo Keycloak realm (`demo/keycloak/realm-demo.json`) imports the same private key as the
`itest-key` RS256 key provider, at a high priority. So Keycloak signs real tokens with it and lists
it in its JWKS, and forged tokens pass the key lookup and fail only the check under test.
Keycloak picks the key's `kid` itself: read it from the realm's JWKS, do not hard-code it.

Regenerate both files (then rebuild the realm file's `privateKey`):

```sh
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out itest-rsa.pem
openssl pkey -in itest-rsa.pem -pubout -out itest-rsa.pub.pem
```
