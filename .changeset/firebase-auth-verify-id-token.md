---
"@fiboup/firebase-auth": minor
---

Safer and faster ID token verification.

- New `verifyIdToken(token, { projectId })`, which fetches keys as needed.
- New `getGooglePublicKeys`, which caches keys until Google's `max-age` expires, shares concurrent requests, and throws `PublicKeysFetchError` on a failed response. `fetchGooglePublicKeys` is unchanged.
- `JwtDecodeError` has a `code`: `expired`, `invalid_signature`, `invalid_claims`, `unknown_key` or `malformed`. Expected rejections are no longer logged.
- Checks the Firebase rules for `sub`, `iat` and `auth_time`, pins RS256, and allows 5 seconds of clock skew by default.
- The decoded token's `uid` is now set to `sub`.
- `verifyAndDecodeJwt` accepts imported `jose` keys as well as PEM certificates, and caches imported certificates.
