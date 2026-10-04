# @fiboup/firebase-auth

## 1.2.0

### Minor Changes

- 200f955: Safer and faster ID token verification.

  - New `verifyIdToken(token, { projectId })`, which fetches keys as needed.
  - New `getGooglePublicKeys`, which caches keys until Google's `max-age` expires, shares concurrent requests, and throws `PublicKeysFetchError` on a failed response. `fetchGooglePublicKeys` is unchanged.
  - `JwtDecodeError` has a `code`: `expired`, `invalid_signature`, `invalid_claims`, `unknown_key` or `malformed`. Expected rejections are no longer logged.
  - Checks the Firebase rules for `sub`, `iat` and `auth_time`, pins RS256, and allows 5 seconds of clock skew by default.
  - The decoded token's `uid` is now set to `sub`.
  - `verifyAndDecodeJwt` accepts imported `jose` keys as well as PEM certificates, and caches imported certificates.

## 1.1.0

### Minor Changes

- [firebase-auth] add firebase refresh token api

## 1.0.3

### Patch Changes

- [firebase-auth]

  - export DecodedIdToken type

  [hono-firebase-auth]

  - allow developer to custom the current user object payload
  - use an empty string for the current user context key to disable setting Hono current user context variable

## 1.0.2

### Patch Changes

- [firebase-auth] export types in package.json

## 1.0.1

### Patch Changes

- [firebase-auth] export missing JWT verify function

## 1.0.0

### Major Changes

- Initialize firebase-auth package to manage decode and verify firebase token
