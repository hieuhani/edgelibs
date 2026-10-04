# @fiboup/hono-firebase-auth

## 2.0.0

### Major Changes

- 200f955: Version 2 for Hono 4.

  - Requires Hono 4 (`peerDependencies: hono ^4.0.0`).
  - New `getToken` option. Return `undefined` to pass a request through, so Firebase can sit next to other kinds of tokens.
  - `projectId` can be a function of the Hono context, such as `(c) => c.env.FIREBASE_PROJECT_ID`.
  - `transformCurrentUser` is typed by its return value, may be async, and receives the context. Pass your Env as the third type parameter to type bindings and the user variable together. Without it, the handler accepts any context, as in 1.x, so existing wrappers such as `(c, next) => validateFirebaseAuth({...})(c, next)` keep compiling.
  - Google's public keys are cached and refetched once on an unknown `kid`. Tests can inject keys with `fetchPublicKeys`.
  - Re-exports `verifyIdToken`, `PublicKeysFetchError` and `JwtDecodeErrorCode`.

### Patch Changes

- Updated dependencies [200f955]
  - @fiboup/firebase-auth@1.2.0

## 1.0.6

### Patch Changes

- update hono version

## 1.0.5

### Patch Changes

- use Hono req header function to get request header

## 1.0.4

### Patch Changes

- [hono-firebase-auth] fix JWTDecodeError export

## 1.0.3

### Patch Changes

- [hono-firebase-auth] export JWTDecodeError type

## 1.0.2

### Patch Changes

- [hono-firebase-auth] add readme for hono-firebase-auth package

## 1.0.1

### Patch Changes

- [firebase-auth]

  - export DecodedIdToken type

  [hono-firebase-auth]

  - allow developer to custom the current user object payload
  - use an empty string for the current user context key to disable setting Hono current user context variable

- Updated dependencies
  - @fiboup/firebase-auth@1.0.3
